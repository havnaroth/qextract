"""Copy matched files out of the volumes, run decoders and write everything into one zip."""

import collections
import csv
import datetime
import hashlib
import io
import os
import re
import time

from . import mft, report
from .decoders import DECODERS
from .fs import error_text
from .host import public, read_host
from .output import OutputFolder
from .parsers import PARSERS

FILE_COLUMNS = ['volume', 'source', 'artifact', 'kind', 'path', 'deleted', 'size',
                'created', 'modified', 'accessed', 'sha256', 'saved_as', 'note', 'error']
# schema 1 columns first, in their order; the normalized ones (report.py) appended
QUARANTINE_COLUMNS = ['volume', 'source', 'container', 'detection', 'quarantined', 'threat_id',
                      'item_type', 'original_path', 'resource', 'status', 'size', 'md5', 'sha1',
                      'sha256', 'saved_as', 'file_created', 'file_modified', 'file_accessed',
                      'owner_sid', 'zone_id', 'host_url', 'referrer_url', 'notes'] + report.QUARANTINE_EXTRA
DETECTION_COLUMNS = ['time', 'product', 'event_id', 'event', 'threat', 'path', 'action', 'user',
                     'process', 'details', 'volume', 'source', 'evidence', 'record', 'recovered']
DETECTION_COLUMNS += report.DETECTION_EXTRA

ZIP_DEFLATED = 8
ZIP_PASSWORD = b'infected'  # nosec B105 - the default: the agreed convention for sharing malware, not a secret
GENERIC_SOURCES = {'windows-events'}     # read for every product: not a product of its own
RECOVERED_EXTENSION = 'infected'
METADATA_SUFFIX = 'metadata.txt'
DEFAULT_MAX_DECODE_BYTES = 1024 * 1024 * 1024
SLOW_SOURCE = 1.0     # seconds: a source this slow is named in the log

_BAD_CHARS = re.compile(r'[<>:"|?*/\\\x00-\x1f]')
_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')
# control characters but tab and line breaks: escape sequences from the evidence would steer
# a terminal that shows the CSV (type, cat, less)
_CSV_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x9b]')


def iso(ts):
    if not ts:
        return ''
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat().replace('+00:00', 'Z')
    except (OverflowError, OSError, ValueError):
        return ''


def _specificity(pattern):
    """Length of the fixed start of a path pattern, before its first wildcard."""
    return len(re.split(r'[*?]|regex:', pattern.replace('\\', '/'), maxsplit=1)[0])


def safe_name(part):
    """One file name for the output folder. Names from the evidence may hold path separators
    or '..' (legal on ext/HFS), which must not lead outside the output folder."""
    part = _BAD_CHARS.sub('_', part).rstrip('. ')
    return part or '_'


def is_event_log(artifact, entry):
    """Windows event logs can be gigabytes; copying them is the user's choice."""
    return artifact.get('kind') == 'eventlog' or entry.path.lower().endswith('.evtx')


def human_size(size):
    if size >= 1024 ** 3:
        return f'{size / 1024 ** 3:.1f} GB'
    return f'{max(size / 1024 ** 2, 0.1):.1f} MB'


def _zip_time(ts):
    """A zip member time (UTC; the format only holds 1980-2107)."""
    try:
        t = datetime.datetime.fromtimestamp(ts, datetime.UTC) if ts else datetime.datetime.now(datetime.UTC)
    except (OverflowError, OSError, ValueError):
        t = datetime.datetime.now(datetime.UTC)
    t = min(max(t, datetime.datetime(1980, 1, 1, tzinfo=datetime.UTC)),
            datetime.datetime(2107, 12, 31, 23, 59, 58, tzinfo=datetime.UTC))
    return t.timetuple()[:6]


def _csv(columns, rows, sort=True):
    """Rows as CSV text, sorted by time where they have one."""
    buf = io.StringIO(newline='')
    writer = SafeWriter(buf, columns, extrasaction='ignore')
    writer.writeheader()
    for r in (sorted(rows, key=lambda r: str(r.get('time', ''))) if sort else rows):
        writer.writerow(r)
    return buf.getvalue()


class SafeWriter(csv.DictWriter):
    """Values come from the evidence (file names, detection names chosen by an attacker);
    a leading '=' etc. would run as a formula when the CSV is opened in Excel, and control
    characters could steer a terminal."""

    @staticmethod
    def _clean(v):
        if not isinstance(v, str):
            return v
        v = _CSV_CONTROL.sub('?', v)
        return f"'{v}" if v.startswith(_FORMULA_START) else v

    def writerow(self, row):
        return super().writerow({k: self._clean(v) for k, v in row.items()})


class Context:
    """What a decoder sees: one volume, one source."""

    def __init__(self, collector, volume, source):
        self.collector, self.volume, self.source = collector, volume, source
        self.max_bytes = collector.max_decode_bytes

    def read(self, entry):
        """A whole file in memory, refused above the decode limit (a crafted or huge file
        must not exhaust memory); the file is still copied into the zip as usual."""
        if entry.size > self.max_bytes:
            raise ValueError(f'{entry.size:,} bytes, above the decode limit of {self.max_bytes:,}')
        return self.volume.read(entry)

    def open(self, entry):
        """The file as a seekable stream, for parsers of big files (no size limit, nothing
        held in memory). The caller closes it."""
        return self.volume.open(entry)

    def save(self, name, data, metadata=None):
        """metadata: text (see decoders.util.metadata_text) stored next to the file."""
        return self.collector.save_recovered(self.source['id'], name, data, metadata)

    def warn(self, message):
        self.collector.warn(f'{self.volume.name}/{self.source["id"]}: {message}')

    @property
    def host(self):
        """What host.read_host found on this volume ({} when nothing): time zone, ANSI code page."""
        return self.collector.hosts.get(self.volume.name, {})

    def save_decoded(self, entry, data, suffix='.decoded'):
        """A readable form of an obfuscated log or settings file (not malware), next to the
        copies: info/decoded/<volume>/<path><suffix>."""
        parts = ['decoded', safe_name(self.volume.name), *(safe_name(p) for p in entry.path.split('/'))]
        return self.collector.add_info('/'.join(parts) + suffix, data)

    def table(self, name, rows):
        """Rows for an extra report <name>.csv (columns in the order first seen), for data
        too plentiful for the detections.csv timeline."""
        if name.lower() in ('collected_files', 'quarantine', 'detections', 'summary'):
            raise ValueError(f'table name "{name}" is taken by a standard report')
        for r in rows:
            r.setdefault('volume', self.volume.name)
            r.setdefault('source', self.source['id'])
        self.collector._tables.setdefault(name, []).extend(rows)


class Collector:
    """Everything the run produces goes into ONE zip in the output folder (AES, password
    "infected"): malware/ holds the recovered quarantine files, info/ everything else
    (reports, copied files, log, summary)."""

    def __init__(self, out, log, max_decode_bytes=DEFAULT_MAX_DECODE_BYTES, started=None, password=None,
                 protected=(), zip_name=None, file_history=True, status=None):
        self.out = os.path.abspath(out)
        # the zip is always encrypted: a custom password may replace "infected", never remove it
        self.password = password.encode('utf-8') if password else ZIP_PASSWORD
        # always time-stamped (UTC start of the run), e.g. qextract_recovered_20261101_093000.zip;
        # a given name (the zip next to an image) is only ever created new, nothing is replaced
        started = started or datetime.datetime.now(datetime.UTC)
        self.zip_name = zip_name or f'qextract_recovered_{started:%Y%m%d_%H%M%S}.zip'
        self._replace = zip_name is None
        # the zip is created through it: links refused, never inside the (read-only) input
        self.output = OutputFolder(self.out, protected)
        self.log = log
        self.status = status or (lambda what: None)   # the console's sign of life (progress.py)
        self.max_decode_bytes = max_decode_bytes
        self.warnings = []
        self._zip = self._zip_file = None
        self._copied = {}
        self._members = set()      # lower-case member names, to keep them unique
        self._tables = {}
        # filled by run(), read by the CLI for summary.txt / summary.json
        self.hosts, self.detections, self.quarantine, self.incidents = {}, [], [], []
        # seconds per source: searching the volumes, and copying / decoding / parsing
        self.timings = collections.defaultdict(lambda: {'search': 0.0, 'work': 0.0})
        # the $MFT / $UsnJrnl history of the files the products named (mft.py)
        self.file_history = file_history
        self.history = {'records': 0, 'usn_events': 0, 'seconds': 0.0, 'notes': []}

    def warn(self, message):
        self.warnings.append(message)
        self.log(f'  WARNING: {message}')

    def _archive(self):
        if self._zip is None:
            import pyzipper
            self._zip_file = self.output.create(self.zip_name, replace=self._replace)
            self._zip = pyzipper.AESZipFile(self._zip_file, 'w', compression=pyzipper.ZIP_DEFLATED,
                                            encryption=pyzipper.WZ_AES)
            self._zip.setpassword(self.password)
        return self._zip

    def _member(self, base, suffix=''):
        """A member name not used yet: base+suffix, else base_2+suffix, ... -> the stem"""
        stem, n = base, 1
        while f'{stem}{suffix}'.lower() in self._members:
            n += 1
            stem = f'{base}_{n}'
        self._members.add(f'{stem}{suffix}'.lower())
        return stem

    def save_recovered(self, source_id, name, data, metadata=None):
        """Recovered files are live malware. They only ever go into the encrypted zip
        (malware/<source>/..., password "infected") and get the extension .infected, so that
        even unpacked they do not run on a double click. There is deliberately no option to
        write them plainly. Metadata text, when given, goes next to the file as
        <name>.metadata.txt."""
        stem = self._member(f'malware/{safe_name(source_id)}/{safe_name(name)}', f'.{RECOVERED_EXTENSION}')
        name = f'{stem}.{RECOVERED_EXTENSION}'
        self._archive().writestr(name, data)
        if metadata:
            self._members.add(f'{stem}.{METADATA_SUFFIX}'.lower())
            self._archive().writestr(f'{stem}.{METADATA_SUFFIX}', metadata.encode('utf-8'))
        return f'{self.zip_name}/{name}'

    def add_member(self, name, data):
        """A report outside info/ (e.g. mft/), str written as UTF-8 with BOM."""
        if isinstance(data, str):
            data = data.encode('utf-8-sig')
        member = self._member(name)
        self._archive().writestr(member, data)
        return f'{self.zip_name}/{member}'

    def add_info(self, name, data):
        """A report or other non-malware file into info/ (str is written as UTF-8 with BOM)."""
        if isinstance(data, str):
            data = data.encode('utf-8-sig')
        member = self._member(f'info/{name}')
        self._archive().writestr(member, data)
        return f'{self.zip_name}/{member}'

    def close(self):
        """Finish the zip; creates it if nothing was written yet. The file is closed even when
        finishing fails (a full disk), so nothing stays locked."""
        try:
            self._archive().close()
        finally:
            if self._zip_file is not None:
                self._zip_file.close()
            self._zip = self._zip_file = None

    def _copy(self, volume, entry):
        """Stream one file from the evidence into info/files/<volume>/<path> in the zip."""
        key = (volume.name, entry.path.lower(), entry.deleted)
        if key in self._copied:
            return self._copied[key]
        base = '/'.join(['info', 'files', safe_name(volume.name), *(safe_name(p) for p in entry.path.split('/'))])
        stem, n = base, 1
        while stem.lower() in self._members:
            n += 1
            stem = f'{base} ({n})'
        self._members.add(stem.lower())
        archive = self._archive()
        info = archive.zipinfo_cls(stem, date_time=_zip_time(entry.modified))
        info.compress_type = ZIP_DEFLATED
        digest = hashlib.sha256()
        with archive.open(info, 'w', force_zip64=True) as f:
            try:
                for chunk in volume.chunks(entry):
                    digest.update(chunk)
                    f.write(chunk)
            except OSError as e:
                raise OSError(f'{e} (the copy {stem} in the zip is incomplete)') from e
        result = (f'{self.zip_name}/{stem}', digest.hexdigest())
        self._copied[key] = result
        return result

    @staticmethod
    def _match(volume, art, roots):
        """-> {(path, deleted): (entry, how specific the most specific matching pattern is)}"""
        matched = {}
        for root in roots:
            for pattern in art['paths']:
                spec = _specificity(pattern)
                for e in volume.glob(pattern, root):
                    key = (e.path.lower(), e.deleted)
                    if key not in matched or matched[key][1] < spec:
                        matched[key] = (e, spec)
        return matched

    def _owners(self, volume, roots, sources, matches):
        """One file belongs to one product. When several products match a file (WithSecure
        Elements and the consumer F-Secure app share ProgramData/F-Secure), it goes to the
        product whose marker files exist on this volume, then to the more specific pattern,
        then to the first product, with a warning."""
        claims = {}
        for source, _art, matched in matches:
            for key, (_e, spec) in matched.items():
                c = claims.setdefault(key, {})
                c[source['id']] = max(spec, c.get(source['id'], -1))
        by_id = {s['id']: s for s in sources}
        order = {s['id']: n for n, s in enumerate(sources)}
        present = {}
        owners, ambiguous = {}, set()
        for key, c in claims.items():
            if len(c) == 1:
                continue
            for sid in c:
                if sid not in present:
                    present[sid] = any(next(iter(volume.glob(m, root)), None) is not None
                                       for m in by_id[sid].get('markers', []) for root in roots)
            ranked = sorted(c, key=lambda sid: (not present[sid], -c[sid], order[sid]))
            best, second = ranked[0], ranked[1]
            if (present[best], c[best]) == (present[second], c[second]):
                ambiguous.add((best, *sorted(set(c) - {best})))
            owners[key] = best
        for best, *others in sorted(ambiguous):
            self.warn(f'{volume.name}: files matched by {best} and {", ".join(others)}; no marker shows which '
                      f'product is installed, so they were given to {best}')
        return owners

    def _plan(self, volumes, sources):
        """Every match before anything is copied, so the size of the event logs is known
        up front. Folder listings are cached, so the second walk costs nothing."""
        plan = []
        products = sum(1 for s in sources if s.get('id') not in GENERIC_SOURCES)
        for volume in volumes:
            roots = volume.roots()
            self.log(f'Volume {volume.name}: {volume.description}')
            if roots != ['']:
                self.log(f'  Windows folders found under: {", ".join("/" + r for r in roots)}')
            for root in roots:
                host = read_host(volume, root)
                if host:
                    self.hosts[volume.name] = host
                    h = public(host)
                    problem = f" ({h['error']})" if h.get('error') else ''
                    self.log(f"  Host: {h.get('computer', '?')}, {h.get('os', 'Windows version unknown')}, "
                             f"time zone {h.get('time_zone', 'unknown')}{problem}")
                    break
            self.log(f'  Searching for {products} products ...')
            t_search = time.monotonic()
            matches = []
            for source in sources:
                self.status(f"searching {volume.name} for {source.get('name', source['id'])}")
                t0 = time.monotonic()
                for art in source['artifacts']:
                    matched = self._match(volume, art, roots)
                    if matched:
                        matches.append((source, art, matched))
                self.timings[source['id']]['search'] += time.monotonic() - t0
            owners = self._owners(volume, roots, sources, matches)
            work = []
            for source, art, matched in matches:
                entries = sorted((e for key, (e, _spec) in matched.items()
                                  if owners.get(key, source['id']) == source['id']), key=lambda e: e.path.lower())
                if entries:
                    work.append((source, art, entries))
            found = {s['id'] for s, _a, _e in work if s.get('id') not in GENERIC_SOURCES}
            self.log(f'  Search done in {time.monotonic() - t_search:.1f} s: '
                     f'{sum(len(e) for _s, _a, e in work)} file(s) of {len(found)} product(s)')
            plan.append((volume, roots, work))
        return plan

    def _wanted_paths(self):
        """The absolute file paths the products named: incidents, quarantine, detections."""
        # only what a product called a threat: ASR / controlled folder access events name the
        # process that triggered the rule (e.g. svchost.exe), not a malicious file
        paths = {i.get('path', '') for i in self.incidents if i.get('path_type') == 'file' and i.get('threats')}
        paths |= {p for r in self.quarantine for p in str(r.get('path_norm') or '').split('; ')}
        paths |= {p for r in self.detections if r.get('category') in ('detection', 'response') and r.get('threat')
                  and r.get('path_type') in ('file', 'mixed') for p in str(r.get('path_norm') or '').split('; ')}
        return {p for p in paths if re.match(r'^[A-Za-z]:\\', p)}

    def _file_history(self, plan):
        """$MFT / $J records of the named files -> mft/ in the zip, and the incidents learn when
        their file was on the disk first."""
        paths = self._wanted_paths()
        if not paths:
            return
        t0 = time.monotonic()
        records, events = [], []
        read = 0
        for volume, roots, _work in plan:
            host = self.hosts.get(volume.name)
            drive = host.get('system_drive', 'C:') if host else None
            if not host:
                # a collection with $MFT but no registry: its files are the C: drive's. An image
                # partition without Windows is not guessed (C:\ paths would match the wrong one)
                if hasattr(volume, 'fs') or next(iter(volume.glob(f'{roots[0]}/$MFT' if roots[0] else '$MFT')),
                                                 None) is None:
                    continue
                drive = 'C:'
                self.history['notes'].append(f'{volume.name}: no registry to tell the drive letter; taken as C:')
            try:
                self.status(f'reading the $MFT / $UsnJrnl of {volume.name}')
                found, usn, notes = mft.history_for(volume, roots[0], drive, paths, self.log,
                                                    status=self.status)
            except (OSError, ValueError, TimeoutError) as err:
                self.warn(f'{volume.name}: file history not read: {error_text(err)}')
                continue
            records += found
            events += usn
            self.history['notes'] += [f'{volume.name}: {n}' for n in notes]
            read += 0 if notes and notes[0].startswith('no $MFT') else 1
        self.history.update(records=len(records), usn_events=len(events), seconds=round(time.monotonic() - t0, 2))
        if not read:
            self.history['notes'].append('no $MFT read: it needs an NTFS image, a raw drive (administrator) '
                                         'or a collection that holds $MFT')
            return
        first = mft.first_on_disk(records, events)
        # dwell runs to the FIRST detection of the path: a file detected again months later (a new
        # incident after the one-day gap) was not missed for months
        first_detected = {}
        for inc in self.incidents:
            key = str(inc.get('path', '')).lower()
            if key and (key not in first_detected or inc.get('first_seen', '') < first_detected[key]):
                first_detected[key] = inc.get('first_seen', '')
        zones = {}
        for r in records:
            if r.get('target') and (r.get('host_url') or r.get('zone_id')):
                zones.setdefault(r['target'].lower(), (r, 0 if r.get('state') == 'in use' else 1))
                if r.get('state') == 'in use':
                    zones[r['target'].lower()] = (r, 0)
        for inc in self.incidents:
            key = str(inc.get('path', '')).lower()
            zone = zones.get(key)
            if zone and not inc.get('origin'):
                r = zone[0]
                inc['origin'] = report.origin_text(r.get('zone_id'), r.get('host_url'), r.get('referrer_url'))
                inc['origin_evidence'] = (f"Zone.Identifier in $MFT record {r.get('record')}"
                                          + (' (deleted file)' if r.get('state') != 'in use' else ''))
            known = first.get(key)
            if not known:
                continue
            inc['on_disk_since'], inc['on_disk_evidence'] = known
            if inc.get('first_seen', '') == first_detected.get(key):
                inc['dwell'] = report.duration(known[0], inc.get('first_seen', ''))
        moves, journeys = mft.file_moves(records, events)
        for inc in self.incidents:
            journey = journeys.get(str(inc.get('path', '')).lower())
            if journey:
                inc['journey'] = journey
        self.history['moves'] = sum(1 for m in moves if m['step'] in ('moved', 'renamed'))
        self.add_member('mft/file_records.csv', _csv(mft.RECORD_COLUMNS, records, sort=False))
        self.add_member('mft/usn_events.csv', _csv(mft.USN_COLUMNS, events))
        # always written, also empty: its absence would look like a missing step (summary.txt
        # says what period the journal covers)
        self.add_member('mft/file_moves.csv', _csv(mft.MOVE_COLUMNS, moves))

    def run(self, volumes, sources, copy_event_logs=None):
        """copy_event_logs: None = copy them, or a callable(count, total bytes) -> bool that
        decides once the size of all matched event logs is known (the CLI asks the user)."""
        stats, detections, listed = {}, [], set()
        plan = self._plan(volumes, sources)
        logs = {(v.name, e.path.lower(), e.deleted): e.size for v, _roots, work in plan
                for _source, art, entries in work for e in entries if is_event_log(art, e)}
        copy_logs = True
        if logs and copy_event_logs is not None:
            copy_logs = bool(copy_event_logs(len(logs), sum(logs.values())))

        # the reports go into the zip at the end, also when the run fails half way
        files_csv = io.StringIO(newline='')
        quarantine = []
        try:
            files = SafeWriter(files_csv, FILE_COLUMNS, extrasaction='ignore')
            files.writeheader()
            for volume, _roots, work in plan:
                if work:
                    self.log(f'Copying and decoding ({volume.name}):')
                for source, art, entries in work:
                    self.status(f"copying / decoding {source['name']} - {art['name']} ({len(entries)} file(s))")
                    t_work = time.monotonic()
                    s = stats.setdefault(source['id'], {'name': source['name'], 'files': 0, 'bytes': 0,
                                                        'quarantine_items': 0, 'recovered': 0, 'events': 0})
                    self.log(f'  {source["name"]} - {art["name"]}: {len(entries)} file(s)')
                    for e in entries:
                        key = (volume.name, source['id'], e.path.lower(), e.deleted)
                        if key in listed:
                            continue    # same file matched by another artifact of this product
                        listed.add(key)
                        row = {'volume': volume.name, 'source': source['id'], 'artifact': art['name'],
                               'kind': art['kind'], 'path': e.path, 'deleted': 'yes' if e.deleted else '',
                               'size': e.size, 'created': iso(e.created), 'modified': iso(e.modified),
                               'accessed': iso(e.accessed)}
                        if not copy_logs and is_event_log(art, e):
                            row['note'] = 'event log not copied (read in place for the timeline)'
                            files.writerow(row)
                            continue
                        try:
                            row['saved_as'], row['sha256'] = self._copy(volume, e)
                            s['files'] += 1
                            s['bytes'] += e.size
                        except OSError as err:
                            row['error'] = str(err)
                            self.warn(f'cannot copy {e.path}: {error_text(err)}')
                        files.writerow(row)
                    if art.get('decoder'):
                        ctx = Context(self, volume, source)
                        try:
                            rows = DECODERS[art['decoder']](ctx, entries, art['options'])
                        except Exception as err:  # noqa: BLE001 - a broken decoder must not stop the collection
                            self.warn(f'decoder "{art["decoder"]}" failed: {err!r}')
                            rows = []
                        for r in rows:
                            r.setdefault('volume', volume.name)
                            r.setdefault('source', source['id'])
                            r.setdefault('product', source.get('name', source['id']))   # incidents.csv
                            quarantine.append(r)
                            s['quarantine_items'] += 1
                            s['recovered'] += 1 if r.get('saved_as') else 0
                        if rows:
                            saved = sum(1 for r in rows if r.get('saved_as'))
                            self.log(f'    decoded {len(rows)} item(s), recovered {saved}')
                    if art.get('parser'):
                        ctx = Context(self, volume, source)
                        try:
                            rows = PARSERS[art['parser']](ctx, entries, art['options'])
                        except Exception as err:  # noqa: BLE001 - a broken parser must not stop the collection
                            self.warn(f'parser "{art["parser"]}" failed: {err!r}')
                            rows = []
                        for r in rows:
                            r.setdefault('volume', volume.name)
                            r.setdefault('source', source['id'])
                        detections += rows
                        s['events'] += len(rows)
                        if rows:
                            self.log(f'    {len(rows)} event(s) for the timeline')
                    self.timings[source['id']]['work'] += time.monotonic() - t_work
                for w in volume.warnings:
                    self.warn(f'{volume.name}: {w}')
        finally:
            self.add_info('collected_files.csv', files_csv.getvalue())
            try:
                self.incidents = report.normalize_all(detections, quarantine, self.hosts)
            except Exception as err:  # noqa: BLE001 - the raw rows are still written
                self.warn(f'report normalization failed: {err!r}')
            self.add_info('quarantine.csv', _csv(QUARANTINE_COLUMNS, quarantine, sort=False))
            self.detections, self.quarantine = detections, quarantine
        self.add_info('detections.csv', _csv(DETECTION_COLUMNS, detections))
        if self.file_history:
            try:
                self._file_history(plan)
            except Exception as err:  # noqa: BLE001 - the history is an extra; the rest is written
                self.warn(f'file history failed: {err!r}')
        self.add_info('incidents.csv', _csv(report.INCIDENT_COLUMNS, self.incidents, sort=False))
        for name, rows in self._tables.items():
            self.add_info(f'{safe_name(name)}.csv', _csv(list(dict.fromkeys(k for r in rows for k in r)), rows))
        slow = sorted(((t['search'] + t['work'], sid, t) for sid, t in self.timings.items()
                       if t['search'] + t['work'] >= SLOW_SOURCE), reverse=True)
        names = {s['id']: s['name'] for s in sources}
        for total, sid, t in slow:
            self.log(f"  Slow: {names.get(sid, sid)} {total:.1f} s (search {t['search']:.1f} s, "
                     f"copy / decode / parse {t['work']:.1f} s)")
        for sid, s in stats.items():
            t = self.timings.get(sid, {})
            s['seconds'] = round(t.get('search', 0) + t.get('work', 0), 2)
        return {k: v for k, v in stats.items() if v['files'] or v['quarantine_items'] or v['events']}
