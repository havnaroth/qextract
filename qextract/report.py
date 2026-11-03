"""One report layer for every product: the rows the decoders and parsers return are normalized
here, so a new product gets it without code of its own.

- detections.csv gets category, log, action_norm, path_norm / path_type, the common details as
  columns (sha256, md5, threat_family, severity), details_json and its incident;
- quarantine.csv gets quarantined_utc (local times converted with the host's time zone),
  recovery, verified_by, warning, path_norm and its incident;
- incidents.csv: one row per threat on one file (or AMSI buffer, registry key), joining the
  events of every log and the quarantine items with their recovered files;
- summary.txt: the run for a human reader.

The existing columns keep their content and order; the new ones are appended (SCHEMA_VERSION).
Everything here reads values from the evidence: nothing is trusted to have a shape.
"""

import collections
import datetime
import json
import re

from . import host as hostinfo

SCHEMA_VERSION = 2
DETECTION_EXTRA = ['category', 'log', 'action_norm', 'path_norm', 'path_type', 'sha256', 'md5',
                   'threat_family', 'severity', 'incident', 'details_json']
QUARANTINE_EXTRA = ['quarantined_utc', 'recovery', 'verified_by', 'warning', 'path_norm', 'incident']
INCIDENT_COLUMNS = ['incident', 'first_seen', 'last_seen', 'path', 'path_type', 'threats', 'products',
                    'actions', 'events', 'logs', 'quarantined', 'recovered_files', 'sha256', 'users',
                    'processes', 'volume']
INCIDENT_GAP = datetime.timedelta(days=1)    # the same file detected again after a day: a new incident

CATEGORIES = ('detection', 'response', 'tamper', 'config', 'scan', 'health', 'telemetry', 'other')
# Defender "Action ID" (language independent, unlike "Action Name")
DEFENDER_ACTIONS = {'1': 'cleaned', '2': 'quarantined', '3': 'deleted', '6': 'allowed', '8': 'user defined',
                    '9': 'none', '10': 'blocked'}
_ACTION_WORDS = (     # (substring of the lower-case action, normalized action); first match wins
    ('quarant', 'quarantined'), ('kwarant', 'quarantined'), ('restor', 'restored'), ('przywr', 'restored'),
    ('remove_subkey', 'deleted'), ('delet', 'deleted'), ('remov', 'deleted'), ('usuń', 'deleted'),
    ('usun', 'deleted'), ('block', 'blocked'), ('zablok', 'blocked'), ('disinfect', 'cleaned'),
    ('clean', 'cleaned'), ('wyczy', 'cleaned'), ('allow', 'allowed'), ('zezw', 'allowed'),
    ('fail', 'failed'), ('found', 'detected'), ('detect', 'detected'), ('nie dotyczy', 'none'),
    ('not applicable', 'none'), ('no action', 'none'), ('brak', 'none'))
_SINGLE = {'del': 'deleted', 'bl': 'blocked', 'dis': 'cleaned', 'ren': 'renamed', 'quar': 'quarantined',
           'n/a': 'none', 'none': 'none'}
_DETAIL_SPLIT = re.compile(r'; (?=[A-Za-z][A-Za-z0-9 ()/_.-]{0,40}: )')
_DEVICE = re.compile(r'^\\Device\\HarddiskVolume(\d+)(\\.*)$', re.IGNORECASE)
_MULTI = re.compile(r';\s*(?=(?:file:_|amsi:_|process:_|regkey|[A-Za-z]:\\|\\Device\\|%))')
_DEFENDER_NAME = re.compile(r'^[A-Za-z]+:[A-Za-z0-9]+/([A-Za-z0-9_-]+)')


def _time(value):
    """An ISO UTC time ('...Z') -> datetime, else None."""
    text = str(value or '')
    if not text.endswith('Z'):
        return None
    try:
        return datetime.datetime.fromisoformat(text[:-1])
    except ValueError:
        return None


def details_dict(text):
    """'key: value; key: value' (the details column) -> dict; parts without a key are kept
    under "#1", "#2"..."""
    out, n = {}, 0
    for part in _DETAIL_SPLIT.split(str(text or '')):
        key, sep, value = part.partition(': ')
        if sep and key and len(key) <= 41:
            out.setdefault(key, value)
        elif part:
            n += 1
            out[f'#{n}'] = part
    return out


def category(row):
    event = str(row.get('event', '')).lower()
    product = str(row.get('product', '')).lower()
    if 'securitycenter' in product.replace(' ', ''):
        return 'health'
    if 'disabled' in event or 'tamper' in event or 'history deleted' in event:
        return 'tamper'
    if 'engine failed' in event or 'protection failed' in event:
        return 'health'
    if 'configuration' in event or 'exclusion' in event or 'enabled' in event:
        return 'config'
    if 'cloud query' in event or 'file hash' in event or 'slow scan' in event or 'threat hash' in event:
        return 'telemetry'
    if any(w in event for w in ('detected', 'asr rule', 'controlled folder', 'network protection', 'suspicious')):
        return 'detection'
    if any(w in event for w in ('action', 'removed', 'restored', 'deleted from quarantine', 'removal')):
        return 'response'
    if 'scan' in event:
        return 'scan'
    return 'other'


def log_type(evidence):
    p = str(evidence or '').lower().replace('\\', '/')
    name = p.rsplit('/', 1)[-1]
    if name.endswith('.evtx'):
        return 'evtx'
    if 'detectionhistory' in p:
        return 'detectionhistory'
    if name.startswith(('mplog', 'mpdetection')) or 'mplog' in name:
        return 'mplog'
    if '/pstor/' in p or name.endswith(('.db', '.sqlite')):
        return 'database'
    if name.startswith('adlicereport'):
        return 'report'
    return 'log'


def action_norm(row, details):
    aid = str(details.get('Action ID', '')).strip()
    if aid in DEFENDER_ACTIONS:
        return DEFENDER_ACTIONS[aid]
    raw = str(row.get('action', '')).strip().lower()
    event = str(row.get('event', '')).lower()
    if raw in _SINGLE:
        return _SINGLE[raw]
    for word, norm in _ACTION_WORDS:
        if word in raw:
            return norm
    if raw:
        return 'other'
    if 'restored' in event:
        return 'restored'
    if 'failed' in event:
        return 'failed'
    if event == 'removed':
        return 'deleted'
    return 'detected' if category(row) == 'detection' else ''


class PathMapper:
    """\\Device\\HarddiskVolumeN -> drive letter, learned from the evidence itself: products and
    logs often name one file both ways (MPLog vs. the event log); left as it is when unknown."""

    def __init__(self, paths, system_drive='C:'):
        votes = collections.defaultdict(collections.Counter)
        tails = collections.defaultdict(set)
        stripped = [_strip(p) for p in paths]
        for p in stripped:
            m = _DEVICE.match(p)
            if m:
                tails[m.group(2).lower()].add(m.group(1))
        for p in stripped:
            if re.match(r'^[A-Za-z]:\\', p) and p[2:].lower() in tails:
                for n in tails[p[2:].lower()]:
                    votes[n][p[:2].upper()] += 1
        self.letters = {n: c.most_common(1)[0][0] for n, c in votes.items()}
        self.system_drive = system_drive

    def letter(self, n, tail):
        if n in self.letters:
            return self.letters[n]
        # the Windows folders only exist on the system drive
        if re.match(r'^\\(windows|users|programdata|program files)', tail, re.IGNORECASE) and len(self.letters) == 0:
            return self.system_drive
        return None


def _strip(path):
    p = str(path or '').strip()
    for prefix in ('file:_', 'process:_', '\\\\?\\', '\\??\\'):
        if p.lower().startswith(prefix):
            p = p[len(prefix):]
    return p


def normalize_path(path, mapper, system_drive='C:'):
    """-> (normalized path, path type). Several paths (Defender lists them) are each normalized."""
    raw = str(path or '').strip()
    if not raw:
        return '', ''
    parts = [x.strip().rstrip(';').strip() for x in _MULTI.split(raw) if x.strip()]
    out, kinds = [], []
    for part in parts:
        amsi = part.lower().startswith('amsi:')
        p = _strip(part[5:].lstrip('_') if amsi else part)     # amsi:_<the scanning process>
        if amsi:
            m = _DEVICE.match(p)
            letter = mapper.letter(m.group(1), m.group(2)) if m and mapper is not None else None
            out.append(letter + m.group(2) if letter else p)
            kinds.append('amsi')
            continue
        if p.upper().startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR', 'HKU\\', 'REGKEY')):
            out.append(p)
            kinds.append('registry')
            continue
        if p.lower().startswith('%systemdrive%'):
            p = system_drive + p[len('%systemdrive%'):]
        elif p.lower().startswith('%systemroot%'):
            p = system_drive + '\\Windows' + p[len('%systemroot%'):]
        m = _DEVICE.match(p)
        if m and mapper is not None:
            letter = mapper.letter(m.group(1), m.group(2))
            if letter:
                p = letter + m.group(2)
        out.append(p)
        kinds.append('file' if re.match(r'^[A-Za-z]:\\|^\\Device\\|^\\\\', p) else 'other')
    kind = kinds[0] if len(set(kinds)) == 1 else 'mixed'
    return '; '.join(out), kind


def normalize_detection(row, mapper, system_drive):
    details = details_dict(row.get('details'))
    row['category'] = category(row)
    row['log'] = log_type(row.get('evidence'))
    row['action_norm'] = action_norm(row, details)
    row['path_norm'], row['path_type'] = normalize_path(row.get('path'), mapper, system_drive)
    low = {k.lower(): v for k, v in details.items()}
    if 'amsi' in str(low.get('scan source', '')).lower() and row['path_type'] == 'file':
        row['path_type'] = 'amsi'      # MPLog names the scanning process without the amsi: prefix
    sha256, md5 = str(low.get('sha256', '')), str(low.get('md5', ''))
    row['sha256'] = sha256.lower() if re.fullmatch(r'[0-9a-fA-F]{64}', sha256) else ''
    row['md5'] = md5.lower() if re.fullmatch(r'[0-9a-fA-F]{32}', md5) else ''
    family = low.get('family', '')
    if not family:
        m = _DEFENDER_NAME.match(str(row.get('threat', '')))
        family = m.group(1) if m else ''
    row['threat_family'] = family
    row['severity'] = low.get('severity name', '') or low.get('severity', '')
    row['details_json'] = json.dumps(details, ensure_ascii=False) if details else ''
    return row


def normalize_quarantine(row, hosts, mapper):
    host = hosts.get(row.get('volume'), {})
    when = str(row.get('quarantined', '') or '')
    row['quarantined_utc'] = when if when.endswith('Z') else hostinfo.to_utc(host, when)
    status = str(row.get('status', '')).lower()
    if status.startswith('recovered'):
        row['recovery'] = 'recovered'
    elif status.startswith('error'):
        row['recovery'] = 'error'
    else:
        row['recovery'] = 'not recovered'
    if row['recovery'] == 'recovered' and not row.get('verified_by'):
        row['verified_by'] = ('none' if 'not verified' in status
                              else 'size' if 'size matches' in status else 'stored hash')
    row['path_norm'], _kind = normalize_path(row.get('original_path'), mapper, host.get('system_drive', 'C:'))
    return row


def _kind(path):
    if path.lower().startswith('amsi:'):
        return 'amsi'
    if path.upper().startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR', 'HKU\\', 'REGKEY')):
        return 'registry'
    return 'file' if re.match(r'^[A-Za-z]:\\|^\\Device\\|^\\\\', path) else 'other'


def _key(path, path_type, threat):
    if path_type == 'file' and path:
        return ('file', path.lower())
    return (path_type or 'other', path.lower(), threat.lower())


LINK_SECONDS = 2     # an event without a usable path joins a detection of the same threat this close
_PATH_RANK = {'file': 0, 'amsi': 1, 'registry': 2, 'other': 3}


def _items(detections, quarantine):
    """-> [(time, path, path type, threat, row, 'event' | 'quarantine')]"""
    items = []
    for r in detections:
        if r.get('category') not in ('detection', 'response') or not (r.get('path_norm') or r.get('threat')):
            continue
        t = _time(r.get('time'))
        if t is None:
            continue
        for path in (r.get('path_norm') or '').split('; '):
            kind = 'amsi' if r.get('path_type') == 'amsi' else (_kind(path) if path else 'other')
            items.append((t, path, kind, str(r.get('threat', '')).lower(), r, 'event'))
    for r in quarantine:
        t = _time(r.get('quarantined_utc'))
        path = r.get('path_norm', '')
        if t is not None and (path or r.get('detection')):
            items.append((t, path, _kind(path) if path else 'other', str(r.get('detection', '')).lower(), r,
                          'quarantine'))
    return items


def _components(items):
    """Joins items that are one incident: the same file (or AMSI process / key + threat) within
    INCIDENT_GAP, the same Defender detection ID (1116 and its 1117 / 1119), and events without
    a usable path to a detection of the same threat within LINK_SECONDS."""
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        parent[find(a)] = find(b)

    by_key = collections.defaultdict(list)
    by_detection = collections.defaultdict(list)
    by_threat = collections.defaultdict(list)
    for i, (_t, path, kind, threat, row, _src) in enumerate(items):
        if path and kind != 'other':
            by_key[_key(path, kind, threat)].append(i)
        did = details_dict(row.get('details')).get('Detection ID', '') if 'details' in row else ''
        if did:
            by_detection[did].append(i)
        if threat:
            by_threat[threat].append(i)
    # one Defender detection can name several files: it joins the same path across its events
    # (1116 / 1117 / 1119), and its events without a path to the first of its files
    for members in by_detection.values():
        with_path = [i for i in members if items[i][1] and items[i][2] != 'other']
        anchor = min(with_path, key=lambda i: (items[i][0], items[i][1])) if with_path else members[0]
        for i in members:
            if not (items[i][1] and items[i][2] != 'other'):
                union(i, anchor)
    for members in by_key.values():
        members.sort(key=lambda i: items[i][0])
        for a, b in zip(members, members[1:], strict=False):
            if items[b][0] - items[a][0] <= INCIDENT_GAP:
                union(a, b)
    window = datetime.timedelta(seconds=LINK_SECONDS)
    for members in by_threat.values():
        members.sort(key=lambda i: items[i][0])
        for n, i in enumerate(members):
            if items[i][1] and items[i][2] != 'other':
                continue
            near = [j for j in members[max(0, n - 3):n + 4] if j != i and abs(items[j][0] - items[i][0]) <= window]
            if near:
                union(i, min(near, key=lambda j: (_PATH_RANK.get(items[j][2], 9), abs(items[j][0] - items[i][0]))))
    groups = collections.defaultdict(list)
    for i in range(len(items)):
        groups[find(i)].append(items[i])
    return sorted((sorted(g, key=lambda m: m[0]) for g in groups.values()), key=lambda g: g[0][0])


def _actions(values):
    acts = {a for a in values if a}
    real = acts - {'none', 'detected'}
    return sorted(real) if real else sorted(acts & {'detected'})


def build_incidents(detections, quarantine):
    """Assigns row['incident'] and returns the incident rows (sorted by first time)."""
    rows = []
    for n, members in enumerate(_components(_items(detections, quarantine)), 1):
        iid = f'I{n:04d}'
        events = list({id(m[4]): m[4] for m in members if m[5] == 'event'}.values())
        quar = list({id(m[4]): m[4] for m in members if m[5] == 'quarantine'}.values())
        for m in members:
            ids = [x for x in str(m[4].get('incident', '')).split(', ') if x]
            if iid not in ids:
                m[4]['incident'] = ', '.join(ids + [iid])
        best = min(members, key=lambda m: (_PATH_RANK.get(m[2], 9) if m[1] else 9, m[0]))

        def uniq(values):
            return '; '.join(dict.fromkeys(str(v) for v in values if v))
        actions = [r.get('action_norm') for r in events] + (['quarantined'] if quar else [])
        actions = _actions(actions)
        rows.append({
            'incident': iid,
            'first_seen': members[0][0].isoformat() + 'Z', 'last_seen': members[-1][0].isoformat() + 'Z',
            'path': best[1], 'path_type': best[2] if best[1] else '',
            'threats': uniq([r.get('threat') for r in events] + [r.get('detection') for r in quar]),
            'products': uniq([r.get('product') for r in events] + [r.get('source') for r in quar]),
            'actions': uniq(actions), 'events': len(events),
            'logs': uniq(sorted({r.get('log') for r in events})),
            'quarantined': 'yes' if quar or 'quarantined' in actions else '',
            'recovered_files': uniq(r.get('saved_as') for r in quar),
            'sha256': uniq([r.get('sha256') for r in quar] + [r.get('sha256') for r in events]),
            'users': uniq(r.get('user') for r in events), 'processes': uniq(r.get('process') for r in events),
            'volume': uniq([r.get('volume') for r in events] + [r.get('volume') for r in quar])})
    return rows


def normalize_all(detections, quarantine, hosts):
    """Everything in place; returns the incident rows."""
    system_drive = next((h.get('system_drive') for h in hosts.values() if h.get('system_drive')), 'C:')
    paths = [r.get('path', '') for r in detections] + [r.get('original_path', '') for r in quarantine]
    flat = [p for raw in paths for p in re.split(r';\s*', str(raw or '')) if p]
    mapper = PathMapper(flat, system_drive)
    for r in detections:
        drive = hosts.get(r.get('volume'), {}).get('system_drive', system_drive)
        normalize_detection(r, mapper, drive)
    for r in quarantine:
        normalize_quarantine(r, hosts, mapper)
    return build_incidents(detections, quarantine)


def _cut(text, width, end=False):
    """At most width characters; a path keeps its end (the file name), other text its start."""
    text = str(text)
    if len(text) <= width:
        return text
    return '...' + text[-(width - 3):] if end else text[:width - 3] + '...'


def _table(rows, columns):
    widths = [max([len(str(c))] + [len(str(r[i])) for r in rows]) for i, c in enumerate(columns)]
    lines = ['  ' + '  '.join(str(c).ljust(w) for c, w in zip(columns, widths, strict=True))]
    for r in rows:
        lines.append('  ' + '  '.join(str(v).ljust(w) for v, w in zip(r, widths, strict=True)))
    return lines


def summary_text(summary, detections, quarantine, incidents, hosts, limit=40):
    """The run for a human reader (info/summary.txt)."""
    out = [f"{summary.get('tool', 'qextract')} - report schema {SCHEMA_VERSION}",
           f"Started {summary.get('started', '')}, finished {summary.get('finished', '')}",
           f"Input:  {summary.get('input', '')} ({len(summary.get('volumes', []))} volume(s))"]
    if summary.get('output_on_input'):
        why = ('a live system keeping its own results' if summary.get('live_system')
               else '--force: the input was changed by the writing')
        out.append(f'Output: on the scanned input - {why}')
    out.append('')
    for vol, h in sorted(hosts.items()):
        if h:
            p = hostinfo.public(h)
            out.append(f"Host ({vol}): {p.get('computer', '?')} - {p.get('os', 'Windows version unknown')}")
            offset = f" ({p['utc_offset']})" if p.get('utc_offset') else ''
            problem = f"; {p['error']}" if p.get('error') else ''
            out.append(f"  time zone {p.get('time_zone', 'unknown')}{offset}{problem}")
    if any(hosts.values()):
        out.append('')
    found = summary.get('found', {})
    cats = collections.defaultdict(collections.Counter)
    for r in detections:
        cats[r.get('source', '')][r.get('category', 'other')] += 1
    rows = []
    for sid, s in sorted(found.items(), key=lambda x: x[1].get('name', '')):
        c = cats.get(sid, {})
        rows.append([s.get('name', sid), s.get('files', 0), s.get('quarantine_items', 0), s.get('recovered', 0),
                     c.get('detection', 0), c.get('response', 0), sum(c.values())])
    if rows:
        out.append('Products')
        out += _table(rows, ['product', 'files', 'quarantine', 'recovered', 'detections', 'responses', 'timeline'])
    else:
        out.append('Nothing found.')
    out.append('')
    noise = collections.Counter(r.get('category') for r in detections)
    if detections:
        out.append('Timeline: ' + ', '.join(f'{noise[c]} {c}' for c in CATEGORIES if noise.get(c)))
        out.append('')
    out.append(f'Incidents ({len(incidents)}) - one threat on one file, all logs and quarantine joined (incidents.csv)')
    rows = [[i['incident'], i['first_seen'][:19].replace('T', ' '), _cut(i['threats'] or '?', 40),
             i['actions'] or '-', 'yes' if i['recovered_files'] else '', _cut(i['path'] or '', 70, end=True)]
            for i in incidents[:limit]]
    if rows:
        out += _table(rows, ['id', 'first seen (UTC)', 'threat', 'actions', 'file', 'path'])
        if len(incidents) > limit:
            out.append(f'  ... {len(incidents) - limit} more in incidents.csv')
    out.append('')
    rec = [r for r in quarantine if r.get('saved_as')]
    password = ' - password "infected"' if summary.get('zip_password') == 'infected' else ''
    out.append(f'Recovered files ({len(rec)}) in malware\\{password}')
    for r in rec[:limit]:
        verified = r.get('verified_by') or ''
        when = r.get('quarantined_utc') or r.get('quarantined') or ''
        out.append(f"  {(r.get('detection') or '?')[:35]:35}  {when:20}  {verified[:22]:22}  "
                   f"{r.get('path_norm') or r.get('original_path') or ''}")
    not_rec = [r for r in quarantine if r.get('recovery') != 'recovered']
    if not_rec:
        out.append(f'  not recovered: {len(not_rec)} (see quarantine.csv, status)')
    out.append('')
    warnings, errors = summary.get('warnings', []), summary.get('errors', [])
    out.append(f'Warnings ({len(warnings)})' + (':' if warnings else ''))
    out += [f'  - {w}' for w in warnings[:limit]]
    out.append(f'Errors: {"; ".join(errors) if errors else "none"}')
    out += ['', 'Files in this zip:',
            '  incidents.csv        start here: one row per threat on a file',
            '  detections.csv       the timeline of all AV logs (filter on category)',
            '  quarantine.csv       quarantine items, hashes, recovered or not',
            '  collected_files.csv  every copied file; the copies are in files\\, decoded forms in decoded\\',
            '  summary.json         this summary for programs; qextract.log the run']
    return '\n'.join(out) + '\n'
