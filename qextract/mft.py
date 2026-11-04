"""File history from the NTFS metadata: the $MFT records and the $UsnJrnl:$J events of the
files the AV products named, so a file that sat on the disk long before its first detection
shows when it arrived (no real-time protection, a late signature, a scan days later).

- $MFT: every record is read once (streamed, 16 MB at a time); directories give the path map,
  the records whose $FILE_NAME matches a wanted file name are kept - in use or deleted (the
  quarantine usually deletes the original; its record survives until it is reused). Both time
  sets are reported: $STANDARD_INFORMATION (easy to change, "timestomping") and $FILE_NAME
  (set by the system); a $STANDARD_INFORMATION creation before the $FILE_NAME one is flagged.
- $UsnJrnl:$J: every record of the allocated part; the events of the matched records or names
  (create, write, rename, delete) with their times. The journal is small (32 MB by default):
  on a busy machine it covers hours or days.

Sources: a TSK volume (image, raw drive) or the files $MFT and $J of a triage collection.
Everything is read from the evidence and checked: record sizes, fixups, attribute bounds.
"""

import collections
import datetime
import re
import struct
import time

from .decoders.util import filetime, zone_fields

CHUNK = 16 << 20
ROOT_RECORD = 5
NAME_LIMIT = 50               # same-name records in other folders kept per name
ZONE_STREAM = 'zone.identifier'   # "Mark of the Web": where a downloaded file came from
ZONE_MAX = 4096
REASONS = ((0x1, 'data overwrite'), (0x2, 'data extend'), (0x4, 'data truncation'), (0x10, 'named data overwrite'),
           (0x20, 'named data extend'), (0x40, 'named data truncation'), (0x100, 'file create'),
           (0x200, 'file delete'), (0x400, 'ea change'), (0x800, 'security change'), (0x1000, 'rename old name'),
           (0x2000, 'rename new name'), (0x4000, 'indexable change'), (0x8000, 'basic info change'),
           (0x10000, 'hard link change'), (0x20000, 'compression change'), (0x40000, 'encryption change'),
           (0x80000, 'object id change'), (0x100000, 'reparse point change'), (0x200000, 'stream change'),
           (0x80000000, 'close'))
# the path, where the row comes from and the times that matter first; $FILE_NAME before
# $STANDARD_INFORMATION (the folder index only has $FILE_NAME), the details last
RECORD_COLUMNS = ['path', 'state', 'size', 'fn_created', 'fn_modified', 'si_created', 'si_modified',
                  'zone_id', 'host_url', 'referrer_url', 'note', 'match', 'target', 'record', 'sequence', 'directory',
                  'fn_mft_modified', 'fn_accessed', 'si_mft_modified', 'si_accessed', 'volume']
USN_COLUMNS = ['time', 'event', 'path', 'name', 'record', 'sequence', 'parent_record', 'usn', 'target',
               'volume']
FILETIME_MIN, FILETIME_MAX = 119600064000000000, 159000000000000000      # 1980 .. 2104
_U16, _II, _Q = struct.Struct('<H'), struct.Struct('<II'), struct.Struct('<Q')
_NONZERO = re.compile(b'[^\x00]')


def _span(a, b):
    """'7 h 12 min' / '3 d 4 h' between two ISO times (the report module would import back)."""
    try:
        seconds = int((datetime.datetime.fromisoformat(b.rstrip('Z')) -
                       datetime.datetime.fromisoformat(a.rstrip('Z'))).total_seconds())
    except ValueError:
        return '?'
    days, hours, minutes = seconds // 86400, seconds % 86400 // 3600, seconds % 3600 // 60
    return f'{days} d {hours} h' if days else f'{hours} h {minutes} min'


def _ft(value):
    return filetime(value) if FILETIME_MIN < value < FILETIME_MAX else ''


def _fixup(data, off, size):
    """The record with its update sequence applied (the last two bytes of each sector)."""
    usa_off, usa_count = struct.unpack_from('<HH', data, off + 4)
    if usa_count < 2 or usa_off + 2 * usa_count > size or (usa_count - 1) * 512 > size:
        return None
    rec = bytearray(data[off:off + size])
    for i in range(1, usa_count):
        end = i * 512
        rec[end - 2:end] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(rec)


def _patched(data, off, start, stop):
    """data[start:stop] of the record at off with the fixup bytes of the sector ends inside."""
    usa_off = struct.unpack_from('<H', data, off + 4)[0]
    out = bytearray(data[start:stop])
    sector = (start - off) // 512 + 1
    while off + sector * 512 - 2 < stop:
        end = off + sector * 512 - 2              # the two fixup bytes of this sector
        src = off + usa_off + 2 * sector
        if src + 2 > len(data) or usa_off + 2 * sector + 2 > 1024:
            break
        for k in range(2):
            if start <= end + k < stop:
                out[end + k - start] = data[src + k]
        sector += 1
    return bytes(out)


def parse_record(rec):
    """One fixed-up FILE record -> dict (flags, sequence, base, SI times, FN names), or None."""
    if len(rec) < 48 or rec[:4] != b'FILE':
        return None
    seq, _links, first, flags, used = struct.unpack_from('<HHHHI', rec, 16)
    base = struct.unpack_from('<Q', rec, 32)[0] & 0xFFFFFFFFFFFF
    out = {'sequence': seq, 'in_use': bool(flags & 1), 'directory': bool(flags & 2), 'base': base,
           'si': None, 'names': [], 'size': None}
    a = first
    end = min(used, len(rec))
    for _ in range(64):                                   # attribute count limit (crafted records)
        if a + 16 > end:
            break
        atype, alen = struct.unpack_from('<II', rec, a)
        if atype == 0xFFFFFFFF or alen < 16 or a + alen > end:
            break
        if atype == 0x80 and rec[a + 9] and 'zone' not in out:     # a named $DATA: an alternate stream
            name_off, nlen = struct.unpack_from('<H', rec, a + 10)[0], rec[a + 9]
            if a + name_off + 2 * nlen <= a + alen and \
                    rec[a + name_off:a + name_off + 2 * nlen].decode('utf-16-le', 'replace').lower() == ZONE_STREAM:
                if rec[a + 8] == 0 and a + 22 <= end:                # resident: the text is in the record
                    vlen, voff = struct.unpack_from('<IH', rec, a + 16)
                    if voff >= 16 and a + voff + vlen <= a + alen:
                        out['zone'] = bytes(rec[a + voff:a + voff + min(vlen, ZONE_MAX)])
                else:
                    out['zone'] = None                               # non-resident: not read (rare, > ~700 bytes)
        if atype == 0x80 and rec[a + 9] == 0 and out['size'] is None:      # the unnamed $DATA
            if rec[a + 8] == 0 and a + 20 <= end:
                out['size'] = struct.unpack_from('<I', rec, a + 16)[0]          # resident: value length
            elif rec[a + 8] == 1 and a + 56 <= end:
                out['size'] = struct.unpack_from('<Q', rec, a + 48)[0]          # non-resident: real size
        if rec[a + 8] == 0 and atype in (0x10, 0x30):     # resident
            vlen, voff = struct.unpack_from('<IH', rec, a + 16)
            body = a + voff
            if voff >= 16 and body + vlen <= a + alen:
                if atype == 0x10 and vlen >= 32:
                    out['si'] = struct.unpack_from('<4Q', rec, body)
                elif atype == 0x30 and vlen >= 66:
                    parent = struct.unpack_from('<Q', rec, body)[0]
                    times = struct.unpack_from('<4Q', rec, body + 8)
                    size = struct.unpack_from('<Q', rec, body + 48)[0]
                    nlen, space = rec[body + 64], rec[body + 65]
                    if body + 66 + 2 * nlen <= body + vlen:
                        name = rec[body + 66:body + 66 + 2 * nlen].decode('utf-16-le', 'replace')
                        out['names'].append({'parent': parent & 0xFFFFFFFFFFFF, 'parent_seq': parent >> 48,
                                             'times': times, 'size': size, 'name': name, 'space': space})
        a += alen
    return out


def _long_name(names):
    """The Win32 name before the DOS 8.3 one (namespace 2 = DOS only)."""
    for n in names:
        if n['space'] != 2:
            return n
    return names[0] if names else None


class History:
    """Collects the directory map and the wanted records in one pass over $MFT."""

    def __init__(self, targets):
        # targets: relative paths without the drive ('Users/x/Downloads/a.exe'), lower case
        self.targets = {t.lower().replace('\\', '/').strip('/') for t in targets if t}
        self.names = {t.rsplit('/', 1)[-1] for t in self.targets}
        self.lengths = {len(n) for n in self.names}
        # the folders the wanted files were in: their index ($I30) keeps copies of $FILE_NAME,
        # also of deleted entries (index slack), when the file's own record is gone
        self.parent_names = {t.rsplit('/', 2)[-2] for t in self.targets if t.count('/') >= 1}
        self.stash = {}               # folder record -> its raw record bytes (fixed up later)
        self.dirs = {}                # record -> (parent record, name)
        self.found = []               # (record number, parsed record, matching name entry)
        self.per_name = collections.Counter()
        self.records = 0
        self.usn_span = None          # (oldest, newest) time in $UsnJrnl:$J

    def _full(self, data, off, size, number):
        """The slow, exact way: fixups applied, every attribute parsed."""
        rec = _fixup(data, off, size)
        parsed = parse_record(rec) if rec else None
        if not parsed or not parsed['names']:
            return
        if parsed['directory'] and parsed['base'] == 0:
            n = _long_name(parsed['names'])
            self.dirs[number] = (n['parent'], n['name'])
            if any(x['name'].lower() in self.parent_names for x in parsed['names']):
                self.stash[number] = bytes(data[off:off + size])
        for n in parsed['names']:
            low = n['name'].lower()
            if len(n['name']) in self.lengths and low in self.names and self.per_name[low] < NAME_LIMIT * 4:
                self.per_name[low] += 1
                self.found.append((number, parsed, n))

    def feed(self, data, first_record, size):
        """Fast path over the raw records: only the $FILE_NAME headers are read in place. A record
        whose wanted part touches a sector end (where the fixup bytes sit), or that matches a
        wanted name, is parsed the exact way."""
        unpack_u16, unpack_ii, unpack_q = _U16.unpack_from, _II.unpack_from, _Q.unpack_from
        lengths, names, dirs = self.lengths, self.names, self.dirs
        for i in range(len(data) // size):
            off = i * size
            if data[off:off + 4] != b'FILE':
                continue
            self.records += 1
            first, flags = unpack_u16(data, off + 20)[0], unpack_u16(data, off + 22)[0]
            a, end = off + first, off + size
            directory = flags & 2 and unpack_q(data, off + 32)[0] & 0xFFFFFFFFFFFF == 0    # a base record
            number = first_record + i
            slow = False
            for _ in range(64):
                if a + 24 > end:
                    break
                pos = (a - off) % 512
                if pos > 506:                          # even the type field touches a sector end
                    slow = True
                    break
                atype = unpack_ii(data, a)[0]
                # attributes are sorted by type: after $FILE_NAME (0x30) no name can follow
                if atype > 0x30:
                    break
                if pos > 488:                          # a header we need straddles a sector end
                    slow = True
                    break
                alen = unpack_ii(data, a)[1]
                if alen < 16 or a + alen > end:
                    break
                if atype == 0x30 and data[a + 8] == 0:
                    body = a + unpack_u16(data, a + 20)[0]
                    if body + 66 > end:
                        break
                    nlen = data[body + 64]
                    stop = body + 66 + 2 * nlen
                    if (body - off) % 512 > 444:       # the fixed fields reach the fixup bytes (510, 511)
                        slow = True
                        break
                    if directory or nlen in lengths:
                        raw = data[body + 66:stop]
                        if stop > off + (body + 66 - off) // 512 * 512 + 510:
                            raw = _patched(data, off, body + 66, stop)    # the name holds fixup bytes
                        name = raw.decode('utf-16-le', 'replace')
                        if directory:              # the long name wins over the DOS 8.3 one
                            entry = (unpack_q(data, body)[0] & 0xFFFFFFFFFFFF, name)
                            if data[body + 65] != 2:
                                dirs[number] = entry
                            else:
                                dirs.setdefault(number, entry)
                            if name.lower() in self.parent_names:
                                self.stash[number] = bytes(data[off:off + size])
                        if nlen in lengths and name.lower() in names:
                            slow = True                # a wanted file: read it exactly
                            break
                a += alen
            if slow:
                self._full(data, off, size, number)

    def path(self, parent, name, limit=64):
        parts = [name]
        seen = set()
        while parent != ROOT_RECORD and limit > 0:
            if parent in seen or parent not in self.dirs:
                parts.append('?')            # the folder's record is gone or reused
                break
            seen.add(parent)
            parent, pname = self.dirs[parent]
            parts.append(pname)
            limit -= 1
        return '/'.join(reversed(parts))


def _stream_mft(source, history, deadline, status=None):
    """source: (read(offset, size) -> bytes, total size). status: gets 'reading $MFT: 45% ...'."""
    read, total = source
    first = read(0, 1024)
    if len(first) < 48 or first[:4] != b'FILE':
        raise ValueError('$MFT does not start with a FILE record')
    size = struct.unpack_from('<I', first, 28)[0]
    if size not in (1024, 2048, 4096):
        raise ValueError(f'unexpected MFT record size {size}')
    off = 0
    chunk = CHUNK - CHUNK % size
    while off < total:
        if time.monotonic() > deadline:
            raise TimeoutError('time limit reached while reading $MFT')
        data = read(off, min(chunk, total - off))
        if not data:
            break
        data = data[:len(data) - len(data) % size]
        history.feed(data, off // size, size)
        off += len(data)
        if status:
            status(f'reading $MFT: {off * 100 // max(total, 1)}% of {total // size:,} records')
    return size


def record_rows(history, volume_name, drive):
    rows = []
    kept = collections.Counter()
    for number, parsed, n in history.found:
        rel = history.path(n['parent'], n['name'])
        target = rel.lower()
        exact = target in history.targets
        if not exact:
            kept[n['name'].lower()] += 1
            if kept[n['name'].lower()] > NAME_LIMIT:
                continue
        si = parsed['si'] or (0, 0, 0, 0)
        fn = n['times']
        note = []
        if si[0] and fn[0] and si[0] < fn[0] - 10_000_000:
            # a restore from a quarantine, an archive tool or a copy that keeps the times does
            # this too, so it is a hint to check, not a finding
            note.append('$SI created before $FN created: times set by a tool (restore, unpack, copy) '
                        'or timestomping')
        if n['space'] == 2:
            note.append('8.3 name')
        zone = zone_fields(parsed['zone'].decode('utf-8', 'replace')) if parsed.get('zone') else {}
        if 'zone' in parsed and parsed['zone'] is None:
            note.append('Zone.Identifier stored outside the record (not read)')
        rows.append({
            **zone,
            'target': drive + '\\' + rel.replace('/', '\\') if exact else '',
            'match': 'path' if exact else 'name only (another folder)',
            'path': drive + '\\' + rel.replace('/', '\\'), 'record': number, 'sequence': parsed['sequence'],
            'state': 'in use' if parsed['in_use'] else 'deleted', 'directory': 'yes' if parsed['directory'] else '',
            'size': parsed['size'] if parsed['size'] is not None else (n['size'] or ''),
            'si_created': _ft(si[0]), 'si_modified': _ft(si[1]), 'si_mft_modified': _ft(si[2]),
            'si_accessed': _ft(si[3]),
            'fn_created': _ft(fn[0]), 'fn_modified': _ft(fn[1]), 'fn_mft_modified': _ft(fn[2]),
            'fn_accessed': _ft(fn[3]), 'note': '; '.join(note), 'volume': volume_name})
    return rows


def parse_usn(data, history, records, drive, volume_name, limit=200000):
    """Every USN record (v2 / v3) of the data; the ones of the wanted records or names.
    history.usn_span gets the oldest and newest time in the journal (what it can show at all)."""
    rows = []
    off = 0
    names = history.names
    oldest = newest = None
    while off + 60 <= len(data) and len(rows) < limit:
        length = struct.unpack_from('<I', data, off)[0]
        if length == 0:
            # zeros: page padding, but also gaps inside a page - go to the next non-zero 8-byte slot
            m = _NONZERO.search(data, off)
            if m is None:
                break
            off = max(off + 8, m.start() - m.start() % 8)
            continue
        major = struct.unpack_from('<H', data, off + 4)[0]
        if length < 60 or length > 1024 or length % 8 or major not in (2, 3) or off + length > len(data):
            off += 8
            continue
        if major == 2:
            ref, parent, usn, ts, reason = struct.unpack_from('<QQQQI', data, off + 8)
            nlen, noff = struct.unpack_from('<HH', data, off + 56)
            record, seq = ref & 0xFFFFFFFFFFFF, ref >> 48
            parent_rec = parent & 0xFFFFFFFFFFFF
        else:
            if length < 76:
                off += 8
                continue
            ref_lo, _ref_hi, par_lo, _par_hi, usn, ts, reason = struct.unpack_from('<QQQQQQI', data, off + 8)
            nlen, noff = struct.unpack_from('<HH', data, off + 72)
            record, seq = ref_lo & 0xFFFFFFFFFFFF, ref_lo >> 48
            parent_rec = par_lo & 0xFFFFFFFFFFFF
        if FILETIME_MIN < ts < FILETIME_MAX:
            oldest = ts if oldest is None or ts < oldest else oldest
            newest = ts if newest is None or ts > newest else newest
        if noff + nlen <= length:
            name = data[off + noff:off + noff + nlen].decode('utf-16-le', 'replace')
            if (record, seq) in records or name.lower() in names:
                rel = history.path(parent_rec, name)
                rows.append({'time': _ft(ts), 'event': ', '.join(t for bit, t in REASONS if reason & bit),
                             'path': drive + '\\' + rel.replace('/', '\\'), 'name': name, 'record': record,
                             'sequence': seq, 'parent_record': parent_rec, 'usn': usn,
                             'target': drive + '\\' + rel.replace('/', '\\') if rel.lower() in history.targets else '',
                             'volume': volume_name})
        off += length
    history.usn_span = (_ft(oldest), _ft(newest)) if oldest else None
    return rows


def _carve_index(buf, start, used, end, folder, wanted):
    """$FILE_NAME copies of wanted names in buf[start:end] (index entries, index slack, record
    slack). A copy is recognised by its name (an exact wanted name, searched only in the folder
    the file was in), plausible times and sizes; its parent reference may be overwritten (an
    end marker written over an old entry). Before used: live entries.
    -> [(state, file record or '', name entry)]"""
    out = []
    lengths = {len(w) for w in wanted}
    fn = start + (-(start) % 8)
    while fn + 66 <= end:
        nlen = buf[fn + 64]
        if nlen in lengths and buf[fn + 65] <= 3 and fn + 66 + 2 * nlen <= end:
            name = buf[fn + 66:fn + 66 + 2 * nlen].decode('utf-16-le', 'replace')
            times = struct.unpack_from('<4Q', buf, fn + 8)
            alloc, size = struct.unpack_from('<QQ', buf, fn + 40)
            if (name.lower() in wanted and FILETIME_MIN < times[0] < FILETIME_MAX
                    and FILETIME_MIN < times[1] < FILETIME_MAX and size <= alloc < 1 << 50):
                parent_ok = struct.unpack_from('<Q', buf, fn)[0] & 0xFFFFFFFFFFFF == folder
                live = fn - 16 < used and parent_ok
                ref = struct.unpack_from('<Q', buf, fn - 16)[0] & 0xFFFFFFFFFFFF if fn - 16 >= start else 0
                out.append(('index entry' if live else 'index slack (deleted entry)',
                            ref if parent_ok and ref else '',
                            {'parent': folder, 'name': name, 'times': times, 'space': buf[fn + 65], 'size': size,
                             'parent_ok': parent_ok}))
                fn += 66 + 2 * nlen
                fn += -fn % 8
                continue
        fn += 8
    return out


def _index_root(rec, folder, wanted):
    """The resident $INDEX_ROOT ($I30) of a fixed-up folder record."""
    if len(rec) < 48 or rec[:4] != b'FILE':
        return []
    a = struct.unpack_from('<H', rec, 20)[0]
    for _ in range(64):
        if a + 24 > len(rec):
            break
        atype, alen = struct.unpack_from('<II', rec, a)
        if atype == 0xFFFFFFFF or alen < 24 or a + alen > len(rec):
            break
        if atype == 0x90 and rec[a + 8] == 0:
            node = a + struct.unpack_from('<H', rec, a + 20)[0] + 16
            if node + 16 <= a + alen:
                first, used = struct.unpack_from('<II', rec, node)
                # up to the record end: the record slack keeps entries of a bigger, older index
                return _carve_index(rec, node + first, node + used, len(rec), folder, wanted)
        a += alen
    return []


def _index_allocation(volume, folder, wanted, limit=64 << 20):
    """The INDX blocks ($INDEX_ALLOCATION $I30) of a big folder, read through TSK."""
    import pytsk3
    out = []
    try:
        f = volume.fs.open_meta(inode=folder)
    except OSError:
        return out
    for attr in f:
        if attr.info.type != pytsk3.TSK_FS_ATTR_TYPE_NTFS_IDXALLOC:
            continue
        size = min(attr.info.size, limit)
        try:
            data = f.read_random(0, size, attr.info.type, attr.info.id)
        except OSError:
            continue
        for off in range(0, len(data) - 4095, 4096):
            if data[off:off + 4] != b'INDX':
                continue
            block = _fixup(data, off, 4096)
            if not block:
                continue
            first, used = struct.unpack_from('<II', block, 24)
            node = 24           # the block slack after the used part keeps old entries
            out += _carve_index(block, node + first, node + used, 4096, folder, wanted)
    return out


def index_rows(history, volume, drive, volume_name):
    """Index entries of the wanted files in their folders (live and slack)."""
    rows = []
    seen = set()
    for folder, raw in history.stash.items():
        if folder not in history.dirs:
            continue
        parent_real = history.path(*history.dirs[folder])
        parent_path = parent_real.lower()
        wanted = {t.rsplit('/', 1)[-1] for t in history.targets if t.rsplit('/', 1)[0] == parent_path}
        if not wanted:
            continue
        rec = _fixup(raw, 0, len(raw))
        found = _index_root(rec, folder, wanted) if rec else []
        if hasattr(volume, 'fs'):
            found += _index_allocation(volume, folder, wanted)
        for state, file_record, n in found:
            key = (n['name'].lower(), n['times'])
            if key in seen:                       # slack often holds the same entry twice
                continue
            seen.add(key)
            fn = n['times']
            path = drive + '\\' + (parent_real + '/' + n['name']).replace('/', '\\')
            rows.append({'target': path, 'match': 'path', 'path': path, 'record': file_record, 'sequence': '',
                         'state': state, 'directory': '', 'size': n['size'] or '',
                         'si_created': '', 'si_modified': '', 'si_mft_modified': '', 'si_accessed': '',
                         'fn_created': _ft(fn[0]), 'fn_modified': _ft(fn[1]), 'fn_mft_modified': _ft(fn[2]),
                         'fn_accessed': _ft(fn[3]),
                         'note': 'a $FILE_NAME copy in the folder index ($I30); kept after the file record is gone'
                                 + ('' if n['parent_ok'] else '; its folder reference is overwritten (found by name '
                                                              'in this folder)'),
                         'volume': volume_name})
    return rows


def _tsk_sources(volume):
    """-> ((read, size) of $MFT, bytes of $J or None) from a TSK volume."""
    import pytsk3
    fs = volume.fs
    mft = fs.open('/$MFT')
    mft_src = (mft.read_random, mft.info.meta.size)
    usn = None
    try:
        j = fs.open('/$Extend/$UsnJrnl')
    except OSError:
        return mft_src, None
    for attr in j:
        if attr.info.name == b'$J':
            real = sum(r.len for r in attr if not (r.flags & pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE)) * fs.info.block_size
            real = min(real, attr.info.size, 1 << 30)
            pos, parts = attr.info.size - real, []
            while pos < attr.info.size:
                try:
                    d = j.read_random(pos, min(CHUNK, attr.info.size - pos), pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA,
                                      attr.info.id)
                except OSError:
                    d = b''
                if not d:
                    break
                parts.append(d)
                pos += len(d)
            usn = b''.join(parts)
    return mft_src, usn


def _file_sources(volume, root):
    """$MFT and $J as files of a triage collection (KAPE: C\\$MFT, C\\$Extend\\$UsnJrnl%3A$J).
    -> ((read, size), $J bytes, the stream to close)"""
    prefix = f'{root}/' if root else ''
    mft = next(iter(volume.glob(prefix + '$MFT')), None)
    if mft is None:
        return None, None, None
    stream = volume.open(mft)

    def read(o, n, stream=stream):
        stream.seek(o)
        return stream.read(n)
    usn = None
    for pattern in ('$Extend/$UsnJrnl%3A$J', '$Extend/$J', '$J', '$UsnJrnl%3A$J'):
        e = next(iter(volume.glob(prefix + pattern)), None)
        if e is not None and e.size <= 1 << 30:
            usn = volume.read(e).lstrip(b'\x00')
            break
    return (read, mft.size), usn, stream


def history_for(volume, root, drive, paths, log, seconds=600, status=None):
    """-> (record rows, USN rows, notes) for the wanted absolute paths on this drive."""
    rel = sorted({p[3:].replace('\\', '/') for p in paths if re.match(rf'^{re.escape(drive)}\\', p, re.IGNORECASE)})
    if not rel:
        return [], [], []
    history = History(rel)
    notes = []
    t0 = time.monotonic()
    stream = None
    if hasattr(volume, 'fs'):
        mft_src, usn = _tsk_sources(volume)
    else:
        mft_src, usn, stream = _file_sources(volume, root)
    if mft_src is None:
        return [], [], ['no $MFT on this volume (NTFS image, raw drive or a collection with $MFT needed)']
    try:
        _stream_mft(mft_src, history, t0 + seconds, status)
    finally:
        if stream is not None:
            stream.close()
    if status:
        status('reading the folder indexes ($I30) of the detected files')
    records = record_rows(history, volume.name, drive)
    wanted = {(r['record'], r['sequence']) for r in records}
    # a folder index entry of a file whose own record is here, with the same $FILE_NAME times,
    # says nothing new; the deleted ones and different times stay
    known = {(r['path'].lower(), r['fn_created'], r['fn_modified']) for r in records}
    records += [r for r in index_rows(history, volume, drive, volume.name)
                if (r['path'].lower(), r['fn_created'], r['fn_modified']) not in known]
    if status and usn:
        status(f'reading $UsnJrnl:$J ({len(usn) // 1048576:,} MB)')
    usn_rows = parse_usn(usn, history, wanted, drive, volume.name) if usn else []
    if usn is None:
        notes.append('no $UsnJrnl:$J')
    elif history.usn_span:
        a, b = history.usn_span
        shown = [t[:19].replace('T', ' ') for t in (a, b)]
        notes.append(f'$UsnJrnl:$J covers {shown[0]} .. {shown[1]} UTC '
                     f'({_span(a, b)}): file moves and creations before that are not in it')
    log(f'  File history: {history.records:,} MFT records read, {len(records)} matching record(s), '
        f'{len(usn_rows)} USN event(s) for {len(rel)} file(s) in {time.monotonic() - t0:.1f} s')
    return records, usn_rows, notes


MOVE_COLUMNS = ['target', 'time', 'step', 'from', 'to', 'record', 'sequence', 'usn', 'evidence', 'volume']


def file_moves(records, usn_rows):
    """The way each detected file took on this volume, from $UsnJrnl: a move or rename inside
    one NTFS volume keeps the file's record number, so the journal's "rename old name" /
    "rename new name" pairs of that record are its hops (as far back as the journal reaches).
    A copy or a move from another drive is a new record and is not followed here.
    -> (rows for mft\\file_moves.csv, {target lower: one-line journey})"""
    owner = {}
    for r in records:
        if r.get('match') == 'path' and r.get('target') and r.get('record') != '':
            owner.setdefault((r['record'], r['sequence']), r['target'])
    for u in usn_rows:
        if u.get('target'):
            owner.setdefault((u['record'], u['sequence']), u['target'])
    by_file = collections.defaultdict(list)
    for u in usn_rows:
        key = (u['record'], u['sequence'])
        if key in owner:
            by_file[key].append(u)
    rows, journeys = [], {}
    for key, events in by_file.items():
        target = owner[key]
        steps, old = [], None
        for u in sorted(events, key=lambda e: (e['usn'], e['time'])):
            ev = u['event']
            base = {'target': target, 'time': u['time'], 'record': key[0], 'sequence': key[1], 'usn': u['usn'],
                    'evidence': f"$UsnJrnl USN {u['usn']}", 'volume': u.get('volume', '')}
            if 'file create' in ev and not steps:
                steps.append(dict(base, step='created', **{'from': '', 'to': u['path']}))
            if 'rename old name' in ev:
                old = u['path']
            elif 'rename new name' in ev:
                frm = old or ''
                same_folder = frm.rsplit('\\', 1)[0].lower() == u['path'].rsplit('\\', 1)[0].lower()
                steps.append(dict(base, step='renamed' if same_folder and frm else 'moved',
                                  **{'from': frm, 'to': u['path']}))
                old = None
            if 'file delete' in ev:
                steps.append(dict(base, step='deleted', **{'from': u['path'], 'to': ''}))
        rows += steps
        if any(s['step'] in ('moved', 'renamed') for s in steps):
            parts = []
            for s in steps:
                when = s['time'][:19].replace('T', ' ')
                if s['step'] == 'created':
                    parts.append(f"{when} created in {s['to']}")
                elif s['step'] in ('moved', 'renamed'):
                    parts.append(f"{when} {s['step']} to {s['to']}")
                else:
                    parts.append(f"{when} deleted")
            journeys[target.lower()] = ' -> '.join(parts)
    return rows, journeys


def first_on_disk(records, usn_rows):
    """-> {target path lower: (earliest time, what shows it)} from path matches: when the file
    ARRIVED in that place. Only times the system sets on creation count: $FILE_NAME created and
    the journal's file create. Modified times are the age of the CONTENT (an unpack, a copy or a
    download keeps them: lab, mimikatz unpacked 2026-11-02 carries 2022 write times) and
    $STANDARD_INFORMATION created can be set by any tool; it is only used when nothing else is
    there. All of them stay in mft\\file_records.csv."""
    best, fallback = {}, {}

    def offer(table, target, when, what):
        if target and when:
            key = target.lower()
            if key not in table or when < table[key][0]:
                table[key] = (when, what)
    for r in records:
        if r['match'] == 'path':
            offer(best, r['target'], r['fn_created'], '$MFT $FILE_NAME created')
            offer(fallback, r['target'], r['si_created'], '$MFT $STANDARD_INFORMATION created (settable by tools)')
    for u in usn_rows:
        if 'file create' in u['event']:
            offer(best, u['target'], u['time'], '$J file create')
    for key, value in fallback.items():
        best.setdefault(key, value)
    return best
