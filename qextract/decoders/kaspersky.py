"""Kaspersky quarantine.

Security for Windows Server (<version>\\Quarantine\\{uuid} + quarantine.db): files are XORed
with an 8 byte key; quarantine.db (SQLite) holds the metadata. Its times are packed local
time fields, so they are written without a time zone.
Desktop products (<version>\\QB\\<id>.klq, "KLQB"): a 64-byte header (data offset, data size,
original size at 0x30), the file XORed with the same key, then cNP_QB_* metadata records
(each XORed from its own start; not decoded yet).
"""

import datetime
import re
import sqlite3
import struct

from . import decoder
from .util import guard, open_sqlite, recovered, xor

KEY = bytes([0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC])
UUID = re.compile(r'^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$', re.IGNORECASE)


def packed_time(value):
    """Y(16) M(8) D(8) h(8) m(8) s(8) unused(8), local time."""
    if not value:
        return ''
    if not isinstance(value, int):
        return str(value)
    y, mo, d = value >> 48, (value >> 40) & 0xFF, (value >> 32) & 0xFF
    h, mi, s = (value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF
    return f'{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d} (local time)'


def _key(uuid):
    return str(uuid or '').strip('{}').lower()


def _original(obj):
    path, name = str(obj.get('path') or ''), str(obj.get('name') or '')
    if name and not path.lower().endswith(name.lower()):
        return path.rstrip('\\') + '\\' + name if path else name
    return path


def _objects(ctx, db_entry):
    con = open_sqlite(ctx.read(db_entry))
    try:
        con.row_factory = sqlite3.Row
        return {_key(r['uuid']): dict(r) for r in con.execute('SELECT * FROM objects')}
    finally:
        con.close()


@decoder('kaspersky')
def decode(ctx, files, options):
    rows = []
    folders = {}
    for f in files:
        folder = f.path.rsplit('/', 1)[0]
        if f.name.lower() == 'quarantine.db':
            folders.setdefault(folder, [None, []])[0] = f
        elif UUID.match(f.name):
            folders.setdefault(folder, [None, []])[1].append(f)
    for _folder, (db, items) in sorted(folders.items()):
        objects = {}
        if db is not None:
            try:
                objects = _objects(ctx, db)
            except (sqlite3.Error, ValueError, OSError, TypeError) as e:
                ctx.warn(f'{db.path}: {e}')
        seen = set()
        for f in items:
            with guard(rows, f):
                obj = objects.get(_key(f.name), {})
                seen.add(_key(f.name))
                row = {'container': f.path, 'item_type': 'file', 'resource': f.name,
                       'detection': str(obj.get('virname') or ''), 'quarantined': packed_time(obj.get('time')),
                       'original_path': _original(obj),
                       'notes': f'user: {obj["user"]}' if obj.get('user') else ''}
                recovered(ctx, row, xor(ctx.read(f), KEY), ('size', obj.get('size')))
                rows.append(row)
        for uuid, obj in sorted(objects.items()):
            if uuid not in seen and db is not None:
                with guard(rows, db):
                    rows.append({'container': db.path, 'resource': str(obj['uuid']), 'item_type': 'file',
                                 'detection': str(obj.get('virname') or ''),
                                 'quarantined': packed_time(obj.get('time')),
                                 'original_path': _original(obj), 'status': 'metadata only (file missing)'})
    for f in files:
        if f.name.lower().endswith('.klq'):
            with guard(rows, f):
                rows.append(_klqb(ctx, f))
    return rows


_DRIVE_PATH = re.compile(r'[A-Za-z]:\\[^\x00-\x1f]+')
_DETECTION = re.compile(r'[A-Za-z][\w!-]*(?:\.[\w!@-]+){2,}')
_UTF16_TEXT = re.compile(rb'(?:[\x20-\x7e]\x00|[\x80-\xff][\x00-\x05]){3,}')
_ASCII_TEXT = re.compile(rb'[\x20-\x7e]{6,}')


def _klqb_info(meta):
    """Original path and detection from the cNP_QB_INFO record. Each record is XORed with KEY
    from its own start, so its text reads with the phase that makes the record name readable;
    the record's inner layout is not decoded, the two strings are picked by their shape."""
    for phase in range(8):
        plain = bytes(b ^ KEY[(i + phase) % 8] for i, b in enumerate(meta))
        at = plain.find(b'cNP_QB_INFO\x00')
        if at < 0:
            continue
        texts = [m.group().decode('utf-16-le', 'replace') for m in _UTF16_TEXT.finditer(plain, at)]
        texts += [m.group().decode('ascii') for m in _ASCII_TEXT.finditer(plain, at + 12)]   # the detection is ASCII
        path = next((m.group() for t in texts if (m := _DRIVE_PATH.search(t))), '')
        detection = next((m.group() for t in texts for m in _DETECTION.finditer(t)
                          if m.start() == 0 or t[m.start() - 1] not in '\\/.'), '')
        return path, detection
    return '', ''


_TIMES = {b'cNP_QB_STORE_TIME': 'quarantined', b'cNP_QB_FILE_CREATION_TIME': 'file_created',
          b'cNP_QB_FILE_LAST_WRITE_TIME': 'file_modified', b'cNP_QB_FILE_LAST_ACCESS_TIME': 'file_accessed'}
_YEAR_ONE = datetime.datetime(1, 1, 1, tzinfo=datetime.UTC)


def _klqb_values(meta):
    """Times and attributes: a record's value follows its name and reads with the record's
    phase. Times count 10 ns units from 0001-01-01 UTC (lab: creation, quarantine and the
    2022 modification time of the sample all matched)."""
    found = {}
    for phase in range(8):
        plain = bytes(b ^ KEY[(i + phase) % 8] for i, b in enumerate(meta))
        for tag, column in _TIMES.items():
            at = plain.find(tag + b'\0')
            if at >= 0 and at + len(tag) + 9 <= len(plain):
                (value,) = struct.unpack_from('<Q', plain, at + len(tag) + 1)
                try:
                    when = _YEAR_ONE + datetime.timedelta(microseconds=value // 100)
                except OverflowError:
                    continue
                if 1980 <= when.year <= 2200:
                    found[column] = when.isoformat(timespec='microseconds').replace('+00:00', 'Z')
        at = plain.find(b'cNP_QB_FILE_ATTRIBUTES\0')
        if at >= 0 and at + 27 <= len(plain):
            found['attributes'] = struct.unpack_from('<I', plain, at + 23)[0]
        at = plain.find(b'cNP_QB_FULLNAME\0')
        if at >= 0:
            start = at + 16
            end = next((i for i in range(start, min(len(plain) - 1, start + 65536), 2)
                        if plain[i:i + 2] == b'\0\0'), -1)
            if end > start:
                found['fullname'] = plain[start:end].decode('utf-16-le', 'replace')
        for tag, column in ((b'cNP_QB_FILE_SECURITY_OWNER', 'owner'), (b'cNP_QB_FILE_SECURITY_GROUP', 'group')):
            at = plain.find(tag + b'\0')
            if at >= 0 and (sid := _sd_sid(plain[at + len(tag) + 1:at + len(tag) + 1 + 256], column)):
                found[column] = sid
        at = plain.find(b'cNP_QB_INFO\0')
        if at >= 0:
            found['info'] = [plain[m.end():m.end() + plain[m.end() - 1] // 2 - 1].decode('ascii', 'replace')
                             for m in re.finditer(rb'\x89\x30[\x04-\xff]', plain[:at + 4096]) if m.start() > at]
    return found


def _sd_sid(sd, which):
    """Owner or group SID of a self-relative security descriptor."""
    if len(sd) < 20 or sd[0] != 1:
        return ''
    off = struct.unpack_from('<I', sd, 4 if which == 'owner' else 8)[0]
    if not 20 <= off <= len(sd) - 8 or sd[off] != 1:
        return ''
    count = sd[off + 1]
    if off + 8 + 4 * count > len(sd) or count > 15:
        return ''
    authority = int.from_bytes(sd[off + 2:off + 8], 'big')
    subs = struct.unpack_from(f'<{count}I', sd, off + 8)
    return 'S-1-' + '-'.join(str(x) for x in (authority, *subs))


def _klqb(ctx, f):
    """Desktop products: QB\\<id>.klq = "KLQB" header, the file XORed with KEY from the data
    start, then the metadata (cNP_QB_* records)."""
    data = ctx.read(f)
    row = {'container': f.path, 'item_type': 'file', 'resource': f.name}
    if len(data) < 64 or data[:4] != b'KLQB':
        row['status'] = 'error: not a KLQB file'
        return row
    data_off, data_size = struct.unpack_from('<QQ', data, 8)
    (size,) = struct.unpack_from('<Q', data, 48)
    if not 64 <= data_off <= len(data) or data_off + data_size > len(data) or size > data_size:
        row['status'] = 'error: KLQB header out of range'
        return row
    meta = data[data_off + size:]
    values = _klqb_values(meta)
    attributes, info = values.pop('attributes', None), values.pop('info', [])
    group = values.pop('group', '')
    path, detection = values.pop('fullname', ''), next((s for s in info if _DETECTION.fullmatch(s)), '')
    if not path or not detection:                      # fall back to the strings' shape
        shape_path, shape_detection = _klqb_info(meta)
        path, detection = path or shape_path, detection or shape_detection
    account = next((s for s in info if '\\' in s and not _DRIVE_PATH.match(s)), '')
    row.update(original_path=path, detection=detection, owner_sid=values.pop('owner', ''), **values,
               notes='; '.join(x for x in (f'attributes {attributes:#x}' if attributes is not None else '',
                                           f'group {group}' if group else '',
                                           f'account {account}' if account else '') if x))
    return recovered(ctx, row, xor(data[data_off:data_off + size], KEY))
