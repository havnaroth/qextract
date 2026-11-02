"""Helpers shared by the decoders."""

import contextlib
import datetime
import hashlib
import math
import re
import sqlite3
import struct

try:
    from Cryptodome.Cipher import ARC4
except ImportError:     # slow, but keeps the decoders usable without pycryptodomex
    ARC4 = None


def rc4(key, data):
    """RC4 because the quarantine formats use it, not as protection."""
    if ARC4 is not None:
        return ARC4.new(bytes(key)).decrypt(bytes(data))  # nosec B304 - format requirement
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for k, b in enumerate(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[k] = b ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def xor(data, key):
    """XOR with a single byte (int) or a repeating key (bytes)."""
    if isinstance(key, int):
        return bytes(data).translate(bytes(b ^ key for b in range(256)))
    key = bytes(key)
    full = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, 'little') ^ int.from_bytes(full, 'little')).to_bytes(len(data), 'little')


# one line per value: anything but tab, including line breaks and escape sequences
_CONTROL_CHARS = re.compile('[\x00-\x08\x0a-\x1f\x7f\x9b]')


def metadata_text(fields, sections=()):
    """The .metadata.txt stored next to a recovered file: 'key: value' lines for the
    non-empty fields, then [title] sections of text lines. Everything comes from the
    evidence, so control characters are replaced."""
    lines = ['qextract - metadata of a recovered quarantine item', '']
    lines += [f'{k}: {_CONTROL_CHARS.sub("?", str(v))}' for k, v in fields.items() if v not in ('', None)]
    for title, body in sections:
        lines += ['', f'[{title}]']
        lines += [_CONTROL_CHARS.sub('?', line) for line in body.splitlines()]
    return '\r\n'.join(lines) + '\r\n'


def _iso(dt):
    return dt.isoformat().replace('+00:00', 'Z')


def filetime(value):
    if not value:
        return ''
    try:
        return _iso(datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)
                    + datetime.timedelta(microseconds=value // 10))
    except OverflowError:
        return ''


def unixtime(value):
    if not value:
        return ''
    try:
        return _iso(datetime.datetime.fromtimestamp(value, datetime.UTC))
    except (OverflowError, OSError, ValueError):
        return ''


def plain_path(path):
    """'\\\\?\\C:\\x' -> 'C:\\x', '\\\\?\\UNC\\host\\x' -> '\\\\host\\x'."""
    if path.startswith('\\\\?\\UNC\\'):
        return '\\\\' + path[8:]
    if path.startswith('\\\\?\\'):
        return path[4:]
    return path


def cstring(data, offset, size=None, encoding='utf-8'):
    """Zero-terminated string; UTF-16 strings end at an aligned double zero."""
    end = len(data) if size is None else min(len(data), offset + size)
    chunk = data[offset:end]
    if encoding.startswith('utf-16'):
        for i in range(0, len(chunk) - 1, 2):
            if chunk[i:i + 2] == b'\0\0':
                chunk = chunk[:i]
                break
    else:
        chunk = chunk.split(b'\0', 1)[0]
    return chunk.decode(encoding, 'replace')


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def digest(name, data):
    """MD5 / SHA1 here identify files and check quarantine formats; they protect nothing."""
    return hashlib.new(name, data, usedforsecurity=False).hexdigest()


@contextlib.contextmanager
def guard(rows, entry):
    """One quarantined item. Everything in it comes from the evidence and may be damaged or
    crafted, so any error becomes an error row for this item and the others go on."""
    try:
        yield
    except Exception as e:  # noqa: BLE001 - deliberate boundary around untrusted input
        rows.append({'container': entry.path, 'item_type': 'file',
                     'status': f'error: {type(e).__name__}: {e}'[:500]})


def open_sqlite(data):
    """An SQLite database from the evidence: in memory, read-only, schema not trusted
    (no functions from views or triggers), text that is not UTF-8 kept instead of failing.
    A database in WAL mode (header bytes 18-19 = 2) cannot be opened from memory, so the copy
    is switched to rollback mode; what is still only in the -wal file next to it is not read."""
    data = bytearray(data)
    if data[18:20] == b'\x02\x02':
        data[18:20] = b'\x01\x01'
    con = sqlite3.connect(':memory:')
    con.deserialize(bytes(data))
    con.execute('PRAGMA trusted_schema = OFF')
    con.execute('PRAGMA query_only = ON')
    con.text_factory = lambda b: b.decode('utf-8', 'replace')
    return con


_SIGNATURES = {
    ('exe', 'dll', 'sys', 'scr', 'ocx', 'cpl', 'drv', 'efi', 'mui'): (b'MZ',),
    ('zip', 'jar', 'apk', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'odt', 'ods'): (b'PK\x03\x04', b'PK\x05\x06'),
    ('pdf',): (b'%PDF',),
    ('doc', 'xls', 'ppt', 'msi', 'msg'): (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',),
    ('rar',): (b'Rar!',),
    ('7z',): (b"7z\xbc\xaf'\x1c",),
    ('gz', 'tgz'): (b'\x1f\x8b',),
    ('png',): (b'\x89PNG',),
    ('jpg', 'jpeg'): (b'\xff\xd8\xff',),
    ('gif',): (b'GIF8',),
    ('lnk',): (b'L\x00\x00\x00',),
}
_EXTENSION = {ext: sigs for exts, sigs in _SIGNATURES.items() for ext in exts}
_ALL_SIGNATURES = tuple(s for sigs in _SIGNATURES.values() for s in sigs)


def _entropy(data):
    counts = [data.count(bytes((b,))) for b in range(256)]
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def plausibility(content, name):
    """'' when a recovered file looks like what its name says, else why not. For decoders
    without a stored hash: a wrong key gives random bytes, which a real file rarely is."""
    ext = name.replace('\\', '/').rsplit('/', 1)[-1].rsplit('.', 1)[-1].lower() if '.' in name else ''
    expected = _EXTENSION.get(ext)
    if expected and content and not content.startswith(expected):
        return f'content does not start like a .{ext} file'
    if len(content) >= 65536 and not content.startswith(_ALL_SIGNATURES):
        sample = content[:1048576]
        if _entropy(sample) > 7.995:
            return 'content looks like random bytes'
    return ''


def recovered(ctx, row, content, expected=None, name=None):
    """Hash the recovered file, compare with what the quarantine stored, save it.

    expected: (algorithm, hex digest) or ('size', int)."""
    hashes = {
        'md5': digest('md5', content),
        'sha1': digest('sha1', content),
        'sha256': hashlib.sha256(content).hexdigest(),
    }
    row.update(hashes, size=len(content))
    # without a stored hash (or with a size only: a wrong XOR / RC4 key gives a file of the same
    # length) the file is also checked for looking like its type
    if expected is None or expected[1] in (None, ''):
        status, weak = 'recovered (not verified', True
    else:
        kind, value = expected
        ok = (len(content) == int(value)) if kind == 'size' else (hashes[kind] == str(value).lower())
        if not ok:
            status, weak = f'recovered ({kind.upper()} differs from the stored one)', False
        elif kind == 'size':
            status, weak = 'recovered (size matches', True
        else:
            status, weak = 'recovered', False
    if weak:
        doubt = plausibility(content, row.get('original_path') or name or '')
        status += f'; {doubt})' if doubt else ')'
        if doubt:
            ctx.warn(f'{row.get("container", "")}: {doubt} - either the file does not match its name '
                     '(e.g. a fake extension) or the decoding is wrong (e.g. a changed key)')
    row['status'] = status
    original = (row.get('original_path') or '').replace('\\', '/').rsplit('/', 1)[-1]
    row['saved_as'] = ctx.save(f'{hashes["sha256"]}_{original or name or "file"}', content)
    return row
