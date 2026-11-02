"""Bitdefender quarantine (ProgramData\\Bitdefender\\Desktop\\Quarantine\\).

<guid>.dat is one item: three length-prefixed strings (content id, original path,
detection), then times, the original's size, attributes, its security descriptor and, last,
its SHA256 in hex. <content id>.bdq is the file, shared by items with the same content;
byte i is stored as ((p ^ (0x19 + 3i)) + 0x2B + 20i) & 0xFF, so the key repeats every 256.
"""

import re
import struct

from . import decoder
from .util import filetime, guard, plain_path, recovered, unixtime

MAX_STRING = 64 * 1024
_ITEM = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.dat', re.IGNORECASE)
_HEX = re.compile(rb'[0-9A-Fa-f]{64}')
_TABLES = [bytes(((c - 0x2B - 20 * i) & 0xFF) ^ ((0x19 + 3 * i) & 0xFF) for c in range(256)) for i in range(256)]


def decrypt(data):
    out = bytearray(len(data))
    for i, table in enumerate(_TABLES):
        out[i::256] = data[i::256].translate(table)
    return bytes(out)


def _strings(data, count):
    off, values = 0, []
    for _ in range(count):
        if off + 4 > len(data):
            raise ValueError('item header cut short')
        (size,) = struct.unpack_from('<I', data, off)
        if size > MAX_STRING or off + 4 + size > len(data):
            raise ValueError('item header damaged')
        values.append(data[off + 4:off + 4 + size].split(b'\0', 1)[0].decode('utf-8', 'replace'))
        off += 4 + size
    return values, off


def _item(data, row):
    """Fills row from a .dat -> (content id, size or None, expected hash or None)."""
    (content_id, path, detection), off = _strings(data, 3)
    row.update(resource=content_id, original_path=plain_path(path), detection=detection)
    size = None
    if off + 59 <= len(data):
        kind, quarantined = struct.unpack_from('<II', data, off + 4)
        (size,) = struct.unpack_from('<Q', data, off + 22)
        created, accessed, modified = struct.unpack_from('<QQQ', data, off + 35)
        row.update(quarantined=unixtime(quarantined), file_created=filetime(created),
                   file_accessed=filetime(accessed), file_modified=filetime(modified))
        if kind != 3:
            row['item_type'] = f'type {kind}'
    expected = None
    if len(data) >= off + 69 and data[-69:-65] == b'\x41\0\0\0' and _HEX.fullmatch(data[-65:-1]):
        expected = ('sha256', data[-65:-1].decode().lower())
    return content_id.upper(), size, expected


@decoder('bitdefender')
def decode(ctx, files, options):
    contents = {f.name[:-4].upper(): f for f in files if f.name.lower().endswith('.bdq')}
    rows, items = [], []
    for f in files:
        if _ITEM.fullmatch(f.name):
            with guard(rows, f):
                row = {'container': f.path, 'item_type': 'file'}
                items.append((*_item(ctx.read(f), row), row))
    # items sharing a .bdq are decrypted once (many crafted items must not mean many decryptions)
    items.sort(key=lambda item: item[0])
    current_id, content, error = None, None, None
    for content_id, size, expected, row in items:
        if content_id != current_id:
            current_id, content, error = content_id, None, None
            bdq = contents.get(content_id)
            if bdq is None:
                error = f'{content_id}.bdq is not in the quarantine folder'
            else:
                try:
                    content = decrypt(ctx.read(bdq))
                except (OSError, ValueError) as e:     # unreadable or above the decode limit
                    error = f'{bdq.name}: {e}'
        if content is None:
            row['status'] = f'not recovered: {error}'
        else:
            if size is not None and size != len(content):
                row['notes'] = f'size in the item {size}, content {len(content)}'
            try:
                recovered(ctx, row, content, expected)
            except OSError as e:                       # e.g. the output disk is full
                row['status'] = f'error: {e}'
        rows.append(row)
    return rows
