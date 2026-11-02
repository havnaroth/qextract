"""FortiClient quarantine (Program Files\\Fortinet\\FortiClient\\quarantine\\*).

Layout: magic "QUARF\\0\\0\\0", the file length at 0x34, a SYSTEMTIME-like timestamp at 0x38, path
and threat name lengths at 0x58 / 0x5C, both UTF-16 strings from 0x60, then the file XORed
with 0xAB up to the end.
"""

import struct

from . import decoder
from .util import guard, recovered, xor

MAGIC = b'QUARF\0\0\0'


@decoder('forticlient')
def decode(ctx, files, options):
    rows = []
    for f in files:
        if f.name.lower().endswith('.meta'):
            continue
        with guard(rows, f):
            data = ctx.read(f)
            if not data.startswith(MAGIC):
                continue
            row = {'container': f.path, 'item_type': 'file'}
            length, = struct.unpack_from('<I', data, 0x34)
            year, month, _tz, day, hour, minute, second = struct.unpack_from('<7H', data, 0x38)
            path_len, type_len = struct.unpack_from('<II', data, 0x58)
            pos = 0x60
            path = data[pos:pos + path_len].decode('utf-16-le', 'replace')
            threat = data[pos + path_len:pos + path_len + type_len].decode('utf-16-le', 'replace')
            if path.startswith('\\\\?\\'):
                path = path[4:]
            row.update(original_path=path.rstrip('\0'), detection=threat.rstrip('\0'),
                       quarantined=f'{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}')
            content = xor(data[pos + path_len + type_len:], 0xAB)
            rows.append(recovered(ctx, row, content, ('size', length)))
    return rows
