"""G DATA quarantine (AVK\\Quarantine\\*.q).

Two metadata blocks (plain magic + length, RC4 body) and the file (RC4), each encrypted
separately with a key from AVKQt.dll.
"""

from . import decoder
from .util import filetime, guard, rc4, recovered, u32, u64, unixtime

KEY = bytes([0xA7, 0xBF, 0x73, 0xA0, 0x9F, 0x03, 0xD3, 0x11, 0x85, 0x6F, 0x00, 0x80, 0xAD, 0xA9, 0x6E, 0x9B])
MAGIC1 = b'\xca\xfe\xba\xbe'
MAGIC2 = b'\xba\xad\xf0\x0d'


def _string(data, pos):
    """3 byte marker, 1 byte character count, UTF-16LE text."""
    count = data[pos + 3]
    end = pos + 4 + count * 2
    return data[pos + 4:end].decode('utf-16-le', 'replace'), end


@decoder('gdata')
def decode(ctx, files, options):
    rows = []
    for f in files:
        if not f.name.lower().endswith('.q'):
            continue
        with guard(rows, f):
            data = ctx.read(f)
            row = {'container': f.path, 'item_type': 'file'}
            if data[:4] != MAGIC1:
                raise ValueError('not a G DATA quarantine file')
            len1 = u32(data, 4)
            part1 = rc4(KEY, data[8:8 + len1])
            pos = 8 + len1
            if data[pos:pos + 4] != MAGIC2:
                raise ValueError('second block missing')
            len2 = u32(data, pos + 4)
            part2 = rc4(KEY, data[pos + 8:pos + 8 + len2])
            content = rc4(KEY, data[pos + 8 + len2:])

            row['quarantined'] = unixtime(u32(part1, 0x0C))
            row['detection'], _ = _string(part1, 0x14)
            size = u32(part2, 0x08)
            _, p = _string(part2, 0x0C)
            p += 8
            times = [filetime(u64(part2, p + 8 * i)) for i in range(3)]
            row['original_path'], _ = _string(part2, p + 24 + 8)
            row['notes'] = 'file times: ' + ', '.join(t for t in times if t)
            recovered(ctx, row, content, ('size', size))
            rows.append(row)
    return rows
