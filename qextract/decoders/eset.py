"""ESET quarantine (Users\\<user>\\AppData\\Local\\ESET\\ESET Security\\Quarantine\\).

<hash>.NQF is the file, every byte stored as ((b - 84) mod 256) XOR 0xA5; the name is the
SHA1 (older versions) or the SHA256 (version 20) of the original, which checks the result.
<hash>.NDF ("FQDF") holds one item per quarantined copy of that content: original path,
attributes, a "NIWI" block with the file's created / modified / accessed FILETIMEs, the
quarantine time (unix), the detection name (in the system's language), a technical
description ("@NAME=...@TYPE=...") and the path again. <hash>.NAF (an event record, same
byte coding) is copied but not parsed.
"""

import re
import struct

from . import decoder
from .util import filetime, guard, recovered, unixtime

TABLE = bytes(((b - 84) % 256) ^ 0xA5 for b in range(256))
NAME = re.compile(r'^([0-9a-f]{40}|[0-9a-f]{64})\.nqf$', re.IGNORECASE)
MAX_CHARS = 32 * 1024
MAX_ITEMS = 10000


def _wstr(data, off):
    (chars,) = struct.unpack_from('<I', data, off)
    end = off + 4 + 2 * chars
    if chars > MAX_CHARS or end > len(data):
        raise ValueError('string length out of range')
    return data[off + 4:end].decode('utf-16-le', 'replace').rstrip('\0'), end


def parse_ndf(data):
    """-> list of item dicts; ValueError / struct.error on an unknown or damaged layout."""
    if len(data) < 32 or data[:4] != b'FQDF':
        raise ValueError('not an ESET FQDF metadata file')
    count, hash_len = struct.unpack_from('<I', data, 8)[0], struct.unpack_from('<I', data, 28)[0]
    if hash_len > 64:
        raise ValueError('hash length out of range')
    off, items = 32 + hash_len, []
    for _ in range(min(count, MAX_ITEMS)):
        path, off = _wstr(data, off)
        off += 4                                                    # attributes
        if data[off:off + 4] != b'NIWI':
            raise ValueError('unexpected item layout')
        # lab (v20): the third time was the same for two files scanned together, later than
        # the first two (equal, the write time) - so created, modified, accessed
        created, modified, accessed = struct.unpack_from('<QQQ', data, off + 4)
        quarantined = struct.unpack_from('<I', data, off + 32)[0]
        detection, off = _wstr(data, off + 40)
        info, off = _wstr(data, off)
        original, off = _wstr(data, off + 16)                       # flags, id, time
        items.append({'original_path': path or original, 'detection': detection,
                      'quarantined': unixtime(quarantined), 'file_created': filetime(created),
                      'file_accessed': filetime(accessed), 'file_modified': filetime(modified),
                      'notes': f'ESET: {info}' if info else ''})
    return items


@decoder('eset')
def decode(ctx, files, options):
    metadata = {f.name[:-4].upper(): f for f in files if f.name.lower().endswith('.ndf')}
    rows = []
    for f in files:
        m = NAME.match(f.name)
        if not m:
            continue
        with guard(rows, f):
            digest = m.group(1)
            user = re.search(r'/Users/([^/]+)/', '/' + f.path, re.IGNORECASE)
            base = {'container': f.path, 'item_type': 'file', 'resource': digest.upper()}
            profile = f'user profile: {user.group(1)}' if user else ''
            items, problem = [{}], ''
            ndf = metadata.get(digest.upper())
            if ndf is not None:
                try:
                    items = parse_ndf(ctx.read(ndf)) or [{}]
                except (ValueError, struct.error, OSError) as e:
                    problem = f'metadata (.NDF) not readable: {e}'
            content = ctx.read(f).translate(TABLE)
            expected = ('sha1' if len(digest) == 40 else 'sha256', digest)
            for item in items:
                row = dict(base, **item)
                row['notes'] = '; '.join(x for x in (row.get('notes', ''), profile, problem) if x)
                rows.append(recovered(ctx, row, content, expected, name=f.name[:-4]))
    return rows
