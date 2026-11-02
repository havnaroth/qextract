"""Symantec Endpoint Protection quarantine (Quarantine\\<meta>.VBN, Quarantine\\<meta>\\<id>.VBN).

The <meta>.VBN files hold metadata only. In the files below <meta>\\ the payload after the header
is XORed with 0x5A; it is a list of typed values, and the raw data streams that follow the
file-size value hold the file, XORed again with 0xFF. Older versions XOR the whole payload
with 0x5A and store the file directly; that layout is used when the payload does not start
with eight zero bytes. The metadata line at 0x184 of <meta>.VBN follows the SEP log format
(Time,Event,Category,Logger,Computer,User,Virus,File,...), which gives the detection name.
"""

import re
import struct

from . import decoder
from .util import cstring, guard, recovered, u32, u64, xor

FIXED = {0x01: 1, 0x03: 4, 0x04: 8, 0x06: 4, 0x0A: 1}
VARIABLE = (0x08, 0x09)
SHA1 = re.compile(r'^[0-9a-fA-F]{40}$')


def _values(data, pos, end):
    while pos < end:
        kind = data[pos]
        pos += 1
        if kind in FIXED:
            size = FIXED[kind]
        elif kind in VARIABLE:
            size = u32(data, pos)
            pos += 4
        else:
            raise ValueError(f'unknown value type {kind:#x} at {pos - 1:#x}')
        yield kind, data[pos:pos + size]
        pos += size


def extract(payload):
    """-> (content, stored SHA1 or None, total size or None)"""
    if payload[:8] != b'\0' * 8:
        return payload, None, None
    start, length = u64(payload, 0x18), u64(payload, 0x20)
    chunks, size, sha1, after_size = [], None, None, False
    for kind, value in _values(payload, start, min(len(payload), start + length)):
        if kind == 0x08 and sha1 is None:
            text = value.decode('utf-16-le', 'replace').rstrip('\0')
            if SHA1.match(text):
                sha1 = text
        elif kind == 0x04:
            size, after_size = struct.unpack('<Q', value)[0], True
        elif kind == 0x09 and after_size:
            chunks.append(value)
    if size is None:
        raise ValueError('no file content found')
    return xor(b''.join(chunks), 0xFF)[:size], sha1, size


@decoder('symantec')
def decode(ctx, files, options):
    vbn = [f for f in files if f.name.lower().endswith('.vbn')]
    # <meta>.VBN sits next to the <meta> folder holding the quarantined file
    meta = {f.path[:-4].lower(): f for f in vbn}
    rows = []
    for f in vbn:
        folder = f.path.rsplit('/', 1)[0].lower()
        if folder not in meta:
            continue
        with guard(rows, f):
            row = {'container': f.path, 'item_type': 'file'}
            data = ctx.read(f)
            offset = u32(data, 0)
            row['original_path'] = cstring(data, 0x04, 0x180)
            header = ctx.read(meta[folder])
            csv_line = cstring(header, 0x184, 0x800)
            # SEP log line: Time,Event,Category,Logger,Computer,User,Virus,File,...
            fields = csv_line.split(',')
            if len(fields) > 7:
                row['detection'] = fields[6]
                row['original_path'] = row['original_path'] or fields[7]
            row['notes'] = f'metadata: {csv_line[:500]}' if csv_line else ''
            content, sha1, size = extract(xor(data[offset:], 0x5A))
            recovered(ctx, row, content, ('sha1', sha1) if sha1 else ('size', size) if size else None)
            rows.append(row)
    return rows
