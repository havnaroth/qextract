"""Emsisoft Anti-Malware quarantine (Program Files\\Emsisoft Anti-Malware\\Quarantine\\<GUID>.EQF).

A header with u32 fields from offset 16 (lab, version 2026.1: 0x1A at 22, then a table of
offsets at 46, 50, 54, 58, 62; the content starts at the last table offset + 0x1A), the
metadata in plain UTF-16 (original path as "\\\\?\\C:\\...::$DATA", detection, an id, the
engine "A2PE", the signature number), the unix time after the path, zero padding, then the
file encrypted with RC4. The key is the MD5 of a GUID string in clean.dll (CryptoAPI:
CryptCreateHash CALG_MD5, CryptHashData over the UTF-16 string, CryptDeriveKey CALG_RC4,
128 bit). Only one real item was seen so far, so the content offset is also checked against
the zero padding before it; nothing in the file stores a hash of the original.
"""

import hashlib
import re
import struct

from . import decoder
from .util import guard, plain_path, recovered, rc4, unixtime

KEY = hashlib.md5('{A4A1BFF9-301A-40d3-86D3-D1F29E413B28}'.encode('utf-16-le'),
                  usedforsecurity=False).digest()
_TEXT = re.compile(rb'(?:[\x20-\x7e]\x00){3,}')


def _content_offset(data):
    base, last = struct.unpack_from('<H', data, 22)[0], struct.unpack_from('<H', data, 62)[0]
    start = last + base
    if not 64 < start < len(data) or any(data[start - 32:start]):
        raise ValueError('content offset not found')
    return start


@decoder('emsisoft')
def decode(ctx, files, options):
    rows = []
    for f in files:
        if not f.name.lower().endswith('.eqf'):
            continue
        with guard(rows, f):
            data = ctx.read(f)
            row = {'container': f.path, 'item_type': 'file', 'resource': f.name[:-4]}
            if len(data) < 128:
                row['status'] = 'error: too short for an EQF file'
                rows.append(row)
                continue
            start = _content_offset(data)
            texts = [(m.start(), m.group().decode('utf-16-le')) for m in _TEXT.finditer(data, 0, start)]
            if texts:
                at, path = texts[0]
                row['original_path'] = plain_path(path).removesuffix('::$DATA')
                end = at + 2 * len(path)
                (when,) = struct.unpack_from('<I', data, end + 23) if end + 27 <= start else (0,)
                if 946684800 <= when <= 4102444800:          # 2000-2100
                    # lab: 12:49:18 for a scan that ended 12:49:15 local (UTC+1) - a local time
                    row['quarantined'] = unixtime(when).replace('Z', ' (local time)')
            detection = next((t for _, t in texts[1:] if not t.startswith('{') and '\\' not in t), '')
            row['detection'] = detection
            signature = next((t for _, t in texts if t.isdigit()), '')
            row['notes'] = f'signature {signature}' if signature else ''
            rows.append(recovered(ctx, row, rc4(KEY, data[start:])))
    return rows
