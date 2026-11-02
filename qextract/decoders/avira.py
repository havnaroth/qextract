"""Avira quarantine, two formats of *.qua.

Avira Antivirus (INFECTED\\): header with metadata, then the file XORed with 0xAA up to the
end of the .qua.

Avira Free Security (Endpoint Protection SDK\\quarantine\\): one JSON line (engine, groupId,
malware, os, path, sha256, type, utc, vdf), a newline, then the file encrypted with
AES-256-CFB128 under a fixed key and IV (constants of the Avira binaries). The JSON sha256 is
of the original file, so it checks the decryption.
"""

import json

from Cryptodome.Cipher import AES

from . import decoder
from .util import cstring, guard, plain_path, recovered, u32, unixtime, xor

MAGIC = b'AntiVir Qua'
MAX_JSON = 64 * 1024
SDK_KEY = b'The great pleasu' * 2
SDK_IV = b'AES Blowfish DES'


def _decode_sdk(ctx, data, row):
    end = data.find(b'\n', 0, MAX_JSON)
    if end < 0:
        row['status'] = 'error: no metadata line in the first 64 KB'
        return
    meta = json.loads(data[:end])
    if not isinstance(meta, dict):
        row['status'] = 'error: metadata is not a JSON object'
        return

    def text(key):
        value = meta.get(key)
        return value if isinstance(value, str) else ''

    utc = meta.get('utc')
    sha256 = text('sha256').lower()
    if len(sha256) != 64 or any(c not in '0123456789abcdef' for c in sha256):
        sha256 = None
    row.update(
        detection=text('malware'),
        original_path=plain_path(text('path')),
        quarantined=unixtime(utc) if isinstance(utc, int) and 0 < utc < 2 ** 32 else '',
        notes='; '.join(f'{k}: {text(k)}' for k in ('groupId', 'engine', 'vdf') if text(k)),
    )
    if end + 1 >= len(data):
        row['status'] = 'error: no content after the metadata'
        return
    content = AES.new(SDK_KEY, AES.MODE_CFB, iv=SDK_IV, segment_size=128).decrypt(data[end + 1:])
    recovered(ctx, row, content, ('sha256', sha256))


@decoder('avira')
def decode(ctx, files, options):
    rows = []
    for f in files:
        if not f.name.lower().endswith('.qua'):
            continue
        with guard(rows, f):
            data = ctx.read(f)
            row = {'container': f.path, 'item_type': 'file'}
            if data.startswith(b'{'):
                _decode_sdk(ctx, data, row)
                rows.append(row)
                continue
            if not data.startswith(MAGIC) or len(data) < 0xDC:
                row['status'] = 'error: not an Avira quarantine file'
                rows.append(row)
                continue
            start, name_len, host_len = u32(data, 0x10), u32(data, 0x14), u32(data, 0x18)
            row.update(
                quarantined=unixtime(u32(data, 0x3C)),
                detection=cstring(data, 0x9C, 0x40),
                original_path=cstring(data, 0xDC, name_len, 'utf-16-le'),
                notes=f'host: {cstring(data, 0xDC + name_len, host_len, "utf-16-le")}' if host_len else '',
            )
            if start > len(data) or start < 0xDC + name_len + host_len:
                row['status'] = f'error: content offset {start:#x} out of range'
            else:
                # the content runs to the end of the file; no hash is stored (plausibility check)
                recovered(ctx, row, xor(data[start:], 0xAA))
            rows.append(row)
    return rows
