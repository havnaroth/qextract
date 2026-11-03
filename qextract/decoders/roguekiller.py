"""RogueKiller / Adlice Protect quarantine (<data folder>\\quarantine\\: <ID>.meta + <ID>.vir).

The data folder is "RogueKiller" next to the exe for the portable version (lab: C:\\lab\\
RogueKiller for C:\\lab\\roguekiller_portable64.exe), ProgramData\\RogueKiller when installed.
Lab, Adlice Protect 16.9.0.0 portable (free): <ID>.meta is JSON {id (16 hex digits), path (the
.vir), origpath, type "file", vendor (the detection), date "YYYY/MM/DD HH:MM:SS" in UTC,
encrypted: true}; <ID>.vir held the file unchanged despite "encrypted" (same SHA256 as the
original). Windows Defender took both .vir files into its own quarantine a second after they
were written: a .meta without its .vir is reported, the file may be in another AV's quarantine.
"""

import json

from . import decoder
from .util import guard, plain_path, recovered


def _utc(value):
    text = str(value or '').strip()
    if len(text) == 19 and text[4] == '/' and text[7] == '/':
        return text.replace('/', '-').replace(' ', 'T') + 'Z'
    return text


@decoder('roguekiller')
def decode(ctx, files, options):
    rows = []
    stored = {f.name.lower(): f for f in files if f.name.lower().endswith('.vir')}
    described = set()
    for f in files:
        if not f.name.lower().endswith('.meta'):
            continue
        with guard(rows, f):
            meta = json.loads(ctx.read(f).decode('utf-8-sig'))
            if not isinstance(meta, dict):
                raise ValueError('the .meta file is not a JSON object')
            item = str(meta.get('id') or f.name[:-5])
            vir = stored.get(f'{item}.vir'.lower()) or stored.get(f.name[:-5].lower() + '.vir')
            row = {'container': f.path, 'item_type': str(meta.get('type') or 'file'), 'resource': item,
                   'original_path': plain_path(str(meta.get('origpath') or '')),
                   'detection': str(meta.get('vendor') or ''), 'quarantined': _utc(meta.get('date')),
                   'notes': f"encrypted flag: {str(meta.get('encrypted')).lower()} "
                            '(lab, 16.9: the file was stored unchanged)'}
            if vir is None:
                row['status'] = (f'not recovered: {item}.vir missing (another AV, e.g. Windows Defender, '
                                 'may have quarantined it: check its quarantine)')
                rows.append(row)
                continue
            described.add(vir.name.lower())
            row['container'] = vir.path
            rows.append(recovered(ctx, row, ctx.read(vir)))
    for name, vir in stored.items():      # a .vir whose .meta is gone
        if name not in described:
            with guard(rows, vir):
                row = {'container': vir.path, 'item_type': 'file', 'resource': vir.name[:-4],
                       'notes': 'no .meta: original path and detection unknown'}
                rows.append(recovered(ctx, row, ctx.read(vir)))
    return rows
