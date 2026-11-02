"""Avast and AVG quarantine (chest\\index.xml + chest\\<id>, <volume>\\$AV_ASW|$AV_AVG\\$VAULT\\vault.db).

index.xml lists ChestEntry items (ChestId, OrigFolder,
OrigFileName, Virus, TransferTime); chest files are XORed with a fixed 5120 byte key.
Entries with an IDPBlob element are stored in vault.db instead, an SQLite database XORed
with a 16384 byte key.
"""

import sqlite3
import xml.etree.ElementTree as ET  # nosec B405 - only for ParseError; parsing goes through defusedxml

import defusedxml.ElementTree as DefusedET

from . import decoder
from ._avast_keys import CHEST_KEY, VAULT_KEY
from .util import guard, open_sqlite, recovered, unixtime, xor

VAULT_QUERY = ('SELECT data FROM vault INNER JOIN crossRef ON id = crossRef.vaultid '
               'INNER JOIN stream ON crossRef.streamId = stream.streamId WHERE filename = ?')


def _text(entry, tag):
    node = entry.find(tag)
    return (node.text or '').strip() if node is not None else ''


@decoder('avast')
def decode(ctx, files, options):
    indexes = [f for f in files if f.name.lower() == 'index.xml']
    chest = {f.name.lower(): f for f in files
             if '/chest/' in f.path.lower() and f.name.lower() != 'index.xml'}
    vault_file = next((f for f in files if f.name.lower() == 'vault.db'), None)
    vault = None
    if vault_file is not None:
        try:
            vault = open_sqlite(xor(ctx.read(vault_file), VAULT_KEY))
            vault.execute('SELECT 1 FROM vault LIMIT 1')
        except (sqlite3.Error, ValueError, OSError) as e:
            ctx.warn(f'{vault_file.path}: cannot open the vault ({e})')
            vault = None

    rows, used = [], set()
    for index in indexes:
        try:
            root = DefusedET.fromstring(ctx.read(index))
        except (ET.ParseError, ValueError, OSError) as e:    # defusedxml errors are ValueErrors
            ctx.warn(f'{index.path}: {e}')
            continue
        for entry in root.iter('ChestEntry'):
            with guard(rows, index):
                chest_id = _text(entry, 'ChestId')
                parts = (_text(entry, 'OrigFolder').rstrip('\\'), _text(entry, 'OrigFileName'))
                path = '\\'.join(p for p in parts if p)
                time = _text(entry, 'TransferTime')
                row = {'container': index.path, 'resource': chest_id, 'item_type': 'file',
                       'detection': _text(entry, 'Virus'), 'original_path': path,
                       'quarantined': unixtime(int(time)) if time.isdigit() else time}
                if entry.find('IDPBlob') is not None:
                    row['notes'] = 'stored in $VAULT'
                    data = vault.execute(VAULT_QUERY, (path,)).fetchone() if vault is not None else None
                    if not data or not isinstance(data[0], bytes):
                        row['status'] = 'vault entry not found' if vault is not None else 'vault.db missing'
                    else:
                        recovered(ctx, row, data[0])
                elif chest_id.lower() in chest:
                    used.add(chest_id.lower())
                    row['container'] = chest[chest_id.lower()].path
                    recovered(ctx, row, xor(ctx.read(chest[chest_id.lower()]), CHEST_KEY))
                else:
                    row['status'] = 'chest file missing'
                rows.append(row)

    for chest_id, f in sorted(chest.items()):
        if chest_id not in used and f.name.lower() != 'vault.db':
            with guard(rows, f):
                rows.append(recovered(ctx, {'container': f.path, 'resource': f.name, 'item_type': 'file',
                                            'notes': 'not listed in index.xml'},
                                      xor(ctx.read(f), CHEST_KEY), name=f.name))
    if vault is not None:
        vault.close()
    return rows
