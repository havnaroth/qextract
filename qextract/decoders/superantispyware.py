"""SUPERAntiSpyware quarantine (Users\\<user>\\AppData\\Roaming\\SUPERAntiSpyware.com\\
SUPERAntiSpyware\\Quarantine\\quarantine.db, one SQLite database per user).

Lab, SUPERAntiSpyware Free 27.0.1292: QUARANTINES (one row per quarantine action: quarantineid,
createdtime, summary), FILES (original path in patha as written and pathw upper case,
createdtime, dataid -> FILEDATA.id, md5 of the original, parentguidid -> FAMILIES.guidid),
FILEDATA (data = a plain ZIP with one member "data" holding the file, size, md5; files with the
same content share one row), FAMILIES (name = the detection). REGKEYS_V2, REGVALS_V2,
DIRECTORIES and LAYEREDSERVICEPROVIDERS_V2 hold other removed items; they are counted in the
notes. The times are local time (lab: 23:05:47 for a scan run at 23:05 local, UTC+1).
"""

import io
import zipfile

from . import decoder
from .util import guard, open_sqlite, plain_path, recovered

OTHER_ITEMS = ('DIRECTORIES', 'REGKEYS_V2', 'REGVALS_V2', 'LAYEREDSERVICEPROVIDERS_V2')


def _local(value):
    text = str(value or '').strip()
    return text.replace(' ', 'T', 1) + ' (local time)' if text else ''


def _content(blob, size, limit):
    """The file inside one FILEDATA zip, read no further than the stored size (zip bomb)."""
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        members = [i for i in z.infolist() if not i.is_dir()]
        if len(members) != 1:
            raise ValueError(f'expected one member in the stored zip, found {len(members)}')
        want = size if isinstance(size, int) and 0 <= size <= limit else limit
        with z.open(members[0]) as f:
            content = f.read(want + 1)
        if len(content) > want:
            raise ValueError(f'stored file is larger than the {want:,} bytes recorded for it')
        return content


@decoder('superantispyware')
def decode(ctx, files, options):
    rows = []
    limit = getattr(ctx, 'max_bytes', 1024 * 1024 * 1024)
    for f in files:
        if f.name.lower() != 'quarantine.db':
            continue
        with guard(rows, f):
            con = open_sqlite(ctx.read(f))
            families = {g: n for g, n in con.execute('SELECT guidid, name FROM FAMILIES')}
            actions = {q: (t, s) for q, t, s in
                       con.execute('SELECT quarantineid, createdtime, summary FROM QUARANTINES')}
            tables = {name.upper() for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            others = []
            for table in OTHER_ITEMS:     # an older database may not have all of them
                if table in tables:
                    n = con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]  # noqa: S608  # nosec B608 - fixed table names
                    if n:
                        others.append(f'{n} {table.lower()}')
            items = con.execute('SELECT id, guidid, quarantineid, parentguidid, createdtime, patha, pathw, dataid, md5 '
                                'FROM FILES ORDER BY id').fetchall()
            for _id, guid, qid, family, created, patha, pathw, dataid, md5 in items:
                with guard(rows, f):
                    when, summary = actions.get(qid, (created, ''))
                    row = {'container': f.path, 'item_type': 'file', 'resource': str(guid or ''),
                           'original_path': plain_path(str(patha or pathw or '')),
                           'detection': str(families.get(family, '')),
                           'quarantined': _local(when or created),
                           'notes': '; '.join(x for x in (str(summary or ''), f'quarantine {qid}',
                                                          ('also removed: ' + ', '.join(others)) if others else '')
                                              if x)}
                    data = con.execute('SELECT data, size FROM FILEDATA WHERE id = ?', (dataid,)).fetchone()
                    if data is None or data[0] is None:
                        row['status'] = 'not recovered: no stored data for this file'
                        rows.append(row)
                        continue
                    content = _content(bytes(data[0]), data[1], limit)
                    rows.append(recovered(ctx, row, content, ('md5', str(md5 or '').lower())))
    return rows
