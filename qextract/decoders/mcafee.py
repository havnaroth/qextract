"""McAfee / Trellix quarantine.

*.zip (ENS and current products): a ZIP with the password
    "infected" holding an XML description (creationTime, detectionName,
    Files/File/originalPath, Files/File/size) and the quarantined file.
*.bup (VirusScan Enterprise, C:\\Quarantine): an OLE compound file whose streams are XORed
    with 0x6A; "Details" is INI text with the detection, "File_0", "File_1", ... are the
    files. Not checked against a real sample.
"""

import io
import re
import zipfile

import defusedxml.ElementTree as DefusedET

from . import decoder
from .util import guard, recovered, xor

MAX_MEMBERS = 64        # far more than a quarantine zip holds (the file and its XML)
UUID = re.compile(rb'[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}')


def _zip(ctx, f):
    row = {'container': f.path, 'item_type': 'file'}
    with zipfile.ZipFile(io.BytesIO(ctx.read(f))) as z:
        z.setpassword(b'infected')
        meta, content = None, None
        members = z.infolist()
        if len(members) > MAX_MEMBERS:      # a quarantine zip holds the file and its XML
            raise ValueError(f'{len(members)} entries in the archive, not a quarantine item')
        budget = ctx.max_bytes              # for all entries together, not each
        for info in members:
            if meta is not None and content is not None:
                break
            # the sizes in the archive are attacker controlled: refuse zip bombs up front,
            # and stop reading at the limit in case the header lies
            if info.file_size > budget:
                raise ValueError(f'{info.filename}: {info.file_size} bytes unpacked, above the decode limit')
            with z.open(info) as member:
                data = member.read(budget + 1)
            if len(data) > budget:
                raise ValueError(f'{info.filename}: unpacks to more than the decode limit')
            budget -= len(data)
            if meta is None and UUID.search(data[:4096]) and data.lstrip().startswith(b'<'):
                meta = DefusedET.fromstring(data)
            elif content is None:
                content = data
    size = None
    if meta is not None:
        def text(path):
            node = meta.find(path)
            return (node.text or '').strip() if node is not None else ''
        row.update(quarantined=text('creationTime'), detection=text('detectionName'),
                   original_path=text('Files/File/originalPath'))
        size = text('Files/File/size') or None
    if content is None:
        row['status'] = 'metadata only'
        return row
    return recovered(ctx, row, content, ('size', size) if size and size.isdigit() else None)


def _ini(text):
    current = {}
    sections = {'': current}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('[') and line.endswith(']'):
            current = sections.setdefault(line[1:-1].lower(), {})
        elif '=' in line:
            key, value = line.split('=', 1)
            current[key.strip().lower()] = value.strip()
    return sections


def _bup(ctx, f):
    import olefile
    rows = []
    with olefile.OleFileIO(ctx.read(f)) as ole:
        streams = ['/'.join(s) for s in ole.listdir()]
        details = _ini(xor(ole.openstream('Details').read(), 0x6A).decode('utf-8', 'replace')) \
            if 'Details' in streams else {}
        info = details.get('details', {})
        when = ''
        if info.get('creationyear'):
            parts = [info.get(k, '0') for k in ('creationyear', 'creationmonth', 'creationday',
                                                 'creationhours', 'creationminutes', 'creationseconds')]
            if all(p.isdigit() for p in parts):
                when = '{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d} (local time)'.format(*map(int, parts))
        for name in sorted(s for s in streams if s.lower().startswith('file_')):
            meta = details.get(name.lower(), {})
            row = {'container': f.path, 'resource': name, 'item_type': 'file',
                   'detection': info.get('detectionname', ''), 'quarantined': when,
                   'original_path': meta.get('originalname', '')}
            rows.append(recovered(ctx, row, xor(ole.openstream(name).read(), 0x6A), name=name))
    return rows or [{'container': f.path, 'status': 'no File_ streams'}]


@decoder('mcafee')
def decode(ctx, files, options):
    rows = []
    for f in files:
        name = f.name.lower()
        with guard(rows, f):
            if name.endswith('.zip'):
                rows.append(_zip(ctx, f))
            elif name.endswith('.bup'):
                rows += _bup(ctx, f)
    return rows
