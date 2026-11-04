"""Avast / AVG (one engine, one layout: ProgramData\\Avast Software\\Avast or ProgramData\\AVG\\Antivirus).

Lab, Avast Free and AVG AntiVirus Free 2026 (Polish Windows 11, UTC+1), files ending in:

Log.db (SQLite)          ScanResult: Virus, Time (FILETIME, UTC), PathId -> Path.Name, UserId ->
                         User.Name, SessionId -> ScanSession (TaskGuid: "FileSystemShield" or the
                         GUID of a scan task; Started = unix time, UTC). One row per detection.
report\\<Shield>.txt      text in the system ANSI code page and language, LOCAL time:
                         "1.11.2026 20:04:33<TAB>C:\\...\\eicar.com [L] EICAR Test-NOT virus!!! (0)"
                         then a line with the action ("Plik został przeniesiony do kwarantanny...").
Users\\*\\...\\Cache\\NCcache.dat   JSON list of the notifications shown to the user (Timestamp: unix
                         time as text, "Viewed": did the user open it, Desc names file and threat).

avast_logs: one row per Log.db detection and scan session, per report line, per notification.
Log.db and the reports describe the same detections when both are there; the report is what
is left when Log.db was cleared (and the reverse), so both are kept.
"""

import json
import re
import sqlite3

from ..decoders.util import decode_text, filetime, open_sqlite, unixtime
from ..fs import error_text
from . import parser

PRODUCTS = {'avast': 'Avast Antivirus', 'avg': 'AVG Antivirus'}
SESSION_TYPES = {2: 'shield', 3: 'scan'}          # lab: 3 = the first full scan, 2 = File System Shield
_REPORT_LINE = re.compile(r'^(\d{1,2})\.(\d{1,2})\.(\d{4}) (\d{1,2}):(\d\d):(\d\d)\t(.+?)'
                          r'(?: \[(\w+)\])? (.+?)(?: \((-?\d+)\))?$')
_STRONG = re.compile(r'<strong>(.*?)</strong>', re.S)


def _product(ctx):
    return PRODUCTS.get(ctx.source.get('id', ''), 'Avast Antivirus')


def _details(pairs):
    return '; '.join(f'{k}: {v}' for k, v in pairs.items() if v not in (None, ''))


def _log_db(ctx, f, common):
    rows = []
    con = open_sqlite(ctx.read(f))
    try:
        con.row_factory = sqlite3.Row
        tables = {n.lower() for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        sessions = {}
        if 'scansession' in tables:
            for row in con.execute('SELECT * FROM ScanSession'):
                s = dict(row)
                sessions[s.get('Id')] = s
                kind = SESSION_TYPES.get(s.get('Type'), f"type {s.get('Type')}")
                module = str(s.get('TaskGuid') or '')
                rows.append(dict(common, time=unixtime(s.get('Started') or 0), event_id=f"session {s.get('Id')}",
                                 event='shield session' if kind == 'shield' else 'scan',
                                 process=module,
                                 details=_details({'module': module, 'files tested': s.get('TestedFiles'),
                                                   'infected': s.get('InfectedFiles'),
                                                   'run time (s)': s.get('RunTime'), 'status': s.get('Status'),
                                                   'error': s.get('Error') or '', 'percent': s.get('Percent'),
                                                   'last scanned': s.get('LastScanned')})))
        if 'scanresult' not in tables:
            return rows
        names = {}
        if 'path' in tables:
            names['Path'] = dict(con.execute('SELECT Id, Name FROM Path').fetchall())
        if 'user' in tables:
            names['User'] = dict(con.execute('SELECT Id, Name FROM User').fetchall())
        for row in con.execute('SELECT * FROM ScanResult ORDER BY Id'):
            r = dict(row)
            session = sessions.get(r.get('SessionId'), {})
            module = str(session.get('TaskGuid') or '')
            rows.append(dict(common, time=filetime(r.get('Time') or 0), event_id=f"result {r.get('Id')}",
                             event='malware detected', threat=str(r.get('Virus') or ''),
                             path=str(names.get('Path', {}).get(r.get('PathId'), '') or ''),
                             user=str(names.get('User', {}).get(r.get('UserId'), '') or ''),
                             process=module,
                             details=_details({'module': module, 'alert id': r.get('AlertId'),
                                               'source url': r.get('SourceUrl'), 'chest id': r.get('ChestId') or '',
                                               'error': r.get('Error') or '', 'flags': r.get('Flags'),
                                               'virus flags': r.get('VirusFlags'),
                                               'action flags': r.get('VirusActionFlags')})))
    finally:
        con.close()
    return rows


def _report(ctx, f, common):
    rows = []
    shield = f.name.rsplit('.', 1)[0]
    lines = decode_text(ctx.read(f), ctx.host).splitlines()
    for i, line in enumerate(lines):
        m = _REPORT_LINE.match(line.strip('\r'))
        if not m:
            continue
        day, month, year, hour, minute, second, path, flag, threat, code = m.groups()
        action = ''
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ''
        if nxt and not nxt.startswith('*') and not _REPORT_LINE.match(nxt):
            action = nxt.rstrip('.').strip()
        when = f'{int(year):04d}-{int(month):02d}-{int(day):02d}T{int(hour):02d}:{minute}:{second}'
        rows.append(dict(common, time=when + ' (local time)', event_id=f'{shield} line {i + 1}',
                         event='malware detected', threat=threat.strip(), path=path.strip(), action=action,
                         process=shield, details=_details({'module': shield, 'flag': flag, 'code': code})))
    return rows


def _notifications(ctx, f, common):
    rows = []
    items = json.loads(decode_text(ctx.read(f)))
    for n in items if isinstance(items, list) else []:
        if not isinstance(n, dict):
            continue
        desc = str(n.get('Desc') or '')
        strong = _STRONG.findall(desc)
        try:
            when = unixtime(int(str(n.get('Timestamp') or '0')))
        except ValueError:
            when = ''
        viewed = n.get('Viewed')
        rows.append(dict(common, time=when, event_id=f"notification {n.get('ItemUID', '')}",
                         event='notification shown', threat=strong[1] if len(strong) > 1 else '',
                         path=strong[0] if strong else '',
                         details=_details({'title': n.get('Title'), 'text': _STRONG.sub(r'\1', desc),
                                           'viewed by the user': {True: 'yes', False: 'no'}.get(viewed, viewed)})))
    return rows


@parser('avast_logs')
def avast_logs(ctx, files, options):
    rows = []
    for f in files:
        name = f.name.lower()
        low = f.path.lower().replace('\\', '/')
        common = {'product': _product(ctx), 'evidence': f.path}
        try:
            if name == 'log.db':
                rows += _log_db(ctx, f, common)
            elif name.endswith('.txt') and '/report/' in low:
                rows += _report(ctx, f, common)
            elif name == 'nccache.dat':
                rows += _notifications(ctx, f, common)
        except Exception as e:  # noqa: BLE001 - one unreadable file must not hide the others
            ctx.warn(f'{f.path}: Avast/AVG log not readable ({error_text(e)})')
    return rows
