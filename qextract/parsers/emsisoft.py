"""Emsisoft Anti-Malware logs.

Lab, Emsisoft Anti-Malware Home 2026.1 (no license: on-demand scans only; Polish Windows 11):

Program Files\\Emsisoft Anti-Malware\\Logs\\logs.db3 (SQLite, times = unix seconds, UTC; text UTF-8)
    ForensicsLog   the event journal: Date, ComponentID, UserName, ActionID, AdditionalInfo,
                   ScanLogID / InfectionLogID; the readable text (in the UI language) is in
                   ForensicsDesc via ForensicsRefs.GroupID. ActionIDs seen in the lab: see ACTIONS.
    ScanLogs       one row per scan: ScanDate, CountObj, FoundObj, Duration, FileName (the report).
    ILogs          one row per detection: Name (threat), Location (path), Date, SHA1, Action,
                   RiskLevel, LogID -> ScanLogs.
    QObjects       quarantine items: Name, Location, Quarantined / Restored / Removed (unix
                   time), SHA1. Lab: only the item quarantined from the scan window is here; the
                   10 files quarantined at the end of a later scan are only in its report.
    SystemLogs, IDSLogs (behavior blocker)  empty in the lab: read by their column names.
ProgramData\\Emsisoft\\Reports\\scan_<YYMMDD-HHMMSS>.txt  (UTF-16, system language, LOCAL time)
    header, "<label>:<TAB>2.11.2026 12:48:47" (start, later end), detections
    "<path> <TAB><label>: <threat> [<engine>]" and after the scan the actions
    "<path><TAB><action text> <threat>". Labels and actions are in the UI language, so lines
    are recognised by their shape (a path, a tab) and the action text is what precedes the
    threat already named for that path.
ProgramData\\Emsisoft\\EDR\\edr.db3  SuspectedFiles (FilePath, DetectionTime REAL, InfectionName):
    empty in the lab; the time format is unknown, so it is kept raw in details.

emsisoft_logs: rows for scans, detections, quarantine, settings changes and program events.
"""

import datetime
import re

from ..decoders.util import decode_text, open_sqlite
from ..fs import error_text
from . import parser

PRODUCT = 'Emsisoft'                     # the source name, as on the quarantine rows
ACTIONS = {   # ForensicsLog.ActionID -> event (lab 2026.1; text from ForensicsDesc goes to details)
    113: 'configuration changed', 115: 'configuration changed', 121: 'configuration changed',
    135: 'program started', 137: 'system shutdown',
    49: 'real-time protection failed to start (license)',
}
SKIP = {35, 36, 40, 41, 55, 57, 59, 67}   # scans, detections, quarantine: from their own tables
_DATE = re.compile(r'(\d{1,2})[./](\d{1,2})[./](\d{4})\s+(\d{1,2}):(\d\d):(\d\d)(?:\s*([AP]M))?', re.I)
_PATH = re.compile(r'^(?:[A-Za-z]:\\|\\\\)')
_ACCOUNT = re.compile(r'^[^\\\s:]+\\[^\\:]+$')          # HOST\user


def _wall(value):
    """logs.db3 keeps the LOCAL wall-clock time as unix seconds (lab: a scan started 13:27:45
    local, UTC+1, is stored as 13:27:45 "UTC"); the report converts it with the host's zone."""
    try:
        t = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(value))
    except (TypeError, ValueError, OverflowError):
        return ''
    return t.isoformat() + ' (local time)' if value else ''


def _details(pairs):
    return '; '.join(f'{k}: {v}' for k, v in pairs.items() if v not in (None, ''))


def _tables(con):
    return {n.lower() for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _rows(con, sql):
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r, strict=True)) for r in cur]


def _logs_db(ctx, f, common):
    rows = []
    con = open_sqlite(ctx.read(f))
    try:
        tables = _tables(con)
        forensics = []
        if {'forensicslog', 'forensicsrefs', 'forensicsdesc'} <= tables:
            forensics = _rows(con, 'SELECT l.*, (SELECT d.Description FROM ForensicsRefs r JOIN ForensicsDesc d '
                                   'ON d.GroupID = r.GroupID WHERE r.ForensicsID = l.ID LIMIT 1) AS Text '
                                   'FROM ForensicsLog l ORDER BY l.ID')
        elif 'forensicslog' in tables:
            forensics = _rows(con, 'SELECT * FROM ForensicsLog ORDER BY ID')
        by_scan = {}
        for e in forensics:
            if e.get('ScanLogID') is not None:
                by_scan.setdefault(e['ScanLogID'], []).append(e)
            action = e.get('ActionID')
            if action in SKIP:
                continue
            text = e.get('Text') or e.get('Description') or ''
            rows.append(dict(common, time=_wall(e.get('Date') or 0), event_id=f'forensics {action}',
                             event=ACTIONS.get(action, f'event {action}'), user=str(e.get('UserName') or ''),
                             details=_details({'text': text, 'value': e.get('AdditionalInfo'),
                                               'component': e.get('ComponentID')})))
        if 'scanlogs' in tables:
            for s in _rows(con, 'SELECT * FROM ScanLogs ORDER BY ID'):
                events = by_scan.get(s.get('ID'), [])
                user = next((e.get('UserName') for e in events if e.get('UserName')), '')
                target = next((e.get('AdditionalInfo') for e in events if e.get('ActionID') == 59), '')
                result = next((e.get('Text') for e in events if e.get('ActionID') == 55 and e.get('Text')), '')
                rows.append(dict(common, time=_wall(s.get('ScanDate') or 0), event_id=f"scan {s.get('ID')}",
                                 event='scan', user=str(user or ''),
                                 details=_details({'target': target, 'objects scanned': s.get('CountObj'),
                                                   'found': s.get('FoundObj'), 'duration': s.get('Duration'),
                                                   'result': result, 'report': s.get('FileName'),
                                                   'method': s.get('Method'), 'scan type': s.get('ScanType')})))
        if 'ilogs' in tables:
            for d in _rows(con, 'SELECT * FROM ILogs ORDER BY ID'):
                rows.append(dict(common, time=_wall(d.get('Date') or 0), event_id=f"infection {d.get('ID')}",
                                 event='malware detected', threat=str(d.get('Name') or ''),
                                 path=str(d.get('Location') or ''),
                                 details=_details({'sha1': d.get('SHA1'), 'scan': d.get('LogID'),
                                                   'risk level': d.get('RiskLevel'), 'action code': d.get('Action'),
                                                   'infection type': d.get('InfectionType')})))
        if 'qobjects' in tables:
            for q in _rows(con, 'SELECT * FROM QObjects ORDER BY ID'):
                for column, action in (('Quarantined', 'quarantined'), ('Restored', 'restored'),
                                       ('Removed', 'deleted from quarantine')):
                    if q.get(column):
                        rows.append(dict(common, time=_wall(q[column]), event_id=f"quarantine {q.get('ID')}",
                                         event=f'malware action: {action}', action=action,
                                         threat=str(q.get('Name') or ''), path=str(q.get('Location') or ''),
                                         details=_details({'size': q.get('FileSize'), 'status': q.get('Status'),
                                                           'id': q.get('Unic')})))
        if 'systemlogs' in tables:
            for s in _rows(con, 'SELECT * FROM SystemLogs ORDER BY ID'):
                rows.append(dict(common, time=_wall(s.get('Date') or 0), event_id=f"system {s.get('ID')}",
                                 event=str(s.get('Event') or 'system event'), threat=str(s.get('InfectionName') or ''),
                                 path=str(s.get('Location') or ''), user=str(s.get('UserName') or ''),
                                 details=_details({'details': s.get('Details'), 'action code': s.get('Action'),
                                                   'risk level': s.get('RiskLevel')})))
        if 'idslogs' in tables:
            for s in _rows(con, 'SELECT * FROM IDSLogs ORDER BY ID'):
                rows.append(dict(common, time=_wall(s.get('Date') or 0), event_id=f"ids {s.get('ID')}",
                                 event='behavior blocker event', path=str(s.get('FileName') or ''),
                                 details=_details({'event code': s.get('Event'), 'pid': s.get('PID'),
                                                   'info': s.get('Info'), 'infection': s.get('Infection')})))
        if 'suspectedfiles' in tables:
            for s in _rows(con, 'SELECT * FROM SuspectedFiles ORDER BY id'):
                rows.append(dict(common, event_id=f"edr {s.get('id')}", event='suspicious file (EDR)',
                                 threat=str(s.get('InfectionName') or ''), path=str(s.get('FilePath') or ''),
                                 details=_details({'detection time (raw)': s.get('DetectionTime')})))
    finally:
        con.close()
    return rows


def _local(m):
    day, month, year, hour, minute, second, ampm = m.groups()
    sep = m.group(0)[len(day)]
    if sep == '/':
        if not ampm:
            return ''                      # d/m or m/d: not guessed
        day, month = month, day
    h = int(hour)
    if ampm:
        h = h % 12 + (12 if ampm.upper() == 'PM' else 0)
    try:
        return datetime.datetime(int(year), int(month), int(day), h, int(minute), int(second)).isoformat() \
            + ' (local time)'
    except ValueError:
        return ''


def _report(ctx, f, common):
    rows, threats, times, user = [], {}, [], ''
    lines = [x.rstrip('\r') for x in decode_text(ctx.read(f), ctx.host).split('\n')]
    for number, line in enumerate(lines, 1):
        if '\t' not in line:
            value = line.split(':', 1)[1].strip() if ':' in line else ''
            if not user and _ACCOUNT.match(value):
                user = value                                  # "<user label>: HOST\user"
            continue
        left, right = line.split('\t', 1)
        left, right = left.strip(), right.strip()
        if not _PATH.match(left):
            m = _DATE.search(right)
            if m:
                times.append(_local(m))
            continue
        when = times[-1] if times else ''
        if ': ' in right and right.endswith(']') and ' [' in right:      # detection line
            threat = right.split(': ', 1)[1].rsplit(' [', 1)[0].strip()
            threats[left.lower()] = threat
            rows.append(dict(common, time=when, record=number, event_id='report', event='malware detected',
                             threat=threat, path=left, user=user,
                             details=_details({'engine': right.rsplit(' [', 1)[1].rstrip(']')})))
            continue
        threat = threats.get(left.lower(), '')
        action = right[:-len(threat)].strip() if threat and right.endswith(threat) else right
        rows.append(dict(common, time=when, record=number, event_id='report', event='malware action',
                         threat=threat, path=left, action=action, user=user))
    # the actions are written after the scan: they get its end time, the last date before them
    return rows


@parser('emsisoft_logs')
def emsisoft_logs(ctx, files, options):
    rows = []
    for f in files:
        name = f.name.lower()
        common = {'product': PRODUCT, 'evidence': f.path}
        try:
            if name.endswith('.db3'):
                rows += _logs_db(ctx, f, common)
            elif name.endswith('.txt'):
                rows += _report(ctx, f, common)
        except Exception as e:  # noqa: BLE001 - one unreadable log must not hide the others
            ctx.warn(f'{f.path}: Emsisoft log not readable ({error_text(e)})')
    return rows
