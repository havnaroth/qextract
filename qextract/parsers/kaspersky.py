"""Kaspersky (home products) report database.

Lab, Kaspersky Standard 21.26 (Polish Windows 11): ProgramData\\Kaspersky Lab\\AVP<ver>\\Data\\
reports.db, SQLite in WAL mode - nearly everything is still in reports.db-wal, which is applied
to the copy (decoders.util.apply_wal). Tables "<Name>Report_raw", one row per event, times are
FILETIME (UTC) in "timestamp", columns with dotted names:

FileAvReport_raw (file threat protection; the same shape in WebAv, MailAv, Amsi, ScanTask,
DetectObjectInfo, ... reports): eventId, user.name, result.name (threat), result.verdict,
result.decisionReason, object.directory + object.name (path), object.md5 / object.sha256 (raw
bytes), application.name / .pid / .directory (the process that touched the file).
Lab: per file 302 (detected), then 308 and 307 in the same second as the file went to the
quarantine (QB\\*.klq) and off the disk. EVENTS holds these lab-inferred names.
<X>ProfileSettingsReport_raw / <X>ProfileReport_raw: eventId 221 (verdict 241) = protection
component started, 222 (verdict 242) = stopped; applicationName = avp.exe.
SystemAuditKpcLogin_raw: sign-in to the My Kaspersky portal (userAgent, loginDatetime).
HipsReport_raw (application trust groups, noise), AggregatedActivity_raw, SystemAuditBase:
not turned into rows.

kaspersky_reports: rows for detections and actions, components started / stopped, portal logins.
"""

from ..decoders.util import filetime, open_sqlite
from ..fs import error_text
from . import parser

PRODUCT = 'Kaspersky'
EVENTS = {302: 'malware detected', 307: 'malware action: deleted', 308: 'malware action: quarantined'}
ACTIONS = {307: 'deleted', 308: 'quarantined'}
PROFILE_EVENTS = {221: 'protection component started', 222: 'protection component stopped'}
SKIP_TABLES = ('hipsreport_raw', 'aggregatedactivity_raw', 'systemauditbasereport_raw')


def _details(pairs):
    return '; '.join(f'{k}: {v}' for k, v in pairs.items() if v not in (None, '', b''))


def _hex(value):
    return value.hex() if isinstance(value, bytes) else str(value or '')


def _join(folder, name):
    folder, name = str(folder or ''), str(name or '')
    return f"{folder.rstrip(chr(92))}\\{name}" if folder and name else folder or name


def _component(table):
    return table[:-4].replace('ProfileSettingsReport', '').replace('ProfileReport', '').replace('Report', '')


def _db(ctx, f, wal, common):
    rows = []
    con = open_sqlite(ctx.read(f), ctx.read(wal) if wal else None)
    try:
        tables = [n for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
                  if n.lower().endswith('_raw') and n.lower() not in SKIP_TABLES]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'    # a name from the evidence's schema, escaped
            cur = con.execute(f'SELECT * FROM {quoted}')  # noqa: S608  # nosec B608 - read-only copy, name escaped
            names = [d[0] for d in cur.description]
            if 'eventId' not in names or 'timestamp' not in names:
                continue
            for values in cur:
                r = dict(zip(names, values, strict=True))
                event_id = r.get('eventId')
                when = filetime(r.get('timestamp') or 0)
                user = str(r.get('user.name') or r.get('systemUsername') or '')
                base = dict(common, time=when, user=user, event_id=f'{table[:-4]} {event_id}')
                if r.get('result.name') and (r.get('object.name') or r.get('object.directory')):
                    path = _join(r.get('object.directory'), r.get('object.name'))
                    app = _join(r.get('application.directory'), r.get('application.name'))
                    rows.append(dict(base, event=EVENTS.get(event_id, f'event {event_id}'),
                                     threat=str(r['result.name']), path=path, action=ACTIONS.get(event_id, ''),
                                     process=app,
                                     details=_details({'component': _component(table), 'md5': _hex(r.get('object.md5')),
                                                       'sha256': _hex(r.get('object.sha256')),
                                                       'pid': r.get('application.pid'),
                                                       'verdict': r.get('result.verdict'),
                                                       'decision reason': r.get('result.decisionReason'),
                                                       'object status': r.get('object.status'),
                                                       'severity': r.get('severity'),
                                                       'threat id': r.get('result.threatId')})))
                elif 'Profile' in table and event_id in PROFILE_EVENTS:
                    rows.append(dict(base, event=PROFILE_EVENTS[event_id],
                                     process=str(r.get('applicationName') or ''),
                                     details=_details({'component': _component(table), 'verdict': r.get('verdict'),
                                                       'error': r.get('error')})))
                elif table.lower() == 'systemauditkpclogin_raw':
                    rows.append(dict(base, event='My Kaspersky portal sign-in',
                                     details=_details({'login time': filetime(r.get('loginDatetime') or 0),
                                                       'user agent': r.get('userAgent'),
                                                       'browser type': r.get('browserType'),
                                                       'device type': r.get('deviceType')})))
    finally:
        con.close()
    return rows


@parser('kaspersky_reports')
def kaspersky_reports(ctx, files, options):
    rows = []
    by_path = {f.path.lower(): f for f in files}
    for f in files:
        if not f.name.lower().endswith('.db'):
            continue
        try:
            rows += _db(ctx, f, by_path.get(f.path.lower() + '-wal'), {'product': PRODUCT, 'evidence': f.path})
        except Exception as e:  # noqa: BLE001 - one unreadable database must not hide the others
            ctx.warn(f'{f.path}: Kaspersky report database not readable ({error_text(e)})')
    return rows
