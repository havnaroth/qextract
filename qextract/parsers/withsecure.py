"""WithSecure / F-Secure local EDR store (ProgramData\\F-Secure\\ATP\\pstor\\, SQLite).

state.db (also priority.db and eventspool.db, queues with the same schema) has table event:
one JSON document per event, time_created a FILETIME. Detections carry "iname" (lab,
WithSecure Elements 11.0.107: type sp_evt_oas_alert for files, sp_evt_amsi_alert for scripts
blocked in memory - those never reach the quarantine). Fields: time (UTC; loc_time has the
offset sign inverted), act (taken action), aa (allowed actions), obj.ref (the file, or
"amsi"), obj.sha1 / sha256 / size, obj.creator (the process that wrote the file),
oas.accessor (the process that opened it), obj.meta (AMSI: host application, script name),
pkey = processinstance.gpid of the process the event belongs to (command line, user).

The same JSON goes to the event log FSecureUltralightSDK.evtx (provider "F-Secure Ultralight
SDK"): EventData rl = the event type with dots (sp.evt.oas.alert), rv = the JSON (lab: one
record per detection, event 2 file access, 1 AMSI / action taken). It survives when the
store is cleaned, and it is in every triage collection that takes all event logs.

withsecure_edr: the detections of the store into detections.csv.
withsecure_evtx: the detections of the event log into detections.csv (recovered records too).
"""

import contextlib
import json

from ..decoders.util import filetime, open_sqlite
from ..fs import error_text
from . import evtx, parser

PRODUCT = 'WithSecure Elements EPP'
NAMES = ('state.db', 'priority.db', 'eventspool.db')
ACTIONS = {'del': 'delete', 'bl': 'block', 'dis': 'disinfect', 'ren': 'rename', 'quar': 'quarantine'}
EVENTS = {'sp_evt_oas_alert': 'malware detected (file access)', 'sp_evt_amsi_alert': 'malware detected (AMSI)',
          'sp_evt_fixinf_alert': 'action taken'}    # lab: the PUA block quarantined, act "dis"


def _dict(value):
    return value if isinstance(value, dict) else {}


def _processes(con):
    out = {}
    with contextlib.suppress(Exception):   # an older or damaged schema: detections without the process
        for gpid, data in con.execute('SELECT gpid, data FROM processinstance'):
            with contextlib.suppress(ValueError, TypeError):
                out[gpid] = _dict(json.loads(data))
    return out


def _row(f, record, time, event, processes):
    obj, accessor = _dict(event.get('obj')), _dict(_dict(event.get('oas')).get('accessor'))
    meta, creator = _dict(obj.get('meta')), _dict(obj.get('creator'))
    process = processes.get(event.get('pkey'), {})
    path = obj.get('ref', '')
    if path == 'amsi':
        path = meta.get('contentname') or meta.get('path') or ''
    act = str(event.get('act', ''))
    if process.get('cmdl'):
        who = f"{process['cmdl'].strip()} (pid {process.get('pid', '?')})"
    elif accessor.get('path'):
        who = f"{accessor['path']} (pid {accessor.get('pid', '?')})"
    else:
        who = meta.get('path', '')
    details = {'sha256': obj.get('sha256'), 'sha1': obj.get('sha1'), 'size': obj.get('size'),
               'family': event.get('ifmly'), 'allowed actions': event.get('aa'),
               'written by': ' '.join(str(x) for x in (creator.get('path'), creator.get('hash')) if x),
               'AMSI host': meta.get('appname'), 'quarantine id': event.get('qrid')}
    return {'time': str(event.get('time') or '') or time,
            'product': PRODUCT, 'event_id': str(event.get('type', '')),
            'event': EVENTS.get(event.get('type'), 'malware detected'),
            'threat': str(event.get('iname', '')), 'path': str(path),
            'action': ACTIONS.get(act, act), 'user': str(process.get('user', '')), 'process': who,
            'details': '; '.join(f'{k}: {v}' for k, v in details.items() if v not in (None, '')),
            'evidence': f.path, 'record': record}


@parser('withsecure_edr')
def withsecure_edr(ctx, files, options):
    rows, seen = [], set()
    for f in files:
        if f.name.lower() not in NAMES:
            continue
        try:
            con = open_sqlite(ctx.read(f))
            processes = _processes(con)
            # the JSON is matched as text first: only a few of thousands of events are detections
            for record, data, created in con.execute(
                    'SELECT id, data, time_created FROM event WHERE data LIKE \'%"iname"%\''):
                if data in seen:            # the queues repeat events of state.db
                    continue
                seen.add(data)
                with contextlib.suppress(ValueError, TypeError):
                    event = json.loads(data)
                    if isinstance(event, dict) and event.get('iname'):
                        time = filetime(created if isinstance(created, int) else 0)
                        rows.append(_row(f, record, time, event, processes))
        except Exception as e:  # noqa: BLE001 - one unreadable database must not hide the others
            ctx.warn(f'{f.path}: EDR database not readable ({error_text(e)})')
    return rows


@parser('withsecure_evtx')
def withsecure_evtx(ctx, files, options):
    rows = []
    for f, record, recovered, _event_id, source in evtx._each_record(ctx, files, options):
        if 'f-secure' not in source.lower() and 'withsecure' not in source.lower():
            continue
        data = evtx._event_data(record)
        with contextlib.suppress(ValueError, TypeError):
            event = json.loads(data.get('rv', ''))
            if isinstance(event, dict) and event.get('iname'):
                event.setdefault('type', data.get('rl', '').replace('.', '_'))
                row = _row(f, evtx._record_id(record), evtx._time(record), event, {})
                row['recovered'] = 'yes' if recovered else ''
                rows.append(row)
    return rows
