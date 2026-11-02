"""Windows event logs (.evtx), read with libevtx. Recovered (deleted) records are included.

defender_evtx: Microsoft-Windows-Windows Defender/Operational, the events that matter in
    an investigation (event ids from Microsoft's "Microsoft Defender Antivirus event IDs").
Both take options.match, a glob on the file name.
av_evtx: any log; keeps records whose provider matches options.providers (a regular
    expression, default: every record) and lists their data.
"""

import fnmatch
import re
import xml.etree.ElementTree as ET  # nosec B405 - only for ParseError; parsing goes through defusedxml

import defusedxml.ElementTree as DefusedET

from ..fs import error_text
from . import parser

NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'

DEFENDER_EVENTS = {
    1000: 'scan started', 1001: 'scan finished', 1002: 'scan stopped', 1005: 'scan failed',
    1006: 'malware detected', 1007: 'action taken', 1008: 'action failed',
    1009: 'restored from quarantine', 1010: 'restore from quarantine failed',
    1011: 'deleted from quarantine', 1012: 'delete from quarantine failed',
    1013: 'detection history deleted', 1015: 'suspicious behaviour detected',
    1116: 'malware detected', 1117: 'action taken', 1118: 'action failed', 1119: 'action failed (critical)',
    1120: 'threat hash', 1121: 'ASR rule blocked', 1122: 'ASR rule audited',
    1125: 'network protection audited', 1126: 'network protection blocked',
    1127: 'controlled folder access blocked', 1128: 'controlled folder access audited',
    3002: 'real-time protection failed', 5000: 'real-time protection enabled',
    5001: 'real-time protection disabled', 5004: 'real-time protection configuration changed',
    5007: 'configuration changed', 5008: 'engine failed', 5009: 'antispyware enabled',
    5010: 'antispyware disabled', 5011: 'antivirus enabled', 5012: 'antivirus disabled',
    5013: 'tamper protection blocked a change',
}

# EventData fields shown in their own columns; the rest goes to "details"
COLUMNS = {
    'Threat Name': 'threat', 'Path': 'path', 'Action Name': 'action', 'Process Name': 'process',
    'Detection User': 'user', 'User': 'user',
}
DETAIL_FIELDS = ('Detection Time', 'Severity Name', 'Category Name', 'Source Name', 'Execution Name',
                 'Error Description',
                 'Remediation User', 'Old Value', 'New Value', 'Feature Name', 'Reason', 'Scan Type',
                 'Scan Parameters', 'Scan ID', 'ID', 'Detection ID', 'Threat ID', 'SHA256', 'Hashes',
                 'Timestamp', 'Domain', 'Security intelligence Version')


def _selected(files, options):
    """options.match: glob on the file name, e.g. "*Operational.evtx"."""
    mask = options.get('match', '*').lower()
    return [f for f in files if fnmatch.fnmatch(f.name.lower(), mask)]


def _records(ctx, f):
    """-> (record, recovered, event id, provider). Damaged records (common among the recovered
    ones) whose basic fields cannot be read are skipped and counted."""
    import pyevtx
    with ctx.open(f) as stream:     # streamed from the evidence: logs can be gigabytes
        log = pyevtx.file()
        log.open_file_object(stream)
        damaged = 0
        try:
            sets = ((log.get_record, log.number_of_records, False),
                    (log.get_recovered_record, log.number_of_recovered_records, True))
            for get, count, recovered in sets:
                for i in range(count):
                    try:
                        r = get(i)
                        event_id, source = r.event_identifier, r.source_name or ''
                    except OSError:
                        damaged += 1
                        continue
                    yield r, recovered, event_id, source
        finally:
            log.close()
            if damaged:
                ctx.warn(f'{f.path}: {damaged} unreadable record(s) skipped (usually partial recovered records)')


def _each_record(ctx, files, options):
    """-> (file, record, recovered, event id, provider) over every selected log. A log that
    cannot be read at all (damaged, not EVTX) gives a warning; the other logs are still read."""
    for f in _selected(files, options):
        try:
            for item in _records(ctx, f):
                yield (f, *item)
        except Exception as e:  # noqa: BLE001 - one unreadable log must not hide the others
            ctx.warn(f'{f.path}: event log not readable ({error_text(e)})')


def _record_id(record):
    try:
        return record.identifier
    except OSError:
        return ''


def _event_data(record):
    try:
        root = DefusedET.fromstring(record.xml_string)
    except (ET.ParseError, TypeError, OSError, ValueError):   # defusedxml errors are ValueErrors
        return {}
    data = {}
    for block in (root.find(NS + 'EventData'), root.find(NS + 'UserData')):
        if block is None:
            continue
        for i, d in enumerate(block.iter()):
            if d is block or (d.text or '').strip() == '':
                continue
            name = d.get('Name') or (f'#{i}' if d.tag == NS + 'Data' else d.tag.split('}')[-1])
            data[name if name not in data else f'{name}#{i}'] = d.text.strip()
    return data


def _time(record):
    try:
        t = record.written_time
    except (OSError, ValueError):
        return ''
    return t.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z' if t else ''


def _row(f, record, recovered, event_id, product, event):
    return {'time': _time(record), 'product': product, 'event_id': event_id,
            'event': event, 'evidence': f.path, 'record': _record_id(record),
            'recovered': 'yes' if recovered else ''}


@parser('defender_evtx')
def defender_evtx(ctx, files, options):
    """options.providers: regex the provider must match (needed for shared logs such as
    System.evtx, where SCEP writes as "Microsoft Antimalware"); options.product: label."""
    providers = re.compile(options['providers'], re.IGNORECASE) if options.get('providers') else None
    product = options.get('product', 'Microsoft Defender')
    rows = []
    for f, record, recovered, event_id, source in _each_record(ctx, files, options):
        event = DEFENDER_EVENTS.get(event_id)
        if event is None or (providers and not providers.search(source)):
            continue
        data = _event_data(record)
        row = _row(f, record, recovered, event_id, product, event)
        for name, column in COLUMNS.items():
            if data.get(name):
                row[column] = data[name]
        if row.get('path', '').startswith('file:_'):
            row['path'] = row['path'][6:]
        if event_id == 5007:
            changed = data.get('New Value', '') or data.get('Old Value', '')
            if '\\exclusions\\' in changed.lower():
                row['event'] = 'exclusion ' + ('removed' if not data.get('New Value') else 'added or changed')
        row['details'] = '; '.join(f'{k}: {data[k]}' for k in DETAIL_FIELDS if data.get(k))
        rows.append(row)
    return rows


@parser('av_evtx')
def av_evtx(ctx, files, options):
    providers = re.compile(options.get('providers', '.'), re.IGNORECASE)
    product = options.get('product', '')
    rows = []
    for f, record, recovered, event_id, source in _each_record(ctx, files, options):
        if not providers.search(source):
            continue
        row = _row(f, record, recovered, event_id, product or source, f'{source} event')
        values = _event_data(record)
        if not values:
            try:
                values = {str(i): s for i, s in enumerate(record.strings or []) if s}
            except OSError:
                values = {}
        row['details'] = '; '.join(v if k.isdigit() or k.startswith('#') else f'{k}: {v}'
                                   for k, v in values.items())[:2000]
        rows.append(row)
    return rows
