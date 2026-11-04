"""SUPERAntiSpyware logs. All times are LOCAL time in a fixed US layout (lab, SUPERAntiSpyware
Free 27.0.1292 on a Polish Windows 11: the layout does not follow the system language).

ProgramData\\SUPERAntiSpyware.com\\SUPERAntiSpyware\\AppLogs\\<NAME>-<M-D-YYYY>( <H-M-S> ).SDB
    the application's debug log, each byte XOR 0xED; lines "MM/DD/YYYY - HH:MM:SS [tid] text"
    (the core service writes no [tid]). Threads interleave, so each is followed on its own:
      "Detected Item", "32 Bit", "Rule : 21792", "<threat>.Process[-N]", "<path>"
      "Scan Started" / "Scan Finished"
      "QAF - ", "<threat>" (a family being quarantined), then per file "Quarantine File: ",
      "<path>", ... "<md5, 32 hex>" ..., a result line ("File Not Found On Drive - Removed
      Correctly" in the lab).
Users\\<user>\\AppData\\Roaming\\SUPERAntiSpyware.com\\SUPERAntiSpyware\\Logs\\
SUPERAntiSpyware Scan Log - <MM-DD-YYYY> - <HH-MM-SS>.log
    plain text: "Generated 11/02/2026 at 11:05 PM", scan type and counters, then each detection
    family with its paths (tab-indented, upper case, 8.3 names).

sas_logs: rows for scans, detections and quarantined files from both.
"""

import datetime
import re

from ..decoders.util import decode_text, xor
from ..fs import error_text
from . import parser

PRODUCT = 'SUPERAntiSpyware'
SDB_KEY = b'\xed'
_LINE = re.compile(r'^(\d\d)/(\d\d)/(\d{4}) - (\d\d):(\d\d):(\d\d)(?: \[([0-9a-fA-F]+)\])? ?(.*)$')
_MD5 = re.compile(r'^[0-9A-Fa-f]{32}$')
_PROCESS = re.compile(r'\.Process(?:-\d+)?$')
_GENERATED = re.compile(r'^Generated (\d\d)/(\d\d)/(\d{4}) at (\d{1,2}):(\d\d) ?([AP]M)?', re.I)
_PAIR = re.compile(r'^([A-Za-z][A-Za-z ]*?)\s*:\s*(.+)$')


def _local(month, day, year, hour, minute, second):
    try:
        t = datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
    except ValueError:
        return ''
    return t.isoformat() + ' (local time)'


def _details(pairs):
    return '; '.join(f'{k}: {v}' for k, v in pairs.items() if v not in (None, ''))


def _app_log(ctx, f, common):
    rows, state = [], {}
    text = decode_text(xor(ctx.read(f), SDB_KEY), ctx.host)
    for number, raw in enumerate(text.split('\n'), 1):
        m = _LINE.match(raw.rstrip('\r'))
        if not m:
            continue
        when = _local(*m.groups()[:6])
        tid, line = m.group(7) or '', m.group(8).strip()
        st = state.setdefault(tid, {})
        mode = st.get('mode')
        base = dict(common, time=when, record=number, process=f'thread {tid}' if tid else '')
        if line in ('Scan Started', 'Scan Finished'):
            rows.append(dict(base, event_id='scan', event=line.lower()))
        elif line == 'Detected Item':
            st.clear()
            st.update(mode='detected', lines=[])
        elif mode == 'detected':
            if line.startswith('Rule :'):
                st['rule'] = line.split(':', 1)[1].strip()
            elif line and line != '32 Bit' and line != '64 Bit':
                st['lines'].append(line)
            if len(st['lines']) == 2:
                threat, path = st['lines']
                rows.append(dict(base, event_id='detected item', event='malware detected',
                                 threat=_PROCESS.sub('', threat), path=path,
                                 details=_details({'rule': st.get('rule'), 'detection': threat})))
                st.clear()
        elif line == 'QAF -':
            st.clear()
            st.update(mode='family')
        elif mode == 'family' and line and 'quarantine' not in line.lower() and line != 'Opened DB':
            st.update(mode='quarantine', family=line)
        elif line == 'Quarantine File:':
            st.update(mode='file', path='', md5='', family=st.get('family', ''))
        elif mode == 'file':
            if not st['path'] and line:
                st['path'] = line
            elif _MD5.match(line):
                st['md5'] = line.lower()
            elif 'removed' in line.lower() or 'failed' in line.lower() or 'error' in line.lower():
                rows.append(dict(base, event_id='quarantine', event='file quarantined and removed',
                                 threat=st.get('family', ''), path=st['path'],
                                 action='quarantined, removed from the disk',
                                 details=_details({'md5': st['md5'], 'result': line})))
                st['mode'] = 'quarantine'
    return rows


def _scan_log(ctx, f, common):
    rows = []
    lines = [x.rstrip('\r') for x in decode_text(ctx.read(f), ctx.host).split('\n')]
    when, info, family, found = '', {}, '', False
    for number, line in enumerate(lines, 1):
        m = _GENERATED.match(line.strip())
        if m:
            month, day, year, hour, minute, ampm = m.groups()
            h = int(hour)
            if ampm:
                h = h % 12 + (12 if ampm.upper() == 'PM' else 0)
            when = _local(month, day, year, h, minute, 0)
            continue
        if line.startswith('=') or 'End of Log' in line:
            family = ''
            continue
        pair = _PAIR.match(line.strip())
        if pair and not line.startswith('\t') and not found:
            info[pair.group(1).strip()] = pair.group(2).strip()
            if pair.group(1).strip().lower() == 'file items detected':
                found = True
            continue
        if not found or not line.strip():
            continue
        if line.startswith(('\t', ' ')):
            rows.append(dict(common, time=when, record=number, event_id='scan log', event='malware detected',
                             threat=family, path=line.strip(),
                             details=_details({'scan type': info.get('Scan type'), 'minute precision': 'yes'})))
        else:
            family = line.strip()
    summary = {k: info.get(k) for k in ('Scan type', 'Total Scan Time', 'Application Version', 'Database Version',
                                         'Memory items detected', 'Registry items detected',
                                         'File items scanned', 'File items detected')}
    if not when and not info:
        return rows                     # not a scan log
    rows.insert(0, dict(common, time=when, record=1, event_id='scan log', event='scan',
                        details=_details(summary)))
    return rows


@parser('sas_logs')
def sas_logs(ctx, files, options):
    rows = []
    for f in files:
        name = f.name.lower()
        common = {'product': PRODUCT, 'evidence': f.path}
        try:
            if name.endswith('.sdb'):
                rows += _app_log(ctx, f, common)
            elif name.endswith('.log') and 'scan log' in name:
                rows += _scan_log(ctx, f, common)
        except Exception as e:  # noqa: BLE001 - one unreadable log must not hide the others
            ctx.warn(f'{f.path}: SUPERAntiSpyware log not readable ({error_text(e)})')
    return rows
