"""Microsoft Defender support logs: MPLog-*.log and MPDetection-*.log (Support folder).

Plain text, normally UTF-16 with a byte order mark, one "<time> <message>" line each; the
times are UTC (checked against the quarantine times on a real machine).

defender_mplog: into detections.csv go the detections and the actions taken, the hashes of
    detected files (SDN cloud queries) and files that were slow to scan (evidence that the
    file existed). The per-process scan statistics (ProcessImageName lines: process, pid,
    the file that took longest) are evidence of execution and go to mplog_processes.csv.
Options: match - glob or list of globs on the file name (default MPLog-*.log, MPDetection-*.log).
"""

import codecs
import fnmatch
import io
import re

from ..fs import error_text
from . import parser

PRODUCT = 'Microsoft Defender'
MAX_LINE = 64 * 1024    # longer lines (none in real logs) are cut, never held whole in memory

LINE = re.compile(r'^\ufeff?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z? (.*)$')
DETECTION_EVENT = re.compile(r'^DETECTIONEVENT (\S+) (\S+) (.*)$')
CLEAN_EVENT = re.compile(r'^DETECTION_CLEANEVENT (\S+) (\S+) (\S+) (\S+) (.*)$')
DETECTION = re.compile(r'^DETECTION (\S+) (.*)$')     # MPDetection-*.log
SDN = re.compile(r'^SDN:Issuing SDN query for (.+?) \(.*\) \(sha1=([0-9A-Fa-f]+), sha2=([0-9A-Fa-f]+)\)')
EXPENSIVE = re.compile(r'^ExpensiveFile:Scan time for `(.+?)` is (\d+) units')
PROCESS = re.compile(r'^ProcessImageName: (.*?), Pid: (\d+), TotalTime: (\d+), Count: (\d+), MaxTime: (\d+), '
                     r'MaxTimeFile: (.*?), EstimatedImpact: (\d+)%')


def _selected(files, options):
    masks = options.get('match', ['MPLog-*.log', 'MPDetection-*.log'])
    masks = [masks] if isinstance(masks, str) else masks
    return [f for f in files if any(fnmatch.fnmatch(f.name.lower(), m.lower()) for m in masks)]


def _text(stream):
    """UTF-16 (with or without a byte order mark) or UTF-8, guessed from the first bytes."""
    head = stream.peek(4)[:4]
    if head[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        encoding = 'utf-16'
    elif len(head) >= 4 and head[1] == 0 and head[3] == 0:
        encoding = 'utf-16-le'
    else:
        encoding = 'utf-8-sig'
    return io.TextIOWrapper(stream, encoding=encoding, errors='replace', newline=None)


def _resources(text):
    """'containerfile:C:\\a.zip;file:C:\\a.zip->x/y.py;' -> ['C:\\a.zip', 'C:\\a.zip->x/y.py']"""
    out = []
    for part in text.strip().rstrip(';').split(';'):
        kind, sep, value = part.strip().partition(':')
        # "file:C:\\x" -> C:\\x; a bare path ("C:\\x") has a one-letter "kind"
        out.append(value if sep and len(kind) > 1 else part.strip())
    return [r for r in out if r]


def _detection(row, threat, resources, details):
    paths = _resources(resources)
    row.update(threat=threat, path=paths[0] if paths else '')
    if len(paths) > 1:
        details.append('also: ' + ' | '.join(paths[1:]))
    row['details'] = '; '.join(details)
    return row


def _parse_line(f, number, time, message):
    """-> ('detection', row) | ('process', row) | None"""
    row = {'time': time, 'product': PRODUCT, 'evidence': f.path, 'record': number}
    m = DETECTION_EVENT.match(message)
    if m:
        row.update(event_id='DETECTIONEVENT', event='malware detected')
        return 'detection', _detection(row, m[2], m[3], [f'scan source: {m[1]}'])
    m = CLEAN_EVENT.match(message)
    if m:
        # the result is an HRESULT: 0 = done; anything else failed (e.g. 0x80508023 when the
        # file was gone - seen on a real machine for a file that never reached the quarantine)
        failed = m[3] not in ('0', '0x0', '0x00000000')
        row.update(event_id='DETECTION_CLEANEVENT', event='action failed' if failed else 'action taken',
                   action=m[2])
        return 'detection', _detection(row, m[4], m[5], [f'scan source: {m[1]}', f'result: {m[3]}'])
    m = DETECTION.match(message)
    if m:
        row.update(event_id='DETECTION', event='malware detected')
        return 'detection', _detection(row, m[1], m[2], [])
    m = SDN.match(message)
    if m:
        row.update(event_id='SDN', event='file hash (cloud query)', path=m[1],
                   details=f'sha1: {m[2].lower()}; sha256: {m[3].lower()}')
        return 'detection', row
    m = EXPENSIVE.match(message)
    if m:
        row.update(event_id='ExpensiveFile', event='file scanned (slow scan)', path=m[1],
                   details=f'scan time: {m[2]} units')
        return 'detection', row
    m = PROCESS.match(message)
    if m:
        return 'process', {'time': time, 'process': m[1], 'pid': m[2], 'total_time': m[3], 'count': m[4],
                           'max_time': m[5], 'max_time_file': m[6], 'estimated_impact': f'{m[7]}%',
                           'evidence': f.path, 'record': number}
    return None


def _lines(ctx, f):
    # streamed: MPLog files grow to tens of MB
    with ctx.open(f) as stream, _text(stream) as text:
        number = 0
        while True:
            line = text.readline(MAX_LINE)
            if not line:
                break
            number += 1
            m = LINE.match(line.rstrip('\r\n'))
            if m:
                yield number, m[1] + 'Z', m[2]


@parser('defender_mplog')
def defender_mplog(ctx, files, options):
    rows, processes = [], []
    for f in _selected(files, options):
        try:
            for number, time, message in _lines(ctx, f):
                parsed = _parse_line(f, number, time, message)
                if parsed:
                    (rows if parsed[0] == 'detection' else processes).append(parsed[1])
        except Exception as e:  # noqa: BLE001 - one unreadable log must not hide the others
            ctx.warn(f'{f.path}: log not readable ({error_text(e)})')
    if processes:
        ctx.table('mplog_processes', processes)
    return rows
