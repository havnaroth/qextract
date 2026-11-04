"""Command line: qextract -i <image or folder> -o <output folder>"""

import argparse
import collections
import contextlib
import datetime
import hashlib
import json
import os
import re
import sys
import time

from . import __version__, elevate, report, update
from .collect import DEFAULT_MAX_DECODE_BYTES, Collector, SafeWriter, human_size
from .host import public
from .evidence import drive_letter, input_locations, is_live, open_input, volume_read_only
from .output import OutputFolder, UnsafeOutput, is_link, resolved, shown, within
from .sources import BUILTIN_DIR, exe_sources_dir, load_sources

EPILOG = """\
input:  an image: .E01/.Ex01, .L01/.Lx01, .vhd/.vhdx/.avhdx, .vmdk, .dd/.raw/.img, split .000/.001,
        \\\\.\\PhysicalDriveN;
        a drive letter (C: or E:\\ for a mounted image): read as a raw volume when run as
        administrator - locked and protected files included - otherwise file by file
        (in a console qextract offers to restart as administrator, see --no-elevate);
        or any folder (mounted share, KAPE output, copied ProgramData), read file by file;
        or a ZIP triage collection (Velociraptor, KAPE, CyLR), read in place (--zip-password).
        The input is only ever read. The output folder may not be inside a scanned folder,
        an image, or a mounted image / evidence drive (mount images read-only). A live
        system (its Windows drive, or the disk holding it) may take its own results; their
        folder is left out of the scan.

output: one zip, qextract_recovered_<UTC start time>.zip (e.g. ..._20261101_093000.zip),
        AES, password "infected" (always; nothing is written outside it):
        malware\\<product>\\    recovered quarantined files as <sha256>_<name>.infected
                              (+ <name>.metadata.txt for Defender)
        info\\summary.txt          start here: host, products, incidents, recovered files
        info\\incidents.csv        one row per threat on a file, all logs and quarantine joined
        info\\quarantine.csv       decoded quarantine entries (detection, original path, hashes)
        info\\detections.csv       timeline from the AV event logs and the Defender MPLog
        info\\mplog_processes.csv  Defender MPLog per-process lines (evidence of execution)
        info\\collected_files.csv  every copied file with times and SHA256
        info\\files\\<volume>\\...   copies, original folder layout
        info\\decoded\\<volume>\\... readable forms of obfuscated logs / settings
        info\\summary.json, info\\qextract.log

Add products by dropping a JSON definition into a "sources" folder next to the
exe (or pass -s <folder>); see --list-sources and README.md.
"""


# every log message is one line: anything but tab, including line breaks, is replaced
_CONTROL_CHARS = re.compile('[\x00-\x08\x0a-\x1f\x7f\x9b]')
# Windows device names: a folder called CON or NUL cannot be opened in Explorer
_RESERVED_NAME = re.compile(r'^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$', re.IGNORECASE)


def _utcnow():
    return datetime.datetime.now(datetime.UTC)


def _now():
    return _utcnow().isoformat(timespec='seconds').replace('+00:00', 'Z')


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError):   # not a text stream when redirected oddly
            stream.reconfigure(errors='replace')

    p = argparse.ArgumentParser(prog='qextract', epilog=EPILOG,
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                description='Extract antivirus quarantine and logs from a disk image or folder.')
    p.add_argument('-i', '--input', help='disk image or folder to read')
    p.add_argument('-o', '--output', help='folder for the results (created if missing); may be left out for an '
                                          'image or ZIP file: the result is then <name>_qextract_<UTC time>.zip '
                                          'next to it (the image files are not touched)')
    p.add_argument('-s', '--sources', action='append', default=[], metavar='DIR',
                   help='extra folder with source definitions (*.json), may repeat')
    p.add_argument('--only', metavar='ID[,ID...]', help='only these sources (ids from --list-sources)')
    p.add_argument('--list-sources', action='store_true', help='show the known sources and exit')
    p.add_argument('--export-sources', metavar='CSV', help='write every known location to a CSV and exit')
    p.add_argument('--mode', choices=('auto', 'raw', 'files'), default='auto',
                   help='for a drive letter: raw volume (needs admin, gets locked and protected files), '
                        'files, or auto = raw when possible (default)')
    p.add_argument('--include-deleted', action='store_true',
                   help='also collect deleted files still listed in the file system')
    p.add_argument('--max-decode-mb', type=int, default=DEFAULT_MAX_DECODE_BYTES // (1024 * 1024), metavar='MB',
                   help='largest quarantine file to decode in memory (default: %(default)s); '
                        'larger ones are only copied')
    p.add_argument('--event-logs', choices=('ask', 'copy', 'skip'), default='ask',
                   help='copy matched .evtx files into files\\ (they can be gigabytes): ask = ask in the '
                        'console showing their size (default; without a console they are not copied). '
                        'The timeline is built from the evidence either way')
    p.add_argument('--force', action='store_true',
                   help="override the safety checks that are the user's call: an output folder that is not "
                        'empty, and the output on the scanned drive or inside the scanned folder (e.g. -i D: '
                        '-o D:\\cases\\x; that folder is left out of the scan, but writing changes the input - '
                        'not for evidence that must stay untouched). The protection against crafted evidence '
                        '(links, outside parent disks, ...) stays on')
    p.add_argument('--password', metavar='PASSWORD',
                   help='password of the result zip instead of "infected" (the zip is always encrypted; '
                        'the password is not written to the log or the summary)')
    p.add_argument('--zip-password', metavar='PASSWORD',
                   help='password of an encrypted input ZIP (e.g. a Velociraptor collection)')
    p.add_argument('--no-elevate', action='store_true',
                   help='for a drive letter without admin rights: do not offer to restart as administrator')
    p.add_argument('--no-file-history', action='store_true',
                   help='skip the $MFT / $UsnJrnl history of the detected files (the mft folder of the zip: when a file'
                        'was on the disk before its first detection); it reads the whole $MFT, seconds on a '
                        'workstation, a minute on a large server')
    p.add_argument('--no-update-check', action='store_true',
                   help='do not ask GitHub whether a newer qextract exists (the exe asks by default, in the '
                        'background; nothing is downloaded). Use it where any network traffic matters')
    p.add_argument('--elevated', action='store_true', help=argparse.SUPPRESS)  # set by the restart
    p.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = p.parse_args(argv)
    if args.max_decode_mb < 1:
        p.error('--max-decode-mb must be at least 1')
    if args.password is not None and (not args.password.strip() or _CONTROL_CHARS.search(args.password)):
        p.error('--password must not be empty or contain control characters')

    admin = elevate.is_admin()
    sources, errors = load_sources(args.sources, exe_dir=not admin)
    skipped = exe_sources_dir() if admin else None
    if skipped and os.path.isdir(skipped) and os.path.abspath(skipped) not in map(os.path.abspath, args.sources):
        errors.append(f'{skipped} is not read as administrator (anyone who can write there could make an '
                      f'administrator copy any file); pass it with -s if you trust it')
    for e in errors:
        print(f'WARNING: {e}', file=sys.stderr)

    if args.export_sources:
        columns = ['source_id', 'product', 'artifact', 'kind', 'path', 'decoder', 'parser']
        with open(args.export_sources, 'w', newline='', encoding='utf-8-sig') as f:
            writer = SafeWriter(f, columns)
            writer.writeheader()
            rows = 0
            for s in sorted(sources.values(), key=lambda s: s['name'].lower()):
                for a in s['artifacts']:
                    for path in a['paths']:
                        writer.writerow({'source_id': s['id'], 'product': s['name'], 'artifact': a['name'],
                                         'kind': a['kind'], 'path': path, 'decoder': a.get('decoder', ''),
                                         'parser': a.get('parser', '')})
                        rows += 1
        print(f'{rows} locations of {len(sources)} sources written to {os.path.abspath(args.export_sources)}')
        return 0

    if args.list_sources:
        for s in sorted(sources.values(), key=lambda s: s['name'].lower()):
            kinds = sorted({a['kind'] for a in s['artifacts']})
            decoders = sorted({a['decoder'] for a in s['artifacts'] if a.get('decoder')})
            extra = f'  decoder: {", ".join(decoders)}' if decoders else ''
            print(f'{s["id"]:<22} {s["name"]:<34} {", ".join(kinds)}{extra}')
        print(f'\n{len(sources)} sources')
        return 0

    if not args.input:
        p.error('-i/--input is required')
    if not args.input.startswith('\\\\.\\') and not os.path.exists(args.input):
        p.error(f'input not found: {args.input}')
    # an image or ZIP file without -o: the result goes next to it, the image files untouched
    next_to_input = not args.output
    if next_to_input and (drive_letter(args.input) or args.input.startswith('\\\\.\\')
                          or not os.path.isfile(args.input)):
        p.error('-o/--output is required unless the input is an image or ZIP file')

    selected = list(sources.values())
    if args.only:
        wanted = {x.strip().lower() for x in args.only.split(',') if x.strip()}
        unknown = wanted - {s['id'].lower() for s in selected}
        if unknown:
            p.error(f'unknown source id(s): {", ".join(sorted(unknown))}')
        selected = [s for s in selected if s['id'].lower() in wanted]
    selected.sort(key=lambda s: s['name'].lower())

    out = os.path.dirname(os.path.abspath(args.input)) if next_to_input else os.path.abspath(args.output)
    run_started = _utcnow()     # one time for the zip name, the log and summary.json
    zip_name = _zip_next_to(args.input, run_started) if next_to_input else None
    if next_to_input and not os.access(out, os.W_OK):
        p.error(f'cannot write next to the image ({out}, read-only media?): give an output folder with -o')
    if any(_RESERVED_NAME.match(part.rstrip(' .')) for part in os.path.splitdrive(out)[1].split(os.sep)):
        p.error(f'the output path uses a Windows device name (CON, NUL, COM1, ...): {args.output}')
    if os.path.lexists(out) and (is_link(os.lstat(out)) or not os.path.isdir(out)):
        p.error(f'output must be a plain folder, not a file or a link (symlink or junction): {out}')
    raw_input = drive_letter(args.input) or args.input.startswith('\\\\.\\')
    shown_input = args.input if raw_input else os.path.abspath(args.input)
    # the input is only ever read: no output inside a scanned folder, image, mounted image or
    # evidence disk. A live system (its Windows drive) may take its own results: that folder
    # is left out of the scan.
    live = is_live(args.input)
    locations = input_locations(args.input)
    on_input = next((root for root in locations if within(resolved(out), root)), None)
    target = os.path.normcase(resolved(out)).rstrip('\\/')
    if (live or args.force) and any(target == os.path.normcase(root).rstrip('\\/') for root in locations):
        p.error(f'the output cannot be the input itself ({shown(on_input)}): give a folder inside it')
    protected = [] if live or args.force else locations
    inside = next((root for root in protected if within(resolved(out), root)), None)
    if inside:
        p.error(f'output must not be inside the input ({shown(inside)}): the input is only ever read. '
                'Choose an output folder on another drive or outside the input folder, or use --force '
                'to write onto the input on purpose')
    if not next_to_input and os.path.isdir(out) and os.listdir(out) and not args.force:
        p.error(f'output folder is not empty: {out} (use --force)')
    if _offer_elevation(args, out):
        return 0
    # only the exe: tests and runs from source never touch the network
    update_check = update.Check() if getattr(sys, 'frozen', False) and not args.no_update_check else None
    try:
        os.makedirs(out, exist_ok=True)
        OutputFolder(out, protected)     # checks again: the folder may have been swapped meanwhile
    except UnsafeOutput as e:
        p.error(str(e))
    except OSError as e:                 # no rights, invalid name, disk not ready, ...
        p.error(f'cannot create the output folder {out}: {e.strerror or e}')
    log_lines = []          # the log goes into the zip (info/qextract.log) at the end

    def log(message):
        # names from the evidence may carry line breaks or terminal escape sequences
        message = _CONTROL_CHARS.sub('?', message)
        print(message)
        log_lines.append(message)

    started_at, t0 = run_started, time.monotonic()
    started = started_at.isoformat(timespec='seconds').replace('+00:00', 'Z')
    log(f'qextract {__version__} - {started}')
    log(f'Input:  {shown_input}')
    log(f'Output: {out}')
    log(f'Sources: {len(selected)}')
    for e in errors:
        log(f'WARNING: {e}')
    for s in selected:
        if os.path.dirname(os.path.abspath(s['file'])) != BUILTIN_DIR:
            log(f'Extra source definition: {s["file"]} (sha256 {_sha256(s["file"])})')
    if admin:
        warning = _exe_location_warning()
        if warning:
            log(f'WARNING: {warning}')
    letter = drive_letter(args.input)
    if on_input and args.force and not live:
        log(f'WARNING: --force: the results are written onto the input ({shown(on_input)}); their folder is '
            'left out of the scan, but the input is changed by the writing')
    if live:
        log('Live system: the results may go to the scanned drive; their folder is left out of the scan')
    elif letter:
        read_only = volume_read_only(letter)
        if read_only:
            log(f'Drive {letter}: is mounted read-only')
        elif read_only is False:
            log(f'WARNING: drive {letter}: is writable. If it is a mounted image, mount it read-only '
                '(qextract only reads it; other programs might not)')

    summary = {'tool': f'qextract {__version__}', 'input': shown_input, 'mode': args.mode,
               'output': out, 'started': started, 'sources_loaded': len(selected), 'errors': list(errors),
               'zip_password': 'custom (--password)' if args.password else 'infected', 'live_system': live,
               'output_on_input': bool(on_input)}
    code = 0

    def decide_event_logs(count, size):
        text = f'{count} file(s) ({human_size(size)})'
        if args.event_logs == 'ask':
            if sys.stdin is None or not sys.stdin.isatty():
                log(f'Event logs: {text} - not copied, there is no console to ask (--event-logs copy to copy them)')
                summary['event_logs'] = 'not copied'
                return False
            try:
                answer = input(f'Copy event logs too? {text} [y/N]: ')
            except EOFError:
                answer = ''
            copy = answer.strip().lower() in ('y', 'yes', 't', 'tak')
        else:
            copy = args.event_logs == 'copy'
        summary['event_logs'] = 'copied' if copy else 'not copied'
        log(f'Event logs: {text} - {summary["event_logs"]}; the timeline reads them from the evidence either way')
        return copy

    try:
        collector = Collector(out, log, max_decode_bytes=args.max_decode_mb * 1024 * 1024, started=started_at,
                              password=args.password, protected=protected, zip_name=zip_name,
                              file_history=not args.no_file_history)
    except UnsafeOutput as e:
        p.error(str(e))
    except OSError as e:
        p.error(f'cannot write to the output folder {out}: {e.strerror or e}')
    summary['zip'] = collector.zip_name
    try:
        volumes = open_input(args.input, args.include_deleted, log, args.mode, args.zip_password)
        for v in volumes:
            v.skip_local(out)
        summary['volumes'] = [{'name': v.name, 'description': v.description} for v in volumes]
        summary['found'] = collector.run(volumes, selected, copy_event_logs=decide_event_logs)
    except UnsafeOutput as e:
        log(f'ERROR: UnsafeOutput: {e}')     # nothing more is written: the zip may be redirected
        print(f'Stopped. {out} was tampered with; the results were not finished.')
        return _finish(args, 1)
    except KeyboardInterrupt:
        log('ERROR: interrupted - the zip holds what was collected so far')
        summary['errors'].append('interrupted')
        code = 130
    except Exception as e:  # noqa: BLE001 - any failure is reported and the summary still written
        log(f'ERROR: {type(e).__name__}: {e}')
        summary['errors'].append(str(e))
        code = 1
    summary['warnings'] = collector.warnings
    summary['finished'] = _now()
    summary['schema_version'] = report.SCHEMA_VERSION
    summary['hosts'] = {vol: public(h) for vol, h in collector.hosts.items()}
    summary['incidents'] = len(collector.incidents)
    summary['timeline'] = dict(collections.Counter(r.get('category', 'other') for r in collector.detections))
    summary['file_history'] = collector.history if collector.file_history else 'off'
    summary['seconds_per_source'] = {sid: {k: round(v, 2) for k, v in t.items()}
                                     for sid, t in sorted(collector.timings.items())}

    found = summary.get('found', {})
    log('')
    if found:
        log('Found:')
        for _sid, s in sorted(found.items()):
            q = (f', {s["quarantine_items"]} quarantine item(s), {s["recovered"]} recovered'
                 if s['quarantine_items'] else '')
            log(f'  {s["name"]}: {s["files"]} file(s), {s["bytes"]:,} bytes{q}')
    elif code == 0:
        log('Nothing found.')
    log(f'Done in {time.monotonic() - t0:.1f} s, {len(collector.warnings)} warning(s).')
    shown_password = 'the one given with --password' if args.password else '"infected"'
    log(f'Results: {os.path.join(out, collector.zip_name)} (password {shown_password}: info\\ = reports and '
        f'copied files, malware\\ = recovered files)')
    summary['update_check'] = 'off'
    if update_check:
        notice, summary['update_check'] = update_check.result()
        if notice:
            log('')
            log(notice)

    try:
        try:
            try:
                text = report.summary_text(summary, collector.detections, collector.quarantine,
                                           collector.incidents, collector.hosts)
            except Exception as e:  # noqa: BLE001 - summary.json and the CSVs are still written
                text = f'summary.txt could not be written: {type(e).__name__}: {e}\n'
            collector.add_info('summary.txt', text)
            collector.add_info('summary.json', json.dumps(summary, indent=2, ensure_ascii=False))
            collector.add_info('qextract.log', '\n'.join(log_lines) + '\n')
        finally:
            collector.close()
    except OSError as e:     # e.g. the output disk is full: say so instead of a traceback
        print(f'ERROR: the zip could not be finished ({e.strerror or e}); its content is incomplete.')
        code = 1
    return _finish(args, code)


def _zip_next_to(path, when):
    """<image name>_qextract_<UTC time>.zip, a name not yet taken in the image's folder."""
    folder, stem = os.path.split(os.path.abspath(path))
    stem = os.path.splitext(stem)[0] or 'image'
    name = f'{stem}_qextract_{when:%Y%m%d_%H%M%S}'
    candidate, n = f'{name}.zip', 1
    while os.path.lexists(os.path.join(folder, candidate)):
        n += 1
        candidate = f'{name}_{n}.zip'
    return candidate


def _finish(args, code):
    if args.elevated:   # the administrator window would otherwise close with the results
        with contextlib.suppress(EOFError):
            input('Press Enter to close this window.')
    return code


def _sha256(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError as e:
        return f'unreadable: {e}'


def _exe_location_warning():
    """As administrator the exe should live where only administrators can write: in a user
    folder other programs of that user could plant a DLL next to it or replace it."""
    if not getattr(sys, 'frozen', False):
        return ''
    exe = os.path.normcase(os.path.abspath(sys.executable))
    for var in ('USERPROFILE', 'TEMP', 'TMP', 'PUBLIC'):
        folder = os.environ.get(var)
        if folder and exe.startswith(os.path.normcase(os.path.abspath(folder)) + os.sep):
            return (f'running as administrator from a folder ordinary programs can write to ({os.path.dirname(exe)}); '
                    'copy qextract.exe to a folder only administrators can write, e.g. C:\\Program Files\\qextract')
    return ''


def _offer_elevation(args, out):
    """A live drive without admin rights is read file by file, which misses locked and
    protected files (the Defender quarantine among them). Ask whether to restart as
    administrator. -> True when the elevated copy took over."""
    live = drive_letter(args.input) or args.input.startswith('\\\\.\\')
    if (not live or args.mode == 'files' or args.no_elevate or args.elevated or elevate.is_admin()
            or not elevate.can_relaunch() or sys.stdin is None or not sys.stdin.isatty()):
        return False
    try:
        answer = input('Not running as administrator: locked and protected files (e.g. the Defender '
                       'quarantine) cannot be read. Restart as administrator? [Y/n]: ')
    except EOFError:
        answer = 'n'
    if answer.strip().lower() not in ('', 'y', 'yes', 't', 'tak'):
        return False

    argv = ['-i', args.input, '-o', out, '--mode', args.mode, '--max-decode-mb', str(args.max_decode_mb),
            '--event-logs', args.event_logs, '--elevated']
    for folder in args.sources:
        argv += ['-s', os.path.abspath(folder)]
    if args.only:
        argv += ['--only', args.only]
    if args.password:
        argv += ['--password', args.password]
    argv += [flag for flag, on in (('--include-deleted', args.include_deleted), ('--force', args.force),
                                   ('--no-update-check', args.no_update_check),
                                   ('--no-file-history', getattr(args, 'no_file_history', False))) if on]
    if elevate.relaunch(argv):
        print('Continuing in the administrator window.')
        return True
    print('Not restarted (UAC cancelled or not available) - continuing without administrator rights.')
    return False
