"""RogueKiller / Adlice Protect scan reports (<data folder>\\reports\\AdliceReport_RK-REPORT_
<MMDDYYYY_HHMMSS local>.json; the .json.metas next to it repeats the header only).

Lab, Adlice Protect 16.9.0.0 portable: {header: {date (FILETIME, UTC), properties: [{key,
value}] - type "scan" or "removal", scan_mode, found_count, removed_count, duration (s),
location (the exe), user, ...}, sections: [{id: FILESYSTEM | REGISTRY | PROCESSES | ...,
entries: [...]}]}. Entries nest (a registry rule holds its items); detections carry "vendors".
A scan report keeps the detections the user did not remove; once they are removed it is
rewritten with the header only, and a "removal" report lists them with status [[DELETED]].

roguekiller_report: one row per report (the scan or removal itself) and one per detection.

config.ini (settings) is JSON XORed with a repeating 20-byte key (lab, 16.9); it holds e.g.
virus_total_upload_choice ("always" by default), telemetry and last_scan_date (FILETIME).
roguekiller_config: saves it decoded next to the copies (info/decoded/...), no rows yet.
"""

import json

from ..decoders.util import filetime, xor
from ..fs import error_text
from . import parser

PRODUCT = 'RogueKiller / Adlice Protect'
CONFIG_KEY = b'hFopzDqr8NkJva9zdoak'   # obfuscation, not protection: the same in every copy


def _properties(item):
    out = {}
    for p in item.get('properties', []) if isinstance(item, dict) else []:
        if isinstance(p, dict) and 'key' in p:
            out.setdefault(str(p['key']), p.get('value'))
    return out


def _detections(entries, rule, depth=0):
    for item in entries if isinstance(entries, list) and depth < 20 else []:
        if not isinstance(item, dict):
            continue
        props = _properties(item)
        if props.get('vendors'):
            yield item.get('id', ''), props, rule
        yield from _detections(item.get('entries'), props.get('rule_friendly_name') or rule, depth + 1)


def _status(props):
    return str(props.get('status_str') or '').strip('[]').lower()


@parser('roguekiller_report')
def roguekiller_report(ctx, files, options):
    rows = []
    for f in files:
        if not f.name.lower().endswith('.json'):     # .json.metas: the same header again
            continue
        try:
            report = json.loads(ctx.read(f).decode('utf-8-sig'))
            header = report.get('header', {})
            info = _properties(header)
            time = filetime(header.get('date') if isinstance(header.get('date'), int) else 0)
            kind = str(info.get('type') or 'scan')
            summary = {'mode': info.get('scan_mode'), 'found': info.get('found_count'),
                       'removed': info.get('removed_count'), 'duration (s)': info.get('duration'),
                       'aborted': info.get('aborted'), 'version': info.get('version'),
                       'signatures': info.get('signatures_version')}
            common = {'time': time, 'product': PRODUCT, 'user': str(info.get('user') or ''),
                      'process': str(info.get('location') or ''), 'evidence': f.path}
            rows.append(dict(common, event_id=kind, event=f'{kind} report',
                             details='; '.join(f'{k}: {v}' for k, v in summary.items() if v not in (None, ''))))
            for section in report.get('sections', []) if isinstance(report.get('sections'), list) else []:
                if not isinstance(section, dict):
                    continue
                for item_id, props, rule in _detections(section.get('entries'), ''):
                    vendors = props['vendors']
                    status = _status(props)
                    details = {'section': section.get('id'), 'rule': rule, 'status': status,
                               'sha256': props.get('file_sha256') or props.get('file_hash'),
                               'md5': props.get('file_md5'), 'target': props.get('target'),
                               'VirusTotal': (f"{props.get('file_vtscore')}/{props.get('file_vttotal')}"
                                              if props.get('file_vttotal') else '')}
                    rows.append(dict(common, event_id=f'{kind} {item_id}',
                                     event='removed' if props.get('removed') else 'malware detected',
                                     threat=', '.join(str(v) for v in vendors) if isinstance(vendors, list)
                                     else str(vendors),
                                     path=str(props.get('path') or props.get('value') or ''),
                                     action=status or str(props.get('action') or ''),
                                     details='; '.join(f'{k}: {v}' for k, v in details.items()
                                                       if v not in (None, ''))))
        except Exception as e:  # noqa: BLE001 - one unreadable report must not hide the others
            ctx.warn(f'{f.path}: RogueKiller report not readable ({error_text(e)})')
    return rows


@parser('roguekiller_config')
def roguekiller_config(ctx, files, options):
    for f in files:
        if f.name.lower() != 'config.ini':
            continue
        try:
            data = xor(ctx.read(f), CONFIG_KEY)
            json.loads(data.decode('utf-8'))      # a wrong key (another version) gives no JSON
            ctx.save_decoded(f, data, '.json')
        except Exception as e:  # noqa: BLE001 - the raw copy is in the zip either way
            ctx.warn(f'{f.path}: RogueKiller settings not decoded ({error_text(e)})')
    return []
