"""The examined Windows installation: computer name, Windows version, time zone and system drive,
read from the SYSTEM and SOFTWARE hives of a volume (libregf). The hives come from the evidence:
any value may be missing, damaged or crafted, so every field is optional and checked.

The time zone rules come from SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\<name>
(REG_TZI_FORMAT, with the per-year "Dynamic DST" entries when present): they turn the local times
some products write (SUPERAntiSpyware, Emsisoft) into UTC.
"""

import calendar
import contextlib
import datetime
import re
import struct

from .fs import error_text

TZ_KEY = r'\Microsoft\Windows NT\CurrentVersion\Time Zones'
_LOCAL = re.compile(r'^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?)(?: \(local time\))?$')


def _open(volume, path):
    import pyregf

    entry = next(iter(volume.glob(path)), None)
    if entry is None:
        return None, None
    stream = volume.open(entry)
    f = pyregf.file()
    f.open_file_object(stream)
    return f, stream


def _value(key, name):
    if key is None:
        return None
    v = key.get_value_by_name(name)
    if v is None:
        return None
    if v.type in (4, 5, 11):             # DWORD, DWORD big endian, QWORD
        return v.get_data_as_integer()
    if v.type in (1, 2):                 # SZ, EXPAND_SZ
        return (v.get_data_as_string() or '').strip()
    return v.data


def _rules(tzi):
    """REG_TZI_FORMAT -> dict, or None when the data is not one."""
    if not isinstance(tzi, bytes) or len(tzi) != 44:
        return None
    bias, std_bias, dst_bias = struct.unpack('<3l', tzi[:12])
    std, dst = struct.unpack('<8H', tzi[12:28]), struct.unpack('<8H', tzi[28:44])
    if not (-1440 < bias < 1440 and -1440 < std_bias < 1440 and -1440 < dst_bias < 1440):
        return None
    return {'bias': bias, 'std_bias': std_bias, 'dst_bias': dst_bias, 'std': std, 'dst': dst}


def read_host(volume, root=''):
    """-> dict with what could be read, {} when the volume holds no Windows hives."""
    prefix = f'{root}/' if root else ''
    host = {}
    system = software = None
    streams = []
    try:
        system, s1 = _open(volume, prefix + 'Windows/System32/config/SYSTEM')
        software, s2 = _open(volume, prefix + 'Windows/System32/config/SOFTWARE')
        streams = [s for s in (s1, s2) if s]
        if system is None and software is None:
            return {}
        tz_name = ''
        if system is not None:
            current = _value(system.get_key_by_path(r'\Select'), 'Current')
            cs = f'ControlSet{current:03d}' if isinstance(current, int) and 0 < current < 1000 else 'ControlSet001'
            name = _value(system.get_key_by_path(fr'\{cs}\Control\ComputerName\ComputerName'), 'ComputerName')
            if name:
                host['computer'] = name
            tzkey = system.get_key_by_path(fr'\{cs}\Control\TimeZoneInformation')
            tz_name = _value(tzkey, 'TimeZoneKeyName') or ''
            if tz_name:
                host['time_zone'] = tz_name
            acp = _value(system.get_key_by_path(fr'\{cs}\Control\Nls\CodePage'), 'ACP')
            if isinstance(acp, str) and acp.isdigit() and len(acp) <= 5:
                host['ansi_codepage'] = f'cp{acp}'    # text logs of older programs (e.g. cp1250)
            active = _value(tzkey, 'ActiveTimeBias')
            if isinstance(active, int):
                host['active_bias_minutes'] = active - (1 << 32) if active >= 1 << 31 else active
        if software is not None:
            cv = software.get_key_by_path(r'\Microsoft\Windows NT\CurrentVersion')
            product, build = _value(cv, 'ProductName') or '', str(_value(cv, 'CurrentBuild') or '')
            if product and build.isdigit() and int(build) >= 22000:
                product = product.replace('Windows 10', 'Windows 11')   # the registry keeps "Windows 10"
            ubr = _value(cv, 'UBR')
            parts = [product, _value(cv, 'DisplayVersion') or '',
                     f'build {build}.{ubr}' if build and isinstance(ubr, int) else (f'build {build}' if build else '')]
            if any(parts):
                host['os'] = ' '.join(p for p in parts if p)
            root_dir = _value(cv, 'SystemRoot') or ''
            if re.match(r'^[A-Za-z]:\\', root_dir):
                host['system_drive'] = root_dir[:2].upper()
            # SID -> profile folder: names the owner SID of a file (quarantine metadata)
            profiles = {}
            plist = software.get_key_by_path(r'\Microsoft\Windows NT\CurrentVersion\ProfileList')
            for i in range(min(plist.number_of_sub_keys, 1000) if plist is not None else 0):
                key = plist.get_sub_key(i)
                folder = _value(key, 'ProfileImagePath')
                if isinstance(folder, str) and re.fullmatch(r'S-1-[0-9-]{1,180}', key.name or ''):
                    profiles[key.name] = folder[:260]
            if profiles:
                host['profiles'] = profiles
            if tz_name:
                zone = software.get_key_by_path(f'{TZ_KEY}\\{tz_name}')
                rules = _rules(_value(zone, 'TZI'))
                if rules:
                    host['tz_rules'] = rules
                    dynamic = zone.get_sub_key_by_name('Dynamic DST') if zone is not None else None
                    years = {}
                    for v in (dynamic.values if dynamic is not None else []):
                        if v.name.isdigit() and v.type == 3:
                            r = _rules(v.data)
                            if r:
                                years[int(v.name)] = r
                    if years:
                        host['tz_rules']['years'] = years
        host.setdefault('system_drive', 'C:')
        return host
    except Exception as e:  # noqa: BLE001 - damaged hives must not stop the run
        host['error'] = f'registry not readable: {error_text(e)}'
        return host
    finally:
        for f in (system, software):
            if f is not None:
                with contextlib.suppress(Exception):     # closing a damaged hive
                    f.close()
        for s in streams:
            s.close()


def _transition(year, st):
    """SYSTEMTIME of a TZI rule (month, weekday, week 1-5 = last, hour) -> local datetime."""
    _y, month, weekday, week, hour, minute = st[:6]
    if not (1 <= month <= 12 and 0 <= weekday <= 6 and 1 <= week <= 5 and hour < 24 and minute < 60):
        return None
    first = datetime.date(year, month, 1)
    # Python: Monday = 0; SYSTEMTIME: Sunday = 0
    day = 1 + (weekday - (first.weekday() + 1) % 7) % 7 + 7 * (week - 1)
    while day > calendar.monthrange(year, month)[1]:
        day -= 7
    return datetime.datetime(year, month, day, hour, minute)


def offset_minutes(host, local):
    """UTC = local + offset; None without usable rules."""
    rules = (host or {}).get('tz_rules')
    if not rules:
        return None
    r = rules.get('years', {}).get(local.year, rules)
    if r['std'][1] == 0 or r['dst'][1] == 0:          # no daylight saving in this zone
        return r['bias'] + r['std_bias']
    dst_start, std_start = _transition(local.year, r['dst']), _transition(local.year, r['std'])
    if dst_start is None or std_start is None:
        return r['bias'] + r['std_bias']
    in_dst = (dst_start <= local < std_start) if dst_start < std_start else not (std_start <= local < dst_start)
    return r['bias'] + (r['dst_bias'] if in_dst else r['std_bias'])


def to_utc(host, value):
    """'2026-11-02T23:05:47 (local time)' -> '2026-11-02T22:05:47Z'; '' when it cannot be done."""
    m = _LOCAL.match(str(value or '').strip())
    if not m:
        return ''
    try:
        local = datetime.datetime.fromisoformat(m.group(1).replace(' ', 'T'))
    except ValueError:
        return ''
    offset = offset_minutes(host, local)
    if offset is None:
        return ''
    try:
        return (local + datetime.timedelta(minutes=offset)).isoformat() + 'Z'
    except OverflowError:
        return ''


def public(host):
    """The host for summary.json / summary.txt: without the raw rules."""
    out = {k: v for k, v in host.items() if k != 'tz_rules'}
    if host.get('tz_rules'):
        r = host['tz_rules']
        std, dst = -(r['bias'] + r['std_bias']) / 60, -(r['bias'] + r['dst_bias']) / 60
        out['utc_offset'] = f'standard {std:+g} h, daylight {dst:+g} h'
    return out
