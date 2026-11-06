"""One report layer for every product: the rows the decoders and parsers return are normalized
here, so a new product gets it without code of its own.

- detections.csv gets category, log, action_norm, path_norm / path_type, the common details as
  columns (sha256, md5, threat_family, severity), details_json and its incident;
- quarantine.csv gets quarantined_utc (local times converted with the host's time zone),
  recovery, verified_by, warning, path_norm and its incident;
- incidents.csv: one row per threat on one file (or AMSI buffer, registry key), joining the
  events of every log and the quarantine items with their recovered files;
- summary.txt: the run for a human reader.

The existing columns keep their content and order; the new ones are appended (SCHEMA_VERSION).
Everything here reads values from the evidence: nothing is trusted to have a shape.
"""

import collections
import datetime
import json
import re

from . import host as hostinfo

SCHEMA_VERSION = 2
DETECTION_EXTRA = ['category', 'log', 'action_norm', 'path_norm', 'path_type', 'sha256', 'md5',
                   'threat_family', 'severity', 'incident', 'details_json', 'sha1']
QUARANTINE_EXTRA = ['quarantined_utc', 'recovery', 'verified_by', 'warning', 'path_norm', 'incident', 'log_hash']
INCIDENT_COLUMNS = ['incident', 'first_seen', 'last_seen', 'path', 'path_type', 'threats', 'products',
                    'actions', 'events', 'logs', 'quarantined', 'recovered_files', 'sha256', 'users',
                    'processes', 'volume', 'on_disk_since', 'on_disk_evidence', 'dwell',
                    'origin', 'origin_evidence', 'journey', 'user_context', 'profile', 'file_owner',
                    'action_times']
INCIDENT_GAP = datetime.timedelta(days=1)    # the same file detected again after a day: a new incident
ZONES = {'0': 'local computer', '1': 'intranet', '2': 'trusted sites', '3': 'internet', '4': 'restricted sites'}


_UNSAFE_TEXT = re.compile('[\x00-\x08\x0a-\x1f\x7f\x9b]')      # as cli._CONTROL_CHARS
_URL_QUERY = re.compile(r'(https?://[^\s?;#]+)[?#][^\s;]*', re.IGNORECASE)


def _short_urls(text):
    """For summary.txt: a signed download link carries hundreds of characters of token after
    '?'; the host and path are what a reader needs (the full URL stays in incidents.csv)."""
    return _URL_QUERY.sub(lambda m: m.group(1) + '?...', str(text or ''))


def origin_text(zone_id='', host_url='', referrer_url=''):
    """Zone.Identifier ("Mark of the Web") as one readable value: where the file was downloaded
    from, the page that linked to it, the zone. '' when there is nothing."""
    zone_id, host_url, referrer_url = (str(x or '').strip() for x in (zone_id, host_url, referrer_url))
    if not (zone_id or host_url or referrer_url):
        return ''
    parts = [host_url or '(no download URL recorded)']
    if referrer_url and referrer_url != host_url:
        parts.append(f'from page {referrer_url}')
    if zone_id:
        parts.append(f'zone {zone_id} ({ZONES[zone_id]})' if zone_id in ZONES else f'zone {zone_id}')
    return '; '.join(parts)

CATEGORIES = ('detection', 'response', 'tamper', 'config', 'scan', 'health', 'telemetry', 'other')
# Defender "Action ID" (language independent, unlike "Action Name")
DEFENDER_ACTIONS = {'1': 'cleaned', '2': 'quarantined', '3': 'deleted', '6': 'allowed', '8': 'user defined',
                    '9': 'none', '10': 'blocked'}
_ACTION_WORDS = (     # (substring of the lower-case action, normalized action); first match wins
    ('quarant', 'quarantined'), ('kwarant', 'quarantined'), ('restor', 'restored'), ('przywr', 'restored'),
    ('remove_subkey', 'deleted'), ('delet', 'deleted'), ('remov', 'deleted'), ('usuń', 'deleted'),
    ('usun', 'deleted'), ('block', 'blocked'), ('zablok', 'blocked'), ('disinfect', 'cleaned'),
    ('clean', 'cleaned'), ('wyczy', 'cleaned'), ('allow', 'allowed'), ('zezw', 'allowed'),
    ('fail', 'failed'), ('found', 'detected'), ('detect', 'detected'), ('nie dotyczy', 'none'),
    ('not applicable', 'none'), ('no action', 'none'), ('brak', 'none'))
_SINGLE = {'del': 'deleted', 'bl': 'blocked', 'dis': 'cleaned', 'ren': 'renamed', 'quar': 'quarantined',
           'n/a': 'none', 'none': 'none'}
_DETAIL_SPLIT = re.compile(r'; (?=[A-Za-z][A-Za-z0-9 ()/_.-]{0,40}: )')
_DEVICE = re.compile(r'^\\Device\\HarddiskVolume(\d+)(\\.*)$', re.IGNORECASE)
_MULTI = re.compile(r';\s*(?=(?:file:_|amsi:_|process:_|regkey|[A-Za-z]:\\|\\Device\\|%))')
_DEFENDER_NAME = re.compile(r'^[A-Za-z]+:[A-Za-z0-9]+/([A-Za-z0-9_-]+)')


def duration(start, end):
    """'3 d 4 h', '17 h 5 min', '42 s' between two ISO UTC times; '' when end is not later."""
    a, b = _time(start), _time(end)
    if a is None or b is None or b <= a:
        return ''
    s = int((b - a).total_seconds())
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    if d:
        return f'{d} d {h} h'
    if h:
        return f'{h} h {m} min'
    return f'{m} min' if m else f'{s} s'


def _time(value):
    """An ISO UTC time ('...Z') -> datetime, else None."""
    text = str(value or '')
    if not text.endswith('Z'):
        return None
    try:
        return datetime.datetime.fromisoformat(text[:-1])
    except ValueError:
        return None


def details_dict(text):
    """'key: value; key: value' (the details column) -> dict; parts without a key are kept
    under "#1", "#2"..."""
    out, n = {}, 0
    for part in _DETAIL_SPLIT.split(str(text or '')):
        key, sep, value = part.partition(': ')
        if sep and key and len(key) <= 41:
            out.setdefault(key, value)
        elif part:
            n += 1
            out[f'#{n}'] = part
    return out


def category(row):
    event = str(row.get('event', '')).lower()
    product = str(row.get('product', '')).lower()
    if 'securitycenter' in product.replace(' ', ''):
        return 'health'
    if 'disabled' in event or 'tamper' in event or 'history deleted' in event:
        return 'tamper'
    if 'engine failed' in event or 'protection failed' in event or 'protection component stopped' in event:
        return 'health'
    if 'configuration' in event or 'exclusion' in event or 'enabled' in event:
        return 'config'
    if 'cloud query' in event or 'file hash' in event or 'slow scan' in event or 'threat hash' in event:
        return 'telemetry'
    if any(w in event for w in ('detected', 'asr rule', 'controlled folder', 'network protection', 'suspicious')):
        return 'detection'
    if any(w in event for w in ('action', 'removed', 'restored', 'deleted from quarantine', 'removal')):
        return 'response'
    if 'scan' in event:
        return 'scan'
    return 'other'


def log_type(evidence):
    p = str(evidence or '').lower().replace('\\', '/')
    name = p.rsplit('/', 1)[-1]
    if name.endswith('.evtx'):
        return 'evtx'
    if 'detectionhistory' in p:
        return 'detectionhistory'
    if name.startswith(('mplog', 'mpdetection')) or 'mplog' in name:
        return 'mplog'
    if '/pstor/' in p or name.endswith(('.db', '.sqlite')):
        return 'database'
    if name.startswith('adlicereport'):
        return 'report'
    return 'log'


def action_norm(row, details):
    aid = str(details.get('Action ID', '')).strip()
    if aid in DEFENDER_ACTIONS:
        return DEFENDER_ACTIONS[aid]
    raw = str(row.get('action', '')).strip().lower()
    event = str(row.get('event', '')).lower()
    if raw in _SINGLE:
        return _SINGLE[raw]
    for word, norm in _ACTION_WORDS:
        if word in raw:
            return norm
    if raw:
        return 'other'
    if 'restored' in event:
        return 'restored'
    if 'failed' in event:
        return 'failed'
    if event == 'removed':
        return 'deleted'
    return 'detected' if category(row) == 'detection' else ''


class PathMapper:
    """\\Device\\HarddiskVolumeN -> drive letter, learned from the evidence itself: products and
    logs often name one file both ways (MPLog vs. the event log); left as it is when unknown."""

    def __init__(self, paths, system_drive='C:'):
        votes = collections.defaultdict(collections.Counter)
        tails = collections.defaultdict(set)
        stripped = [_strip(p) for p in paths]
        for p in stripped:
            m = _DEVICE.match(p)
            if m:
                tails[m.group(2).lower()].add(m.group(1))
        for p in stripped:
            if re.match(r'^[A-Za-z]:\\', p) and p[2:].lower() in tails:
                for n in tails[p[2:].lower()]:
                    votes[n][p[:2].upper()] += 1
        self.letters = {n: c.most_common(1)[0][0] for n, c in votes.items()}
        self.system_drive = system_drive

    def letter(self, n, tail):
        if n in self.letters:
            return self.letters[n]
        # the Windows folders only exist on the system drive
        if re.match(r'^\\(windows|users|programdata|program files)', tail, re.IGNORECASE) and len(self.letters) == 0:
            return self.system_drive
        return None


def _strip(path):
    p = str(path or '').strip()
    for prefix in ('file:_', 'process:_', '\\\\?\\', '\\??\\'):
        if p.lower().startswith(prefix):
            p = p[len(prefix):]
    return p


def normalize_path(path, mapper, system_drive='C:'):
    """-> (normalized path, path type). Several paths (Defender lists them) are each normalized."""
    raw = str(path or '').strip()
    if not raw:
        return '', ''
    parts = [x.strip().rstrip(';').strip() for x in _MULTI.split(raw) if x.strip()]
    out, kinds = [], []
    for part in parts:
        amsi = part.lower().startswith('amsi:')
        p = _strip(part[5:].lstrip('_') if amsi else part)     # amsi:_<the scanning process>
        if amsi:
            m = _DEVICE.match(p)
            letter = mapper.letter(m.group(1), m.group(2)) if m and mapper is not None else None
            out.append(letter + m.group(2) if letter else p)
            kinds.append('amsi')
            continue
        if p.upper().startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR', 'HKU\\', 'REGKEY')):
            out.append(p)
            kinds.append('registry')
            continue
        if p.lower().startswith('%systemdrive%'):
            p = system_drive + p[len('%systemdrive%'):]
        elif p.lower().startswith('%systemroot%'):
            p = system_drive + '\\Windows' + p[len('%systemroot%'):]
        m = _DEVICE.match(p)
        if m and mapper is not None:
            letter = mapper.letter(m.group(1), m.group(2))
            if letter:
                p = letter + m.group(2)
        out.append(p)
        kinds.append('file' if re.match(r'^[A-Za-z]:\\|^\\Device\\|^\\\\', p) else 'other')
    kind = kinds[0] if len(set(kinds)) == 1 else 'mixed'
    return '; '.join(out), kind


def normalize_detection(row, mapper, system_drive):
    details = details_dict(row.get('details'))
    row['category'] = category(row)
    row['log'] = log_type(row.get('evidence'))
    row['action_norm'] = action_norm(row, details)
    row['path_norm'], row['path_type'] = normalize_path(row.get('path'), mapper, system_drive)
    low = {k.lower(): v for k, v in details.items()}
    if 'amsi' in str(low.get('scan source', '')).lower() and row['path_type'] == 'file':
        row['path_type'] = 'amsi'      # MPLog names the scanning process without the amsi: prefix
    sha256, md5, sha1 = (str(low.get(k, '')) for k in ('sha256', 'md5', 'sha1'))
    row['sha256'] = sha256.lower() if re.fullmatch(r'[0-9a-fA-F]{64}', sha256) else ''
    row['md5'] = md5.lower() if re.fullmatch(r'[0-9a-fA-F]{32}', md5) else ''
    row['sha1'] = sha1.lower() if re.fullmatch(r'[0-9a-fA-F]{40}', sha1) else ''
    family = low.get('family', '')
    if not family:
        m = _DEFENDER_NAME.match(str(row.get('threat', '')))
        family = m.group(1) if m else ''
    row['threat_family'] = family
    row['severity'] = low.get('severity name', '') or low.get('severity', '')
    row['details_json'] = json.dumps(details, ensure_ascii=False) if details else ''
    return row


def normalize_quarantine(row, hosts, mapper):
    host = hosts.get(row.get('volume'), {})
    when = str(row.get('quarantined', '') or '')
    row['quarantined_utc'] = when if when.endswith('Z') else hostinfo.to_utc(host, when)
    status = str(row.get('status', '')).lower()
    if status.startswith('recovered'):
        row['recovery'] = 'recovered'
    elif status.startswith('error'):
        row['recovery'] = 'error'
    else:
        row['recovery'] = 'not recovered'
    if row['recovery'] == 'recovered' and not row.get('verified_by'):
        row['verified_by'] = ('none' if 'not verified' in status
                              else 'size' if 'size matches' in status else 'stored hash')
    row['path_norm'], _kind = normalize_path(row.get('original_path'), mapper, host.get('system_drive', 'C:'))
    return row


def _kind(path):
    if path.lower().startswith('amsi:'):
        return 'amsi'
    if path.upper().startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR', 'HKU\\', 'REGKEY')):
        return 'registry'
    return 'file' if re.match(r'^[A-Za-z]:\\|^\\Device\\|^\\\\', path) else 'other'


def _key(path, path_type, threat):
    if path_type == 'file' and path:
        return ('file', path.lower())
    return (path_type or 'other', path.lower(), threat.lower())


LINK_SECONDS = 2     # an event without a usable path joins a detection of the same threat this close
_PATH_RANK = {'file': 0, 'amsi': 1, 'registry': 2, 'other': 3}


def _items(detections, quarantine):
    """-> [(time, path, path type, threat, row, 'event' | 'quarantine')]"""
    items = []
    for r in detections:
        if r.get('category') not in ('detection', 'response') or not (r.get('path_norm') or r.get('threat')):
            continue
        t = _time(r.get('time'))
        if t is None:
            continue
        for path in (r.get('path_norm') or '').split('; '):
            kind = 'amsi' if r.get('path_type') == 'amsi' else (_kind(path) if path else 'other')
            items.append((t, path, kind, str(r.get('threat', '')).lower(), r, 'event'))
    for r in quarantine:
        t = _time(r.get('quarantined_utc'))
        path = r.get('path_norm', '')
        if t is not None and (path or r.get('detection')):
            items.append((t, path, _kind(path) if path else 'other', str(r.get('detection', '')).lower(), r,
                          'quarantine'))
    return items


def _components(items):
    """Joins items that are one incident: the same file (or AMSI process / key + threat) within
    INCIDENT_GAP, the same Defender detection ID (1116 and its 1117 / 1119), and events without
    a usable path to a detection of the same threat within LINK_SECONDS."""
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        parent[find(a)] = find(b)

    by_key = collections.defaultdict(list)
    by_detection = collections.defaultdict(list)
    by_threat = collections.defaultdict(list)
    for i, (_t, path, kind, threat, row, _src) in enumerate(items):
        if path and kind != 'other':
            by_key[_key(path, kind, threat)].append(i)
        did = details_dict(row.get('details')).get('Detection ID', '') if 'details' in row else ''
        if did:
            by_detection[did].append(i)
        if threat:
            by_threat[threat].append(i)
    # one Defender detection can name several files: it joins the same path across its events
    # (1116 / 1117 / 1119), and its events without a path to the first of its files
    for members in by_detection.values():
        with_path = [i for i in members if items[i][1] and items[i][2] != 'other']
        anchor = min(with_path, key=lambda i: (items[i][0], items[i][1])) if with_path else members[0]
        for i in members:
            if not (items[i][1] and items[i][2] != 'other'):
                union(i, anchor)
    for members in by_key.values():
        members.sort(key=lambda i: items[i][0])
        for a, b in zip(members, members[1:], strict=False):
            if items[b][0] - items[a][0] <= INCIDENT_GAP:
                union(a, b)
    window = datetime.timedelta(seconds=LINK_SECONDS)
    for members in by_threat.values():
        members.sort(key=lambda i: items[i][0])
        for n, i in enumerate(members):
            if items[i][1] and items[i][2] != 'other':
                continue
            near = [j for j in members[max(0, n - 3):n + 4] if j != i and abs(items[j][0] - items[i][0]) <= window]
            if near:
                union(i, min(near, key=lambda j: (_PATH_RANK.get(items[j][2], 9), abs(items[j][0] - items[i][0]))))
    groups = collections.defaultdict(list)
    for i in range(len(items)):
        groups[find(i)].append(items[i])
    return sorted((sorted(g, key=lambda m: m[0]) for g in groups.values()), key=lambda g: g[0][0])


WELL_KNOWN_SIDS = {'S-1-5-18': 'SYSTEM', 'S-1-5-19': 'LOCAL SERVICE', 'S-1-5-20': 'NETWORK SERVICE'}
WELL_KNOWN_GROUPS = {'S-1-5-32-544': 'Administrators (group)', 'S-1-5-32-545': 'Users (group)',
                     'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users',
                     'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464': 'TrustedInstaller'}
_PROFILE = re.compile(r'^[A-Za-z]:\\Users\\([^\\]+)\\', re.IGNORECASE)
_SHARED_PROFILES = {'public', 'default', 'default user', 'all users'}


# the built-in service accounts as Windows names them in its language (lab: Polish
# "ZARZĄDZANIE NT\USŁUGA LOKALNA" in Defender events): not a person
SERVICE_ACCOUNTS = {
    'LOCAL SERVICE': 'LOCAL SERVICE', 'NETWORK SERVICE': 'NETWORK SERVICE',
    'USŁUGA LOKALNA': 'LOCAL SERVICE', 'USŁUGA SIECIOWA': 'NETWORK SERVICE',
    'LOKALER DIENST': 'LOCAL SERVICE', 'NETZWERKDIENST': 'NETWORK SERVICE',
    'SERVICE LOCAL': 'LOCAL SERVICE', 'SERVICE RÉSEAU': 'NETWORK SERVICE',
    'SERVICIO LOCAL': 'LOCAL SERVICE', 'SERVICIO DE RED': 'NETWORK SERVICE',
    'SERVIZIO LOCALE': 'LOCAL SERVICE', 'SERVIZIO DI RETE': 'NETWORK SERVICE',
}


def account(name):
    """An account as the logs write it -> one spelling: the local system account has a name
    in the system language ('NT AUTHORITY\\SYSTEM', 'ZARZĄDZANIE NT\\SYSTEM', 'SYSTEM', S-1-5-18)."""
    name = str(name or '').strip()
    if name.upper() in ('SYSTEM', 'S-1-5-18') or name.upper().endswith('\\SYSTEM'):
        return 'SYSTEM'
    service = SERVICE_ACCOUNTS.get(name.rsplit('\\', 1)[-1].upper())
    if service:
        return service
    return WELL_KNOWN_SIDS.get(name.upper(), name)


def profile_of(path):
    """C:\\Users\\<name>\\... -> <name> (not the shared profiles), else ''."""
    m = _PROFILE.match(str(path or ''))
    return m.group(1) if m and m.group(1).lower() not in _SHARED_PROFILES else ''


def owner_name(sid, profiles):
    """A file owner SID -> the profile folder's name (ProfileList in the registry), else the SID."""
    sid = str(sid or '').strip()
    if not sid:
        return ''
    if sid.upper() in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid.upper()]
    if sid.upper() in WELL_KNOWN_GROUPS:
        return f'{WELL_KNOWN_GROUPS[sid.upper()]} ({sid})'
    folder = (profiles or {}).get(sid, '')
    return f"{folder.rstrip(chr(92)).rsplit(chr(92), 1)[-1]} ({sid})" if folder else sid


def _user_context(events, quar, path, profiles):
    """-> (user, profile, file owner): the account the detection happened for (a person before
    SYSTEM - SYSTEM there is mostly the AV service or a scan), the profile the file was in, and
    the owner of the quarantined file."""
    users = list(dict.fromkeys(account(r.get('user')) for r in events if r.get('user')))
    people = [u for u in users if u not in WELL_KNOWN_SIDS.values()]
    if people:
        user = '; '.join(people)
    elif users:
        user = f'{users[0]} (a service or a scan, not a person)'
    else:
        user = ''
    owners = list(dict.fromkeys(owner_name(r.get('owner_sid'), profiles) for r in quar if r.get('owner_sid')))
    return user, profile_of(path), '; '.join(owners)


def _action_times(events, quar):
    """Each action with the time it was first seen, per product: 'allowed' and 'quarantined'
    minutes apart are two lines, not one 'allowed; quarantined'. -> [(ISO time, action, product)]"""
    first = {}
    for r in events:
        action = r.get('action_norm')
        if action and action not in ('none',):
            key = (action, r.get('product', ''))
            t = str(r.get('time') or '')
            if t and (key not in first or t < first[key]):
                first[key] = t
    for r in quar:
        key = ('quarantined', r.get('product') or r.get('source', ''))
        t = str(r.get('quarantined_utc') or '')
        if t and key not in first:
            first[key] = t
    real = {k: v for k, v in first.items() if k[0] != 'detected'}
    chosen = real or first
    return sorted(((t, a, p) for (a, p), t in chosen.items()), key=lambda x: (x[0], x[1]))


def _actions(values):
    acts = {a for a in values if a}
    real = acts - {'none', 'detected'}
    return sorted(real) if real else sorted(acts & {'detected'})


_WEAK = ('', 'none', 'size')          # verified_by values a log hash can improve on


def verify_with_logs(events, quar):
    """A recovered file whose quarantine stored no usable hash, checked against the hash a log
    of the same incident (the same file) recorded: Kaspersky / SAS MD5, Emsisoft SHA1, ...
    A match sets verified_by '<algorithm> (<product> log)'; a difference is only a warning (a
    log may describe another version of the file) and never replaces a stored-hash check."""
    logged = {}
    for r in events:
        for algo in ('sha256', 'sha1', 'md5'):
            if r.get(algo):
                logged.setdefault((algo, r[algo]), r.get('product') or r.get('source') or 'a')
    if not logged:
        return
    for q in quar:
        if not q.get('saved_as'):
            continue
        matched = next(((algo, logged[(algo, str(q.get(algo, '')).lower())]) for algo in ('sha256', 'sha1', 'md5')
                        if (algo, str(q.get(algo, '')).lower()) in logged), None)
        if matched:
            q['log_hash'] = f'{matched[0]} matches the {matched[1]} log'
            if str(q.get('verified_by', '')) in _WEAK:
                q['verified_by'] = f'{matched[0]} ({matched[1]} log)'
                if str(q.get('status', '')).startswith('recovered ('):
                    q['status'] = f"recovered ({matched[0].upper()} matches the {matched[1]} log)"
            continue
        algos = {a for a, _v in logged} & {a for a in ('sha256', 'sha1', 'md5') if q.get(a)}
        if algos:
            q['log_hash'] = f"{'/'.join(sorted(algos))} differs from the log's"
            q['warning'] = '; '.join(x for x in (q.get('warning'), q['log_hash']) if x)


def build_incidents(detections, quarantine, profiles=None):
    """Assigns row['incident'] and returns the incident rows (sorted by first time)."""
    rows = []
    for n, members in enumerate(_components(_items(detections, quarantine)), 1):
        iid = f'I{n:04d}'
        events = list({id(m[4]): m[4] for m in members if m[5] == 'event'}.values())
        quar = list({id(m[4]): m[4] for m in members if m[5] == 'quarantine'}.values())
        verify_with_logs(events, quar)
        for m in members:
            ids = [x for x in str(m[4].get('incident', '')).split(', ') if x]
            if iid not in ids:
                m[4]['incident'] = ', '.join(ids + [iid])
        best = min(members, key=lambda m: (_PATH_RANK.get(m[2], 9) if m[1] else 9, m[0]))

        def uniq(values):
            return '; '.join(dict.fromkeys(str(v) for v in values if v))
        actions = [r.get('action_norm') for r in events] + (['quarantined'] if quar else [])
        actions = _actions(actions)
        rows.append({
            'incident': iid,
            'first_seen': members[0][0].isoformat() + 'Z', 'last_seen': members[-1][0].isoformat() + 'Z',
            'path': best[1], 'path_type': best[2] if best[1] else '',
            'threats': uniq([r.get('threat') for r in events] + [r.get('detection') for r in quar]),
            'products': uniq([r.get('product') for r in events] + [r.get('product') or r.get('source') for r in quar]),
            'actions': uniq(actions), 'events': len(events),
            'logs': uniq(sorted({r.get('log') for r in events})),
            'quarantined': 'yes' if quar or 'quarantined' in actions else '',
            'recovered_files': uniq(r.get('saved_as') for r in quar),
            'sha256': uniq([r.get('sha256') for r in quar] + [r.get('sha256') for r in events]),
            'users': uniq(r.get('user') for r in events), 'processes': uniq(r.get('process') for r in events),
            'volume': uniq([r.get('volume') for r in events] + [r.get('volume') for r in quar]),
            **dict(zip(('user_context', 'profile', 'file_owner'), _user_context(events, quar, best[1], profiles),
                       strict=True)),
            'action_times': '; '.join(f'{t} {a} ({p})' if p else f'{t} {a}' for t, a, p in _action_times(events, quar)),
            'origin': uniq(origin_text(r.get('zone_id'), r.get('host_url'), r.get('referrer_url')) for r in quar),
            'origin_evidence': 'Zone.Identifier kept with the quarantined file'
            if any(r.get('zone_id') or r.get('host_url') for r in quar) else ''})
    return rows


def local_time_to_utc(row, host):
    """A parser of a log in local time writes '<ISO> (local time)'; with the host's time zone
    that becomes UTC like every other row, and the original goes into details. Without the
    time zone the row keeps its local time (marked as such)."""
    when = str(row.get('time', '') or '')
    if not when.endswith('(local time)'):
        return
    utc = hostinfo.to_utc(host, when)
    if utc:
        row['time'] = utc
        row['details'] = '; '.join(x for x in (str(row.get('details') or ''), f'local time: {when[:-13]}') if x)


def normalize_all(detections, quarantine, hosts):
    """Everything in place; returns the incident rows."""
    system_drive = next((h.get('system_drive') for h in hosts.values() if h.get('system_drive')), 'C:')
    paths = [r.get('path', '') for r in detections] + [r.get('original_path', '') for r in quarantine]
    flat = [p for raw in paths for p in re.split(r';\s*', str(raw or '')) if p]
    mapper = PathMapper(flat, system_drive)
    for r in detections:
        host = hosts.get(r.get('volume'), {})
        local_time_to_utc(r, host)
        normalize_detection(r, mapper, host.get('system_drive', system_drive))
    for r in quarantine:
        normalize_quarantine(r, hosts, mapper)
    profiles = {sid: folder for h in hosts.values() for sid, folder in (h.get('profiles') or {}).items()}
    return build_incidents(detections, quarantine, profiles)


def _first(values):
    """'a; b; c' -> 'a (+2)': whole names, the full list stays in the CSV."""
    parts = [v for v in str(values or '').split('; ') if v]
    if not parts:
        return '?'
    return parts[0] + (f' (+{len(parts) - 1})' if len(parts) > 1 else '')


_ACTION_TIME = re.compile(r'(\S+) (\S+)(?: \((.*?)\))?(?:; |$)')


def _field(label, value):
    """'  label    value': one fact, one line, never broken (paths and URLs stay copyable)."""
    return [f'  {label:<9}{value}']


def _incident_block(inc):
    """One incident as a labelled block: one fact per line, the path on a line of its own."""
    out = [f"{inc['incident']}  {inc['first_seen'][:19].replace('T', ' ')} UTC  {_first(inc['threats'])}"]
    out += _field('file', inc.get('path') or '?')
    day = str(inc.get('first_seen', ''))[:10]
    actions = _ACTION_TIME.findall(str(inc.get('action_times') or ''))
    same_day = all(t[:10] == day for t, _a, _p in actions)
    for n, (t, action, product) in enumerate(actions):
        when = t[11:19] if same_day else t[:19].replace('T', ' ')
        out.append(f"  {'actions' if n == 0 else '':<9}{when}  {action:<12} {product}".rstrip())
    if inc.get('recovered_files'):
        files = str(inc['recovered_files']).split('; ')
        out += _field('saved as', 'malware\\' + files[0].rsplit('/', 1)[-1] + (f' (+{len(files) - 1})'
                                                                             if len(files) > 1 else ''))
    who = inc.get('user_context') or ''
    if inc.get('profile'):
        who += f"{'  ' if who else ''}(profile {inc['profile']})"
    if who:
        out += _field('user', who)
    if inc.get('file_owner'):
        out += _field('owner', inc['file_owner'])
    process = str(inc.get('processes') or '').split('; ')[0]
    if process and process.lower() != 'unknown':
        itself = '  (the file itself ran)' if process.lower() == str(inc.get('path', '')).lower() else ''
        more = str(inc.get('processes')).count('; ')
        out += _field('process', process + itself + (f'  (+{more} more)' if more else ''))
    if inc.get('origin'):
        out += _field('origin', f"{_short_urls(inc['origin'])}  [{inc.get('origin_evidence', '')}]")
    if inc.get('on_disk_since'):
        dwell = f"  -  {inc['dwell']} before the detection" if inc.get('dwell') else ''
        out += _field('on disk', f"since {inc['on_disk_since'][:19].replace('T', ' ')} UTC{dwell}  "
                                 f"[{inc.get('on_disk_evidence', '')}]")
    for n, hop in enumerate(str(inc.get('journey') or '').split(' -> ') if inc.get('journey') else []):
        out.append(f"  {'journey' if n == 0 else '':<9}{hop}")
    return out


def _table(rows, columns):
    """Aligned columns; the last one (the full path) is never padded or cut."""
    widths = [max([len(str(c))] + [len(str(r[i])) for r in rows]) for i, c in enumerate(columns)]
    widths[-1] = 0
    lines = ['  ' + '  '.join(str(c).ljust(w) for c, w in zip(columns, widths, strict=True))]
    for r in rows:
        lines.append('  ' + '  '.join(str(v).ljust(w) for v, w in zip(r, widths, strict=True)))
    return lines


def summary_text(summary, detections, quarantine, incidents, hosts):
    """The run for a human reader (info/summary.txt)."""
    out = [f"{summary.get('tool', 'qextract')} - report schema {SCHEMA_VERSION}",
           f"Started {summary.get('started', '')}, finished {summary.get('finished', '')}",
           f"Input:  {summary.get('input', '')} ({len(summary.get('volumes', []))} volume(s))"]
    db = summary.get('location_database')
    if isinstance(db, dict) and db:
        out.append(f"Location database: {db.get('locations', 0)} locations, {db.get('products', 0)} products "
                   f"({db.get('decoded', 0)} with the quarantine decoded, {db.get('parsed', 0)} with logs in the "
                   'timeline)')
    if summary.get('output_on_input'):
        why = ('a live system keeping its own results' if summary.get('live_system')
               else '--force: the input was changed by the writing')
        out.append(f'Output: on the scanned input - {why}')
    out.append('')
    for vol, h in sorted(hosts.items()):
        if h:
            p = hostinfo.public(h)
            out.append(f"Host ({vol}): {p.get('computer', '?')} - {p.get('os', 'Windows version unknown')}")
            offset = f" ({p['utc_offset']})" if p.get('utc_offset') else ''
            problem = f"; {p['error']}" if p.get('error') else ''
            out.append(f"  time zone {p.get('time_zone', 'unknown')}{offset}{problem}")
            for n in p.get('networks') or []:      # DHCP = the last lease in the registry (details in summary.json)
                out.append(f"  network   {n.get('address', '?')} ({n.get('adapter', '?')}, "
                           f"{'DHCP' if n.get('dhcp') else 'static'})")
    if any(hosts.values()):
        out.append('')
    found = summary.get('found', {})
    cats = collections.defaultdict(collections.Counter)
    for r in detections:
        cats[r.get('source', '')][r.get('category', 'other')] += 1
    rows = []
    for sid, s in sorted(found.items(), key=lambda x: x[1].get('name', '')):
        c = cats.get(sid, {})
        rows.append([s.get('name', sid), s.get('files', 0), s.get('quarantine_items', 0), s.get('recovered', 0),
                     c.get('detection', 0), c.get('response', 0), sum(c.values())])
    if rows:
        out.append('Products')
        out += _table(rows, ['product', 'files', 'quarantine', 'recovered', 'detections', 'responses', 'timeline'])
    else:
        out.append('Nothing found.')
    out.append('')
    noise = collections.Counter(r.get('category') for r in detections)
    if detections:
        out.append('Timeline: ' + ', '.join(f'{noise[c]} {c}' for c in CATEGORIES if noise.get(c)))
        out.append('')
    out.append(f'Incidents ({len(incidents)}) - one threat on one file, all logs and quarantine joined (incidents.csv)')
    out.append('=' * 80)
    for inc in incidents:              # all of them: the summary is the report, not a teaser
        out += _incident_block(inc)
        out.append('')
    out.append('')
    history = summary.get('file_history') or {}
    if history == 'off':
        out += ['File history ($MFT / $UsnJrnl): off (--no-file-history)', '']
    elif isinstance(history, dict) and history:
        late = [i for i in incidents if i.get('dwell') and not str(i['dwell']).endswith(' s')]   # a minute or more
        out.append(f"File history ($MFT / $UsnJrnl, mft\\): {history.get('records', 0)} file record(s), "
                   f"{history.get('usn_events', 0)} journal event(s), {history.get('seconds', 0)} s")
        for note in history.get('notes', []):
            out.append(f'  {note}')
        if late:
            out.append(f'  On the disk a minute or more before the first detection ({len(late)}): '
                       + ', '.join(f"{i['incident']} ({i['dwell']})" for i in late))
        moved = [i['incident'] for i in incidents if i.get('journey')]
        if moved:
            out.append(f'  Moved or renamed on the drive ({len(moved)}, mft\\file_moves.csv): ' + ', '.join(moved))
        origins = [i['incident'] for i in incidents if i.get('origin')]
        if origins:
            out.append(f'  Download origin known ({len(origins)}, Zone.Identifier): ' + ', '.join(origins))
        out.append('')
    rec = [r for r in quarantine if r.get('saved_as')]
    password = ' - password "infected"' if summary.get('zip_password') == 'infected' else ''
    out.append(f'Recovered files ({len(rec)}) in malware\\{password}')
    if rec:
        out += _table([[r.get('detection') or '?', str(r.get('quarantined_utc') or r.get('quarantined') or '')[:19]
                        .replace('T', ' '), r.get('verified_by') or '-',
                        r.get('path_norm') or r.get('original_path') or ''] for r in rec],
                      ['detection', 'quarantined (UTC)', 'verified by', 'original path'])
    not_rec = [r for r in quarantine if r.get('recovery') != 'recovered']
    if not_rec:
        out.append(f'  not recovered: {len(not_rec)} (see quarantine.csv, status)')
    out.append('')
    warnings, errors = summary.get('warnings', []), summary.get('errors', [])
    out.append(f'Warnings ({len(warnings)})' + (':' if warnings else ''))
    out += [f'  - {w}' for w in warnings]
    out.append(f'Errors: {"; ".join(errors) if errors else "none"}')
    out += ['', 'Files in this zip:',
            '  incidents.csv        start here: one row per threat on a file',
            '  detections.csv       the timeline of all AV logs (filter on category)',
            '  quarantine.csv       quarantine items, hashes, recovered or not',
            '  collected_files.csv  every copied file; the copies are in files\\, decoded forms in decoded\\',
            '  summary.json         this summary for programs; qextract.log the run']
    # paths, names, threat names and download URLs come from the evidence: a line break or a
    # terminal escape sequence in them must not reach a console that shows this file
    return '\n'.join(_UNSAFE_TEXT.sub('?', str(line)) for line in out) + '\n'
