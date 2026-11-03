"""Microsoft Defender quarantine (Quarantine\\Entries + Quarantine\\ResourceData).

Every part is RC4 encrypted with a fixed key taken from mpengine.dll.
"""

import hashlib
import struct

from . import decoder, util
from .util import digest, filetime, guard

KEY = bytes([
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86,
    0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA,
    0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53,
    0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
    0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8,
    0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E,
    0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
    0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A,
    0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
    0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
    0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B,
    0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
])
ENTRY_MAGIC = bytes([0xDB, 0xE8, 0xC5, 0x01, 0x01, 0x00, 0x01, 0x00])
# resource fields of an entry, by the low 12 bits of the identifier (the top 4 bits are
# the value type); times and size checked against a real quarantine
FIELDS = {0x02: 'resource', 0x0A: 'file_attributes', 0x0C: 'physical_path',
          0x0F: 'file_created', 0x10: 'file_accessed', 0x11: 'file_modified', 0x12: 'file_size'}
# WIN32_STREAM_ID types: the resource is the original file as BackupRead returned it
BACKUP_DATA, BACKUP_SECURITY_DATA, BACKUP_ALTERNATE_DATA = 1, 3, 4
STREAM_TYPES = {1: 'data', 2: 'extended attributes', 3: 'security descriptor', 4: 'alternate data',
                5: 'hard link', 6: 'property data', 7: 'object id', 8: 'reparse point',
                9: 'sparse block', 10: 'transactional data'}
ZONE_STREAM = ':zone.identifier:$data'
ROW_FIELDS = ('file_created', 'file_modified', 'file_accessed')
METADATA_FIELDS = ('detection', 'threat_id', 'quarantined', 'item_type', 'original_path',
                   'file_created', 'file_modified', 'file_accessed', 'owner_sid', 'zone_id',
                   'host_url', 'referrer_url', 'size', 'md5', 'sha1', 'sha256', 'resource',
                   'container', 'status', 'notes')

def rc4(data):
    return util.rc4(KEY, data)


def _utf16z(data, pos):
    end = pos
    while end + 1 < len(data) and data[end:end + 2] != b'\0\0':
        end += 2
    return data[pos:end].decode('utf-16-le', 'replace'), end + 2


def parse_entry(data):
    """One Entries\\{GUID} file -> (detection, time, threat id, [(type, path, resource id)])."""
    header = rc4(data[:0x3C])
    if not header.startswith(ENTRY_MAGIC):
        raise ValueError('not a Defender quarantine entry')
    len1, len2 = struct.unpack_from('<II', header, 0x28)
    part1 = rc4(data[0x3C:0x3C + len1])
    part2 = rc4(data[0x3C + len1:0x3C + len1 + len2])
    if len(part1) < 0x34 or len(part2) < 4:
        raise ValueError('entry is truncated')

    when, threat_id = struct.unpack_from('<QQ', part1, 0x20)
    detection = part1[0x34:].split(b'\0', 1)[0].decode('utf-8', 'replace')

    resources = []
    count, = struct.unpack_from('<I', part2, 0)
    for offset in struct.unpack_from(f'<{count}I', part2, 4):
        res = part2[offset:]
        path, pos = _utf16z(res, 0)
        if path.startswith('\\\\?\\'):
            path = path[4:]
        field_count, = struct.unpack_from('<H', res, pos)
        pos += 2
        end = res.index(b'\0', pos)
        kind = res[pos:end].decode('ascii', 'replace')
        pos = end + 1
        pos += (4 - pos) % 4
        info = {'resource': ''}
        for _ in range(field_count):
            if pos + 4 > len(res):
                break
            size, ident = struct.unpack_from('<HH', res, pos)
            value = res[pos + 4:pos + 4 + size]
            name = FIELDS.get(ident & 0x0FFF)
            if name == 'resource' and size == 20 and not info['resource']:
                info['resource'] = value.hex().upper()
            elif name in ('file_created', 'file_accessed', 'file_modified', 'file_size') and size == 8:
                number, = struct.unpack('<Q', value)
                info[name] = number if name == 'file_size' else filetime(number)
            elif name == 'file_attributes' and size == 4:
                info[name] = f'0x{struct.unpack("<I", value)[0]:08X}'
            elif name == 'physical_path':
                info[name] = value.decode('utf-16-le', 'replace').rstrip('\0')
            pos += 4 + size
            pos += (4 - pos) % 4
        resources.append((kind, path, info))
    return detection, filetime(when), threat_id, resources


def read_streams(plain):
    """The decrypted container is a BackupRead stream: WIN32_STREAM_ID headers (type,
    attributes, size, name length, name) each followed by its data, unpadded.
    -> ([(type, name, data)], number of trailing bytes that are not a whole stream)."""
    streams, pos = [], 0
    while pos + 20 <= len(plain):
        kind, _attrs, size, name_len = struct.unpack_from('<IIQI', plain, pos)
        start = pos + 20 + name_len
        if kind not in STREAM_TYPES or start + size > len(plain):
            break
        name = plain[pos + 20:start].decode('utf-16-le', 'replace')
        streams.append((kind, name, plain[start:start + size]))
        pos = start + size
    return streams, len(plain) - pos


def sid_string(sid):
    revision, count = sid[0], sid[1]
    if len(sid) < 8 + 4 * count:
        raise ValueError('SID is truncated')
    authority = int.from_bytes(sid[2:8], 'big')
    subs = struct.unpack_from(f'<{count}I', sid, 8)
    return '-'.join(['S', str(revision), str(authority), *map(str, subs)])


def owner_sid(descriptor):
    """Owner of a self-relative SECURITY_DESCRIPTOR, '' when there is none."""
    if len(descriptor) < 20:
        return ''
    offset, = struct.unpack_from('<I', descriptor, 4)
    if not offset or offset + 8 > len(descriptor):
        return ''
    return sid_string(descriptor[offset:])


def unpack_resource(data):
    """One ResourceData\\xx\\<SHA1> file -> (original file contents, whole decrypted container,
    the other streams: [(type, name, data)], trailing bytes not parsed).

    The file name is the SHA1 of the whole decrypted container (security descriptor, the
    file and, after it, further streams such as Zone.Identifier), not of the file itself;
    checked on a real Defender quarantine."""
    plain = rc4(data)
    streams, trailing = read_streams(plain)
    content = [s for s in streams if s[0] == BACKUP_DATA]
    if not content:
        raise ValueError('no file data stream in the resource')
    return content[0][2], plain, [s for s in streams if s is not content[0]], trailing


def describe_streams(row, streams):
    """Owner SID and Zone.Identifier into the row; -> sections for the metadata text."""
    sections, others = [], []
    for kind, name, data in streams:
        if kind == BACKUP_SECURITY_DATA and not row.get('owner_sid'):
            try:
                row['owner_sid'] = owner_sid(data)
            except (ValueError, struct.error):
                row['owner_sid'] = ''
        elif kind == BACKUP_ALTERNATE_DATA and name.lower() == ZONE_STREAM:
            text = data.decode('utf-8', 'replace').replace('\0', '')
            sections.append(('Zone.Identifier', text))
            for line in text.splitlines():
                key, _, value = line.partition('=')
                column = {'zoneid': 'zone_id', 'hosturl': 'host_url',
                          'referrerurl': 'referrer_url'}.get(key.strip().lower())
                if column:
                    row[column] = value.strip()
        else:
            # other streams may hold anything, so only their name, size and hash are reported
            others.append(f'{STREAM_TYPES[kind]} {name or "(unnamed)"}: {len(data)} bytes, '
                          f'sha256 {hashlib.sha256(data).hexdigest()}')
    if others:
        sections.append(('Other streams (not extracted)', '\n'.join(others)))
    return sections


@decoder('defender')
def decode(ctx, files, options):
    entries = [f for f in files if '/entries/' in f.path.lower()]
    resources = {f.name.upper(): f for f in files if '/resourcedata/' in f.path.lower()}
    rows, used = [], set()

    def recover(row, entry, info):
        try:
            content, container, streams, trailing = unpack_resource(ctx.read(entry))
        except (ValueError, struct.error, OSError) as e:
            row['status'] = f'error: {e}'
            return
        intact = digest('sha1', container).upper() == entry.name.upper()
        row.update(
            size=len(content),
            md5=digest('md5', content),
            sha1=digest('sha1', content),
            sha256=hashlib.sha256(content).hexdigest(),
            status='recovered' if intact else 'recovered (container SHA1 differs from resource name)',
            verified_by='sha1 of the container' if intact else 'sha1 mismatch',
        )
        sections = describe_streams(row, streams)
        if trailing:
            note = f'{trailing} trailing bytes in the resource not parsed'
            row['notes'] = '; '.join(x for x in (row.get('notes'), note) if x)
        fields = {k: row.get(k) for k in METADATA_FIELDS}
        fields.update((k, v) for k, v in info.items() if k in ('file_size', 'file_attributes', 'physical_path'))
        name = row['original_path'].replace('\\', '/').rsplit('/', 1)[-1] or entry.name
        row['saved_as'] = ctx.save(f'{row["sha256"]}_{name}', content, util.metadata_text(fields, sections))

    for e in entries:
        with guard(rows, e):
            detection, when, threat_id, items = parse_entry(ctx.read(e))
            for kind, path, info in items:
                resource_id = info['resource']
                row = {
                    'container': e.path, 'detection': detection, 'quarantined': when,
                    'threat_id': threat_id, 'item_type': kind, 'original_path': path,
                    'resource': resource_id,
                }
                row.update((k, v) for k, v in info.items() if k in ROW_FIELDS)
                res = resources.get(resource_id)
                if res is not None:
                    used.add(resource_id)
                    recover(row, res, info)
                elif kind == 'file':
                    row['status'] = 'resource file missing'
                else:
                    row['status'] = 'metadata only'
                rows.append(row)

    for resource_id, res in sorted(resources.items()):
        if resource_id not in used:
            with guard(rows, res):
                row = {'container': res.path, 'resource': resource_id, 'original_path': '',
                       'item_type': 'file', 'notes': 'no matching entry'}
                recover(row, res, {})
                rows.append(row)
    return rows
