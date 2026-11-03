"""WithSecure Elements EPP quarantine (ProgramData\\F-Secure\\Quarantine\\Repository\\).

The business product still uses the F-Secure folder names. The consumer F-Secure app has not
been checked in the lab: it is a separate product (fsecure) without this decoder.

info\\<n>.xml is one item in plain XML, TAR\\<n>.tar (old-style tar, numbered members) its
content. The key travels with each item, so no product key is needed. Two kinds (lab,
WithSecure Elements 11.0.107):

- a file (public/file): the original path (name_widechar: base64 of UTF-16), infection name,
  size, the file's creation / last access / last write times, the quarantine time (local and
  UTC), the accounts and the scanner versions, and "okey": 1024 random bytes (base64). The tar
  has one member: the file XORed with okey repeated.
- a "spyware" block (public/spyware, from the PUA scanner): a file plus the registry values
  the detection named. Member 0 is the key: magic 19 49 19 49, 12 more header bytes, the
  1024-byte key, 32 zero bytes. Then pairs of members: a descriptor (u32 size of the next
  member, u32 kind: 0 file, 1 registry value; the path in UTF-16) and the data - a file
  XORed with the key, a registry value in plain.
"""

import base64
import re
import struct

import defusedxml.ElementTree as DefusedET

from . import decoder
from .util import guard, plain_path, recovered, xor

_NUMBER = re.compile(r'^(\d{8})\.xml$', re.IGNORECASE)
_SYSTEMTIME = re.compile(r'^(\d{4})\.(\d{2})\.(\d{2})\.\d (\d{2}):(\d{2}):(\d{2})\.(\d{3})$')
_WIDE = re.compile(rb'(?:[\x20-\x7e]\x00){3,}')
_KEY_MAGIC = b'\x19\x49\x19\x49'


def _time(text, utc=True):
    m = _SYSTEMTIME.match((text or '').strip())
    if not m:
        return ''
    y, mo, d, h, mi, s, ms = m.groups()
    return f'{y}-{mo}-{d}T{h}:{mi}:{s}.{ms}' + ('Z' if utc else ' (local time)')


def _text(root, path):
    node = root.find(path)
    return (node.text or '').strip() if node is not None else ''


def _hex(text):
    return int(text, 16) if re.fullmatch(r'[0-9A-Fa-f]{1,16}', text) else None


def _members(tar):
    """The members of a v7 tar, in order (contents only; the names are just numbers)."""
    out, at = [], 0
    while at + 512 <= len(tar) and any(tar[at:at + 512]):
        size = int(tar[at + 124:at + 136].split(b'\0')[0].strip() or b'0', 8)
        if at + 512 + size > len(tar):
            raise ValueError('tar member runs past the end of the file')
        out.append(tar[at + 512:at + 512 + size])
        at += 512 + (size + 511) // 512 * 512
    if not out:
        raise ValueError('empty tar')
    return out


def _spyware_files(members):
    """(path, content) of each file in a spyware block, and the number of registry values."""
    head = members[0]
    if len(head) < 16 + 1024 or head[:4] != _KEY_MAGIC:
        raise ValueError('spyware block without its key member')
    key, files, values = head[16:16 + 1024], [], 0
    for desc, data in zip(members[1::2], members[2::2], strict=False):
        if len(desc) < 8:
            raise ValueError('short descriptor in a spyware block')
        size, kind = struct.unpack_from('<II', desc)
        if kind == 1:
            values += 1
        elif kind == 0:
            if size != len(data):
                raise ValueError(f'file member is {len(data)} bytes, its descriptor says {size}')
            texts = _WIDE.findall(desc)
            files.append((texts[0].decode('utf-16-le') if texts else '', xor(data, key)))
    return files, values


@decoder('withsecure')
def decode(ctx, files, options):
    tars = {f.name[:-4].lower(): f for f in files if f.name.lower().endswith('.tar')}
    rows = []
    for f in files:
        m = _NUMBER.match(f.name)
        if not m:
            continue
        with guard(rows, f):
            # account names are in the ANSI code page (lab: "ZARZ\xa5DZANIE NT"), not UTF-8
            root = DefusedET.fromstring(ctx.read(f).decode('utf-8', 'replace'))
            row = {'container': f.path, 'item_type': 'file', 'resource': m.group(1)}
            wide = _text(root, 'public/file/name_widechar')
            if wide:
                row['original_path'] = plain_path(base64.b64decode(wide).decode('utf-16-le', 'replace').rstrip('\0'))
            row['detection'] = (_text(root, 'public/file/infection/name')
                                or _text(root, 'public/spyware/infection_name')
                                or _text(root, 'public/spyware/infection_family'))
            row['quarantined'] = _time(_text(root, 'public/quarantining_time/utc/systemtime_data'))
            row['file_created'] = _time(_text(root, 'public/file/time/creation_time'))
            row['file_accessed'] = _time(_text(root, 'public/file/time/lastaccess_time'))
            row['file_modified'] = _time(_text(root, 'public/file/time/lastwrite_time'))
            account = '\\'.join(x for x in (_text(root, 'private/domainName'), _text(root, 'private/userName')) if x)
            # private/*: the account of the scanning process (SYSTEM for real-time protection);
            # handle_sid: the account whose access to the file led to the detection
            notes = {'scan account': f'{account} ({_text(root, "private/userSid")})' if account else '',
                     'handle SID': _text(root, 'public/handle_sid'),
                     'computer': _text(root, 'private/computerName'),
                     'scanner': _text(root, 'public/scanner/version'),
                     'database': _text(root, 'public/scanner/database/version')}
            row['notes'] = '; '.join(f'{k} {v}' for k, v in notes.items() if v)
            tar = tars.get(m.group(1))
            if tar is None:
                row['status'] = 'not recovered: no TAR file for this item'
                rows.append(row)
                continue
            members = _members(ctx.read(tar))
            if root.find('public/spyware') is not None:
                block, values = _spyware_files(members)
                if values:
                    row['notes'] += f'; the block also holds {values} registry value(s): see the XML'
                if not block:
                    row['original_path'] = plain_path(_text(root, 'public/spyware/object_name'))
                    row['status'] = 'not recovered: no file in this spyware block'
                    rows.append(row)
                for path, content in block:
                    item = dict(row, original_path=plain_path(path or _text(root, 'public/spyware/object_name')))
                    rows.append(recovered(ctx, item, content))
                continue
            key = base64.b64decode(_text(root, 'public/okey') or '')
            if not key:
                row['status'] = 'not recovered: no key (okey)'
                rows.append(row)
                continue
            size = _hex(_text(root, 'public/object_size') or _text(root, 'public/file/size'))
            rows.append(recovered(ctx, row, xor(members[0], key), ('size', size)))
    return rows
