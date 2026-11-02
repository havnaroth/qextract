"""Read-only views of a file system: a folder on disk or a volume inside a disk image."""

import contextlib
import fnmatch
import functools
import io
import os
import re
import stat
import sys
import zlib
from dataclasses import dataclass, field
from urllib.parse import unquote

CHUNK = 1024 * 1024
MAX_DEPTH = 64
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# A folder holding one of these is treated as the root of a Windows volume.
WINDOWS_ROOT_MARKERS = {'programdata', 'windows', 'users', 'program files', 'program files (x86)',
                        'documents and settings'}
NTFS_METADATA = {'$MFT', '$MFTMirr', '$LogFile', '$Volume', '$AttrDef', '$Bitmap', '$Boot', '$BadClus',
                 '$Secure', '$UpCase', '$Extend', '$OrphanFiles'}     # '$AV_ASW' etc. are real folders
ROOT_SEARCH_DEPTH = 4
ROOT_SEARCH_DIRS = 5000


@dataclass
class Entry:
    path: str                   # relative to the volume root, '/' separated, original case
    is_dir: bool
    size: int = 0
    created: float | None = None
    modified: float | None = None
    accessed: float | None = None
    deleted: bool = False
    handle: object = field(default=None, repr=False, compare=False)
    inode: int | None = None    # file system record number, where the file system has one

    @property
    def name(self):
        return self.path.rsplit('/', 1)[-1]


def nested_quantifier(body):
    """True when a repeated group itself repeats or alternates, e.g. (a+)+, (a*)*, (a|aa)+:
    such an expression takes exponential time on a crafted file name (ReDoS). File names
    come from the evidence, so these expressions are refused."""
    stack, in_class, i = [], False, 0
    while i < len(body):
        c = body[i]
        if c == '\\':
            i += 2
            continue
        if in_class:
            in_class = c != ']'
        elif c == '[':
            in_class = True
        elif c == '(':
            stack.append(False)
        elif c == ')' and stack:
            risky = stack.pop()
            if risky and body[i + 1:i + 2] in ('+', '*', '{'):
                return True
            if stack:
                stack[-1] = stack[-1] or risky
        elif c in '+*{|' and stack:
            stack[-1] = True
        i += 1
    return False


@functools.cache
def _segment(pattern):
    """One path segment: a wildcard pattern, or 'regex:<expression>' (KAPE FileMask syntax)."""
    if pattern.lower().startswith('regex:'):
        body = pattern[6:]
        if nested_quantifier(body):
            raise re.error('nested repetition such as (a+)+ is refused (exponential time on crafted names)')
        try:
            return re.compile(f'(?:{body})\\Z', re.IGNORECASE)
        except re.error:
            # KAPE accepts a leading '*' (e.g. 'regex:*.+\.db'); Python does not
            return re.compile(f'(?:{body.lstrip("*")})\\Z', re.IGNORECASE)
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


def long_path(path):
    """Windows path that is not limited to 260 characters."""
    path = os.path.abspath(path)
    if os.name == 'nt' and not path.startswith('\\\\'):
        return '\\\\?\\' + path
    return path


def error_text(e):
    """Readable reason of an error. An OSError's own text repeats the path as a repr with
    doubled backslashes; the caller already names the file, so only the reason is kept."""
    if isinstance(e, OSError) and e.strerror:
        return e.strerror.rstrip('.')
    return f'{type(e).__name__}: {e}'


def final_path(path=None, fd=None):
    """The path Windows resolves a file to, all links followed ('' elsewhere): of a path,
    or - free of races - of an open file descriptor."""
    if sys.platform != 'win32':
        return ''
    import ctypes
    import msvcrt
    import nt
    if fd is None:
        return nt._getfinalpathname(long_path(path))
    buf = ctypes.create_unicode_buffer(32768)
    kernel32 = ctypes.windll.kernel32
    kernel32.GetFinalPathNameByHandleW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
    n = kernel32.GetFinalPathNameByHandleW(msvcrt.get_osfhandle(fd), buf, len(buf), 0)
    if not n or n >= len(buf):
        raise OSError(f'cannot resolve the path of an open file (error {ctypes.GetLastError()})')
    return buf.value


class Volume:
    """Base class. Subclasses implement _list(path, entry) and chunks(entry)."""

    # Whole file systems start at a Windows root; collections and logical images may
    # hold it deeper (KAPE: <out>\C\ProgramData, L01: <case>\C\ProgramData).
    search_roots = False

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.warnings = []
        self.disk_root = None       # where the volume is on this machine, for folders and drives
        self.skip = set()           # lower-case paths left out (our own output folder)
        self._cache = {}
        self._roots = None

    def skip_local(self, local_path):
        """Leave out a folder of this machine (the output) if it lies inside this volume."""
        if not self.disk_root:
            return
        root = os.path.normcase(os.path.abspath(self.disk_root)).rstrip('\\/') + os.sep
        target = os.path.normcase(os.path.abspath(local_path))
        if target.startswith(root):
            self.skip.add(target[len(root):].replace(os.sep, '/').lower())

    def listdir(self, path='', entry=None):
        if path not in self._cache:
            try:
                entries = self._list(path, entry)
            except OSError as e:
                self.warnings.append(f'cannot list /{path}: {error_text(e)}')
                entries = []
            self._cache[path] = [e for e in entries if e.path.lower() not in self.skip]
        return self._cache[path]

    def read(self, entry):
        return b''.join(self.chunks(entry))

    def chunks(self, entry):
        offset = 0
        while offset < entry.size:
            data = self.read_at(entry, offset, min(CHUNK, entry.size - offset))
            if not data:
                break
            yield data
            offset += len(data)

    def open(self, entry):
        """The file as a read-only, seekable stream, for parsers of files too big to hold in memory."""
        return io.BufferedReader(_EntryStream(self, entry), buffer_size=CHUNK)

    def roots(self):
        """Folders the source paths are matched from ('' is the volume root)."""
        if self._roots is None:
            self._roots = self._find_roots() if self.search_roots else ['']
        return self._roots

    def _find_roots(self):
        def is_root(path):
            return any(e.is_dir and e.name.lower() in WINDOWS_ROOT_MARKERS for e in self.listdir(path))

        if is_root(''):
            return ['']
        roots, level, seen = [], [''], 0
        for _ in range(ROOT_SEARCH_DEPTH):
            below = []
            for path in level:
                for e in self.listdir(path):
                    if not e.is_dir:
                        continue
                    seen += 1
                    if is_root(e.path):
                        roots.append(e.path)
                    else:
                        below.append(e.path)
            if seen > ROOT_SEARCH_DIRS:
                break
            level = below
        return roots or ['']

    def glob(self, pattern, root=''):
        """Case-insensitive match of files below root. '*' and '?' match within one name,
        '**' matches any number of folders (or, at the end, every file below)."""
        parts = [p for p in pattern.replace('\\', '/').split('/') if p]
        seen = set()
        for e in self._glob(root, None, parts, 0, set()):
            if e.path not in seen:
                seen.add(e.path)
                yield e

    def _glob(self, base, base_entry, parts, depth, walked):
        """walked: folders '**' already descended into, by record number. A crafted file
        system can link a folder to its own parent; without this '**' would follow every
        such loop down to MAX_DEPTH, which grows exponentially with the number of links."""
        if depth > MAX_DEPTH:
            return
        head, rest = parts[0], parts[1:]
        if head == '**':
            if rest:
                yield from self._glob(base, base_entry, rest, depth, walked)
            for e in self.listdir(base, base_entry):
                if e.is_dir:
                    if e.inode is not None:
                        if e.inode in walked:
                            continue
                        walked.add(e.inode)
                    yield from self._glob(e.path, e, parts, depth + 1, walked)
                elif not rest:
                    yield e
            return
        try:
            rx = _segment(head)
        except re.error as e:       # definitions are checked on loading; this is the last line
            self.warnings.append(f'pattern "{head}" skipped: {e}')
            return
        for e in self.listdir(base, base_entry):
            if not rx.match(e.name):
                continue
            if not rest:
                if not e.is_dir:
                    yield e
            elif e.is_dir:
                yield from self._glob(e.path, e, rest, depth + 1, walked)


class DirVolume(Volume):
    """A folder on disk: a mounted image, a drive letter or a collected triage folder."""

    search_roots = True

    def __init__(self, root):
        root = os.path.abspath(root)
        super().__init__('dir', root)
        self.root = root
        self.disk_root = root
        self._file_ids = {}     # path -> (device, file id) as listed
        self._final_root = final_path(root).rstrip('\\').lower() if os.path.isdir(root) else ''

    def _list(self, path, entry):
        full = os.path.join(self.root, path.replace('/', os.sep))
        out = []
        with os.scandir(long_path(full)) as it:
            for d in it:
                try:
                    st = d.stat(follow_symlinks=False)
                except OSError as e:
                    self.warnings.append(f'cannot read {d.path}: {error_text(e)}')
                    continue
                if getattr(st, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                    continue    # junctions such as "Application Data" loop back on themselves
                is_dir = stat.S_ISDIR(st.st_mode)
                if not is_dir:      # scandir gives no file id on Windows: ask for it (one call)
                    with contextlib.suppress(OSError):
                        ids = os.lstat(d.path)
                        self._file_ids[d.path] = (ids.st_dev, ids.st_ino)
                out.append(Entry(
                    path=f'{path}/{d.name}' if path else d.name,
                    is_dir=is_dir,
                    size=0 if is_dir else st.st_size,
                    created=st.st_ctime if os.name == 'nt' else None,
                    modified=st.st_mtime,
                    accessed=st.st_atime,
                    handle=d.path,
                ))
        return out

    def _open_checked(self, entry):
        """Open a listed file, refusing it when the name now leads to another file: a file
        swapped for a link after the listing (as administrator that could copy a protected
        file into the user's output)."""
        f = open(entry.handle, 'rb')  # noqa: SIM115 - returned to the caller
        try:
            listed = self._file_ids.get(entry.handle)
            st = os.fstat(f.fileno())
            if listed and listed[1] and (st.st_dev, st.st_ino) != listed:
                raise OSError(f'{entry.path} is another file than the one listed (swapped?) - not read')
            # a folder on the way swapped for a junction since the listing leads elsewhere
            expected = (self._final_root + '\\' + entry.path.replace('/', '\\')).lower()
            if self._final_root and final_path(fd=f.fileno()).lower() != expected:
                raise OSError(f'{entry.path} now leads outside the listed folder (link planted?) - not read')
        except BaseException:
            f.close()
            raise
        return f

    def chunks(self, entry):
        """The file as it was listed: at most entry.size bytes, so a file that keeps growing
        (a live log, or one fed on purpose) cannot fill the output disk or pass the limits."""
        remaining = entry.size
        with self._open_checked(entry) as f:
            while remaining > 0:
                data = f.read(min(CHUNK, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data

    def open(self, entry):
        return self._open_checked(entry)    # the caller closes the stream


class TskVolume(Volume):
    """A file system inside a disk image, read with The Sleuth Kit."""

    def __init__(self, fs, name, description, include_deleted=False):
        super().__init__(name, description)
        self.fs = fs
        self.include_deleted = include_deleted

    def _list(self, path, entry):
        import pytsk3
        if entry is not None and entry.handle is not None:
            directory = entry.handle.as_directory()
        else:
            directory = self.fs.open_dir(path='/' + path)
        out = []
        for f in directory:
            name = f.info.name.name.decode('utf-8', 'replace')
            meta = f.info.meta
            if name in ('.', '..') or meta is None:
                continue
            if not path and name in NTFS_METADATA:
                continue
            deleted = bool(f.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            if deleted and not self.include_deleted:
                continue
            is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
            out.append(Entry(
                path=f'{path}/{name}' if path else name,
                is_dir=is_dir,
                size=0 if is_dir else meta.size,
                created=meta.crtime or None,
                modified=meta.mtime or None,
                accessed=meta.atime or None,
                deleted=deleted,
                handle=f,
                inode=meta.addr,
            ))
        return out

    def read_at(self, entry, offset, size):
        return entry.handle.read_random(offset, size)


class EwfLogicalVolume(Volume):
    """Files inside a logical evidence file (.L01 / .Lx01), read with libewf."""

    search_roots = True

    def __init__(self, root_entry, name, description):
        super().__init__(name, description)
        self.root_entry = root_entry

    def _resolve(self, path):
        node = self.root_entry
        walked = ''
        for part in [p for p in path.split('/') if p]:
            match = next((e for e in self.listdir(walked) if e.name.lower() == part.lower()), None)
            if match is None:
                raise FileNotFoundError(f'no such folder: {path}')
            node, walked = match.handle, match.path
        return node

    def _list(self, path, entry):
        node = entry.handle if entry is not None else self._resolve(path)
        out = []
        for sub in node.sub_file_entries:
            name = sub.name or '_'
            is_dir = sub.number_of_sub_file_entries > 0
            out.append(Entry(
                path=f'{path}/{name}' if path else name,
                is_dir=is_dir,
                size=0 if is_dir else sub.size,
                created=sub.get_creation_time_as_integer() or None,
                modified=sub.get_modification_time_as_integer() or None,
                accessed=sub.get_access_time_as_integer() or None,
                handle=sub,
            ))
        return out

    def read_at(self, entry, offset, size):
        return entry.handle.read_buffer_at_offset(size, offset)


MAX_ZIP_ENTRIES = 2_000_000


class ZipVolume(Volume):
    """Files inside a ZIP archive, such as a triage collection: Velociraptor offline collector,
    KAPE or CyLR output zipped. Read in place, never unpacked to disk.

    Names are paths in the archive; a name such as ../../x stays a name and cannot lead
    anywhere. Velociraptor percent-encodes names (C%3A, %25): decoded for its collections
    only. Archive times are local times of an unknown zone, so they are not reported. A file
    is never read past the size the archive gives for it."""

    search_roots = True

    def __init__(self, path, password=None):
        import pyzipper
        super().__init__('zip', f'zip archive {os.path.basename(path)}')
        self._zip = pyzipper.AESZipFile(path, 'r')
        if password:
            self._zip.setpassword(password.encode('utf-8'))
        self._current = None        # (entry path, open member stream) for read_at
        infos = self._zip.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError(f'{len(infos):,} entries in the archive, more than {MAX_ZIP_ENTRIES:,}')
        velociraptor = any(i.filename.startswith('uploads/') or '%3A' in i.filename for i in infos)
        self.encrypted = any(i.flag_bits & 0x1 for i in infos)
        self._children = {'': {}}
        for info in infos:
            parts = [p for p in info.filename.replace('\\', '/').split('/') if p not in ('', '.')]
            if velociraptor:
                parts = [unquote(p).replace('/', '_').replace('\\', '_') or '_' for p in parts]
            if not parts:
                continue
            folder = ''
            for part in parts[:-1]:
                path_ = f'{folder}/{part}' if folder else part
                siblings = self._children.setdefault(folder, {})
                if part.lower() not in siblings:
                    siblings[part.lower()] = Entry(path=path_, is_dir=True)
                    self._children.setdefault(path_, {})
                folder = siblings[part.lower()].path
            name, siblings = parts[-1], self._children.setdefault(folder, {})
            if name.lower() in siblings:
                if not info.is_dir():
                    self.warnings.append(f'{info.filename}: the name is in the archive twice; the first is used')
                continue
            path_ = f'{folder}/{name}' if folder else name
            if info.is_dir():
                siblings[name.lower()] = Entry(path=path_, is_dir=True)
                self._children.setdefault(path_, {})
            else:
                siblings[name.lower()] = Entry(path=path_, is_dir=False, size=info.file_size, handle=info)

    def _list(self, path, entry):
        return list(self._children.get(path, {}).values())

    def _member(self, entry):
        """An open stream of one archive member; unreadable members become OSError, so that
        one of them is a file error and not the end of the run."""
        try:
            return self._zip.open(entry.handle)
        except NotImplementedError as e:        # e.g. Deflate64 from Windows Explorer
            raise OSError(f'{entry.path}: {e}') from e
        except (RuntimeError, ValueError, EOFError, zlib.error) as e:   # password, damaged entry
            raise OSError(f'{entry.path}: cannot be read from the archive ({e})') from e

    def _read(self, stream, size, entry):
        try:
            return stream.read(size)
        except (RuntimeError, ValueError, EOFError, zlib.error, OSError) as e:
            raise OSError(f'{entry.path}: damaged in the archive ({e})') from e

    def chunks(self, entry):
        with self._member(entry) as f:
            remaining = entry.size
            while remaining > 0:
                data = self._read(f, min(CHUNK, remaining), entry)
                if not data:
                    break
                remaining -= len(data)
                yield data

    def read_at(self, entry, offset, size):
        if self._current is None or self._current[0] != entry.path:
            if self._current is not None:
                self._current[1].close()
            self._current = (entry.path, self._member(entry))
        stream = self._current[1]
        try:
            stream.seek(offset)
        except (RuntimeError, ValueError, EOFError, zlib.error, OSError) as e:
            raise OSError(f'{entry.path}: damaged in the archive ({e})') from e
        return self._read(stream, max(0, min(size, entry.size - offset)), entry)


class _EntryStream(io.RawIOBase):
    """Raw, seekable reader over Volume.read_at; Volume.open wraps it in a buffer."""

    def __init__(self, volume, entry):
        super().__init__()
        self._volume, self._entry, self._pos = volume, entry, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self._pos

    def seek(self, offset, whence=io.SEEK_SET):
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._entry.size}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def readinto(self, buffer):
        size = min(len(buffer), self._entry.size - self._pos)
        if size <= 0:
            return 0
        data = self._volume.read_at(self._entry, self._pos, size)
        buffer[:len(data)] = data
        self._pos += len(data)
        return len(data)
