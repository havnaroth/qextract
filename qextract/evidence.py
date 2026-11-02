"""Open the input: a folder, a raw image (.dd/.raw/.img, split .001), EWF (.E01/.Ex01),
logical EWF (.L01/.Lx01) or a virtual disk (.vhd/.vhdx, .vmdk)."""

import os
import re

import pytsk3

from .fs import DirVolume, EwfLogicalVolume, TskVolume, ZipVolume, final_path

EWF_SIGNATURES = (b'EVF\x09\x0d\x0a\xff\x00', b'EVF2\x0d\x0a\x81\x00')
EWF_LOGICAL_SIGNATURES = (b'LVF\x09\x0d\x0a\xff\x00', b'LEF2\x0d\x0a\x81\x00')
VHDX_SIGNATURE = b'vhdxfile'
VHD_SIGNATURE = b'conectix'
VMDK_SPARSE_SIGNATURES = (b'KDMV', b'COWD')     # hosted sparse / stream-optimized, ESX sparse
VMDK_DESCRIPTOR = b'# Disk D'                   # "# Disk DescriptorFile": split and flat disks
BITLOCKER_SIGNATURE = b'-FVE-FS-'
ZIP_SIGNATURES = (b'PK\x03\x04', b'PK\x05\x06')   # a ZIP with files, an empty ZIP


class VhdiImage(pytsk3.Img_Info):
    """VHD / VHDX, including differencing disks such as Hyper-V checkpoints (.avhdx).

    A differencing disk stores the full path its parent had on the machine that made it.
    That path comes from the evidence, so it is never opened as such: only a file of the same
    name next to the child is used. A crafted disk must not make qextract (maybe running as
    administrator) read another disk of this machine, e.g. one from another case."""

    def __init__(self, path):
        self._files = []
        try:
            self._handle = self._open(path)
        except BaseException:
            self.close()
            raise
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def _open(self, path, depth=0):
        import pyvhdi
        handle = pyvhdi.file()
        handle.open(path, 'r')      # the evidence is only ever read
        self._files.append(handle)
        if handle.parent_identifier is not None:
            if depth > 16:
                raise RuntimeError('differencing disk chain is too long')
            stored = handle.parent_filename or ''
            name = stored.replace('/', '\\').rsplit('\\', 1)[-1]
            if not name or name in ('.', '..') or ':' in name:
                raise RuntimeError(f'{os.path.basename(path)}: parent disk "{stored}" has no usable file name')
            parent = os.path.join(os.path.dirname(os.path.abspath(path)), name)
            if not os.path.isfile(parent):
                raise RuntimeError(f'{os.path.basename(path)} is a differencing disk; put its parent '
                                   f'"{name}" next to it')
            handle.set_parent(self._open(parent, depth + 1))
        return handle

    def close(self):
        for f in reversed(self._files):
            f.close()

    def read(self, offset, size):
        return self._handle.read_buffer_at_offset(size, offset)

    def get_size(self):
        return self._handle.media_size


class VmdkImage(pytsk3.Img_Info):
    """VMware VMDK: sparse or flat, one file or split (-s001 / -f001), stream-optimized (OVA
    exports), and snapshots (-000001.vmdk; the parent is looked up next to the child).

    The descriptor names its extent files and its parent. It comes from the evidence, so only
    plain file names next to the descriptor are accepted: a crafted descriptor must not make
    qextract (maybe running as administrator) read some other file on this machine as a disk.
    qextract opens the extent files itself (read-only) and hands them to libvmdk, which never
    opens a file by a name from the evidence. A one-file sparse disk is its own extent, so it
    still opens after being renamed (its descriptor keeps the original name)."""

    def __init__(self, path):
        self._files = []
        self._objects = []          # extent files opened here, kept open while the disk is
        try:
            self._handle = self._open(os.path.abspath(path))     # libvmdk needs Windows paths
        except BaseException:
            self.close()
            raise
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    @staticmethod
    def _next_to(path, name, what):
        if not name or name in ('.', '..') or any(c in name for c in '\\/:'):
            raise RuntimeError(f'{os.path.basename(path)}: {what} "{name}" is not a file name next to it - refused')
        return os.path.join(os.path.dirname(path), name)

    def _open(self, path, depth=0):
        import pyvmdk
        handle = pyvmdk.handle()
        handle.open(path, 'r')
        self._files.append(handle)
        with open(path, 'rb') as f:
            embedded = f.read(4) in VMDK_SPARSE_SIGNATURES
        extents = list(handle.extent_descriptors)
        if embedded and len(extents) == 1:
            extent_paths = [path]       # one-file sparse disk: the file is its own data
        else:
            # every name the descriptor gives is checked before anything is opened through it
            extent_paths = [self._next_to(path, e.filename, 'data file') for e in extents]
            for e, p in zip(extents, extent_paths, strict=True):
                if not os.path.isfile(p):
                    raise RuntimeError(f'{os.path.basename(path)}: put its data file "{e.filename}" next to it')
        parent = None
        if handle.parent_filename:
            if depth > 16:
                raise RuntimeError('snapshot chain is too long')
            parent = self._next_to(path, handle.parent_filename, 'parent disk')
            if not os.path.isfile(parent):
                raise RuntimeError(f'{os.path.basename(path)} is a snapshot; put its parent '
                                   f'"{handle.parent_filename}" next to it')
        objects = [open(p, 'rb') for p in extent_paths]  # noqa: SIM115 - closed in close()
        self._objects += objects
        handle.open_extent_data_files_as_file_objects(objects)
        if parent:
            handle.set_parent(self._open(parent, depth + 1))
        return handle

    def close(self):
        for f in reversed(self._files):
            f.close()
        for f in self._objects:
            f.close()

    def read(self, offset, size):
        return self._handle.read_buffer_at_offset(size, offset)

    def get_size(self):
        return self._handle.media_size


def _ewf_header(path):
    """(signature, segment number, set identifier) of an EWF segment file, or None."""
    try:
        with open(path, 'rb') as f:
            head = f.read(32)
    except OSError:
        return None
    if head[:8] in EWF_SIGNATURES[:1] + EWF_LOGICAL_SIGNATURES[:1] and len(head) >= 13:
        return head[:8], int.from_bytes(head[9:11], 'little'), b''         # EWF1: E01, L01
    if head[:8] in EWF_SIGNATURES[1:] + EWF_LOGICAL_SIGNATURES[1:] and len(head) >= 32:
        return head[:8], int.from_bytes(head[12:16], 'little'), head[16:32]   # EWF2: set id
    return None


def segments_by_header(path, limit=10000):
    """The segments of the image `path` belongs to, found by their headers among the files of
    its folder - whatever they are called (renamed evidence: case.chuj, case.002.bin, ...).
    -> paths ordered by segment number. Raises RuntimeError when a number is missing or when
    two files claim the same number (two images in one folder: refusing beats guessing)."""
    own = _ewf_header(path)
    if own is None:
        return [path]
    signature, _number, set_id = own
    by_number = {}
    folder = os.path.dirname(os.path.abspath(path))
    with os.scandir(folder) as it:
        for n, entry in enumerate(it):
            if n >= limit:
                break
            if not entry.is_file(follow_symlinks=False):
                continue
            header = _ewf_header(entry.path)
            if header and header[0] == signature and header[2] == set_id:
                by_number.setdefault(header[1], []).append(entry.path)
    if set(by_number) <= {1}:
        return [path]       # only first segments: separate one-file images side by side
    doubles = {k: v for k, v in by_number.items() if len(v) > 1}
    if doubles:
        number, paths = min(doubles.items())
        raise RuntimeError(f'segment {number} of {os.path.basename(path)} is in the folder more than once '
                           f'({", ".join(os.path.basename(p) for p in paths)}): two images in one folder? '
                           'Put each image in its own folder')
    numbers = sorted(by_number)
    # segment numbers come from the evidence (up to 2**32): never walk the whole range,
    # only up to the first ten gaps
    missing, k = [], 1
    while numbers and k <= numbers[-1] and len(missing) < 10:
        if k not in by_number:
            missing.append(k)
        k += 1
    if missing:
        raise RuntimeError(f'{os.path.basename(path)}: segment(s) {", ".join(map(str, missing[:10]))} '
                           'not found in its folder')
    return [by_number[k][0] for k in numbers]


def ewf_segments(path):
    """All segments of an E01/L01. libewf finds .E02... by the extension; when that finds
    fewer segments than the headers in the folder show (renamed or mixed-up names), the
    segments found by header are used."""
    import pyewf
    try:
        named, by_name = pyewf.glob(path), True
    except OSError:
        named, by_name = [path], False
    try:
        found = segments_by_header(path)
    except RuntimeError:
        if by_name and len(named) > 1:
            return named        # the names already give a full set: keep it
        raise
    return found if len(found) > len(named) else named


class EwfImage(pytsk3.Img_Info):
    def __init__(self, path):
        import pyewf
        self._handle = pyewf.handle()
        self._handle.open(ewf_segments(path), 'r')
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._handle.close()

    def read(self, offset, size):
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self):
        return self._handle.get_media_size()


class SplitRawImage(pytsk3.Img_Info):
    """image.001, image.002, ... (or .000, .001, ...) read as one disk."""

    def __init__(self, paths):
        self._files = [open(p, 'rb') for p in paths]  # noqa: SIM115 - open as long as the image, see close()
        self._sizes = [os.path.getsize(p) for p in paths]
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        for f in self._files:
            f.close()

    def read(self, offset, size):
        out = bytearray()
        for f, length in zip(self._files, self._sizes, strict=True):
            if offset >= length:
                offset -= length
                continue
            f.seek(offset)
            out += f.read(min(size - len(out), length - offset))
            offset = 0
            if len(out) >= size:
                break
        return bytes(out)

    def get_size(self):
        return sum(self._sizes)


def _split_segments(path):
    m = re.match(r'^(.*\.)(\d{3})$', path)
    if not m or int(m.group(2)) > 1:
        return None
    segments = []
    n = int(m.group(2))
    while os.path.isfile(f'{m.group(1)}{n:03d}'):
        segments.append(f'{m.group(1)}{n:03d}')
        n += 1
    return segments if len(segments) > 1 else None


def _signature(path):
    with open(path, 'rb') as f:
        head = f.read(8)
        tail = b''
        if head != VHD_SIGNATURE and os.path.getsize(path) >= 512:
            f.seek(-512, os.SEEK_END)    # a fixed VHD only has the footer
            tail = f.read(8)
    return head, tail


def _first_line(error):
    """The useful start of a libyal error ('pyewf_glob: unable to glob filenames. ...')."""
    return str(error).split('. ')[0].strip()[:160]


def open_image(path):
    if not path.startswith('\\\\.\\') and os.path.getsize(path) == 0:
        raise RuntimeError(f'{os.path.basename(path)} is empty')
    head, tail = _signature(path)
    kind, opener = None, None
    if head in EWF_SIGNATURES:
        kind, opener = 'EWF', EwfImage
    elif head == VHDX_SIGNATURE:
        kind, opener = 'VHDX', VhdiImage
    elif VHD_SIGNATURE in (head, tail):
        kind, opener = 'VHD', VhdiImage
    elif head[:4] in VMDK_SPARSE_SIGNATURES or head == VMDK_DESCRIPTOR:
        kind, opener = 'VMDK', VmdkImage
    if opener:
        try:
            return opener(path), kind
        except OSError as e:    # the library's own message, shortened: damaged or not this format
            raise RuntimeError(f'{os.path.basename(path)} looks like {kind} but cannot be opened '
                               f'(damaged or incomplete?): {_first_line(e)}') from e
    segments = _split_segments(path)
    if segments:
        return SplitRawImage(segments), f'raw, {len(segments)} segments'
    return pytsk3.Img_Info(path), 'raw'


_FS_TYPES = {int(getattr(pytsk3, n)): n[len('TSK_FS_TYPE_'):].lower()
             for n in dir(pytsk3)
             if n.startswith('TSK_FS_TYPE_') and not n.endswith(('_DETECT', '_UNSUPP', '_ENUM'))}


def _fs_type(fs):
    return _FS_TYPES.get(int(fs.info.ftype), f'fs{int(fs.info.ftype)}')


def drive_letter(path):
    """'E:', 'E:\\' or 'e:/' -> 'E', anything else -> None."""
    m = re.match(r'^([A-Za-z]):[\\/]?$', path.strip())
    return m.group(1).upper() if m else None


def _volumes_on_disk(disk_number):
    """Drive letters whose volume lies (partly) on physical disk N."""
    return [letter for letter, disks in _disks_by_letter().items() if disk_number in disks]


def _disks_by_letter():
    """{drive letter: physical disk numbers its volume lies on}"""
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel32.DeviceIoControl.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                         ctypes.c_void_p)
    ioctl_volume_get_volume_disk_extents, open_existing, share_all = 0x560000, 3, 7
    found = {}
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if not os.path.exists(f'{letter}:\\'):
            continue
        # no access rights asked: enough for this query, works without admin, touches nothing
        h = kernel32.CreateFileW(f'\\\\.\\{letter}:', 0, share_all, None, open_existing, 0, None)
        if h in (None, wintypes.HANDLE(-1).value):
            continue
        try:
            buf, got = ctypes.create_string_buffer(8 + 24 * 32), wintypes.DWORD()
            if kernel32.DeviceIoControl(h, ioctl_volume_get_volume_disk_extents, None, 0, buf, len(buf),
                                        ctypes.byref(got), None):
                count = int.from_bytes(buf.raw[0:4], 'little')
                found[letter] = {int.from_bytes(buf.raw[8 + 24 * i:12 + 24 * i], 'little')
                                 for i in range(min(count, 32))}
        finally:
            kernel32.CloseHandle(h)
    return found


_PHYSICAL_DRIVE = re.compile(r'^\\\\\.\\PhysicalDrive(\d+)$', re.IGNORECASE)


def system_drive():
    return (os.environ.get('SYSTEMDRIVE') or 'C:')[0].upper()


def is_live(path):
    """The running Windows itself: its system drive, or the physical disk that holds it."""
    letter = drive_letter(path)
    if letter:
        return letter == system_drive()
    m = _PHYSICAL_DRIVE.match(path.strip())
    return bool(m) and os.name == 'nt' and system_drive() in _volumes_on_disk(int(m.group(1)))


def volume_read_only(letter):
    """True / False whether drive X: is mounted read-only, None when it cannot be told."""
    if os.name != 'nt':
        return None
    import ctypes
    from ctypes import wintypes
    flags = wintypes.DWORD()
    ok = ctypes.windll.kernel32.GetVolumeInformationW(f'{letter}:\\', None, 0, None, None,
                                                      ctypes.byref(flags), None, 0)
    return bool(flags.value & 0x80000) if ok else None     # FILE_READ_ONLY_VOLUME


def input_locations(path):
    """Where the input lives, as resolved paths (links, subst and mapped drives followed): the
    output may not be written there, the evidence is only ever read. A folder or image ->
    itself; a drive letter -> the whole drive; \\\\.\\PhysicalDriveN -> every drive on it.
    The caller leaves out a live system (see is_live): its results may go to its own drive."""
    letter = drive_letter(path)
    if letter:
        roots = [f'{letter}:\\']
    else:
        m = _PHYSICAL_DRIVE.match(path.strip())
        if m:
            roots = [f'{x}:\\' for x in _volumes_on_disk(int(m.group(1)))] if os.name == 'nt' else []
        elif path.startswith('\\\\.\\'):
            roots = []      # another device: no file system path to compare with
        else:
            roots = [os.path.abspath(path)]
    return [final_path(r) or os.path.abspath(r) for r in roots if os.path.exists(r)]


def _open_drive(letter, include_deleted, log):
    """A mounted or live drive read as a raw volume: no file locks or ACLs, needs admin."""
    device = f'\\\\.\\{letter}:'
    fs = pytsk3.FS_Info(pytsk3.Img_Info(device))
    fstype = _fs_type(fs)
    log(f'Drive {letter}: read as a raw volume ({device}, {fstype})')
    volume = TskVolume(fs, f'{letter}_{fstype}', f'drive {letter}: raw volume, {fstype}', include_deleted)
    volume.disk_root = f'{letter}:\\'
    return volume


def _open_zip(path, password, log):
    """A ZIP (triage collection) as a volume, with clear errors for a damaged archive, a
    missing or a wrong password."""
    import zipfile

    import pyzipper
    name = os.path.basename(path)
    try:
        volume = ZipVolume(path, password)
    except (zipfile.BadZipFile, pyzipper.BadZipFile, ValueError, EOFError, OSError) as e:
        raise RuntimeError(f'{name} looks like a ZIP but cannot be read (damaged or incomplete?): {e}') from e
    if volume.encrypted:
        if not password:
            raise RuntimeError(f'{name} is password protected: give the password with --zip-password')
        first = next(i for i in volume._zip.infolist() if i.flag_bits & 0x1)
        try:
            with volume._zip.open(first) as f:
                f.read(1)
        except (RuntimeError, zipfile.BadZipFile, pyzipper.BadZipFile) as e:
            raise RuntimeError(f'{name}: wrong --zip-password ({e})') from e
    files = sum(1 for i in volume._zip.infolist() if not i.is_dir())
    log(f'Zip: {path} ({files:,} files{", encrypted" if volume.encrypted else ""}; read in place)')
    return volume


def open_input(path, include_deleted=False, log=print, mode='auto', zip_password=None):
    """Return the volumes to search, each with a short name used in the output folder.

    mode: 'auto' reads a drive letter as a raw volume when possible (admin) and falls back to
    its files; 'raw' insists on the raw volume; 'files' always goes through the file system.
    A ZIP (triage collection) is read in place; zip_password for an encrypted one."""
    letter = drive_letter(path)
    if letter:
        if mode != 'files':
            try:
                return [_open_drive(letter, include_deleted, log)]
            except OSError as e:
                if mode == 'raw':
                    raise RuntimeError(f'cannot read drive {letter}: as a raw volume - '
                                       f'run as administrator ({e})') from e
                log(f'Drive {letter}: raw read not possible (run as administrator to also get locked and '
                    f'protected files) - reading its files instead')
        path = f'{letter}:\\'
    elif mode == 'raw' and os.path.isdir(path):
        raise RuntimeError('--mode raw needs a drive letter (for example E:) or an image file')

    if os.path.isdir(path):
        log(f'Folder: {path} (files, as the logged-on user can read them)')
        return [DirVolume(path)]

    if not path.startswith('\\\\.\\'):
        path = os.path.abspath(path)
        if _signature(path)[0][:4] in ZIP_SIGNATURES:
            return [_open_zip(path, zip_password, log)]
        if _signature(path)[0] in EWF_LOGICAL_SIGNATURES:
            import pyewf
            handle = pyewf.handle()
            try:
                handle.open(ewf_segments(path), 'r')
            except OSError as e:
                raise RuntimeError(f'{os.path.basename(path)} looks like L01 but cannot be opened '
                                   f'(damaged or incomplete?): {_first_line(e)}') from e
            log(f'Image: {path} (logical EWF)')
            volume = EwfLogicalVolume(handle.get_root_file_entry(), 'logical', 'logical evidence file')
            volume.handle = handle      # keeps the image open while its entries are in use
            return [volume]

    img, kind = open_image(path)
    log(f'Image: {path} ({kind}, {img.get_size():,} bytes)')

    candidates = []
    try:
        vs = pytsk3.Volume_Info(img)
        block = vs.info.block_size
        for part in vs:
            if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                desc = part.desc.decode('utf-8', 'replace')
                candidates.append((part.addr, part.start * block, desc))
    except OSError:
        pass
    if not candidates:
        candidates = [(0, 0, 'no partition table')]

    volumes = []
    for addr, offset, desc in candidates:
        try:
            fs = pytsk3.FS_Info(img, offset=offset)
        except OSError:
            try:
                signature = img.read(offset + 3, 8)
            except OSError:     # a partition that points past a damaged or cut image
                signature = b''
            if signature == BITLOCKER_SIGNATURE:
                log(f'  partition {addr} at {offset}: BitLocker - decrypt the image first, skipped')
            continue
        fstype = _fs_type(fs)
        name = f'p{addr}_{fstype}'
        log(f'  partition {addr} at offset {offset}: {fstype} ({desc}) -> {name}')
        volumes.append(TskVolume(fs, name, f'{desc}, offset {offset}, {fstype}', include_deleted))
    if not volumes:
        raise RuntimeError('no readable file system found in the image')
    return volumes
