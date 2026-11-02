"""Writing into the output folder without being redirected.

qextract may run as administrator while other programs of the same user (or other users)
can write to the output folder. A planted symlink, junction or hard link there must not
turn an administrator's write into an overwrite of some other file. So every file is
- created new (exclusive create, never opened through an existing name: an existing file
  is removed first, which removes a hard link and not its target),
- under folders that are checked one by one to be plain folders, not links,
- and checked after opening, through its handle, to really be inside the output folder
  (this closes the race between the checks and the open).
"""

import contextlib
import os
import stat

from .fs import final_path as _final_path
from .fs import long_path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class UnsafeOutput(Exception):
    """The output folder or something in it is a link: refuse to write. Deliberately not
    an OSError, so it is never taken for one unreadable file: it stops the whole run."""


def is_link(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, 'st_file_attributes', 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def resolved(path):
    """path with every link, subst and mapped drive followed, also when it does not exist yet
    (resolved from its nearest existing parent)."""
    path, rest = os.path.abspath(path), []
    while not os.path.exists(path):
        path, tail = os.path.split(path)
        if not tail:
            break
        rest.insert(0, tail)
    return os.path.join(_final_path(path) or path, *rest)


def shown(path):
    """A resolved path as people write it: \\\\?\\C:\\x -> C:\\x, \\\\?\\UNC\\s\\x -> \\\\s\\x"""
    if path.startswith('\\\\?\\UNC\\'):
        return '\\\\' + path[8:]
    return path.removeprefix('\\\\?\\')


def within(path, root):
    """path is root or inside it (both resolved, compared without regard to case)"""
    p, r = path.rstrip('\\/').lower(), root.rstrip('\\/').lower()
    return p == r or p.startswith(r + os.sep)


class OutputFolder:
    """protected: resolved paths of the input. The input is only ever read, so nothing may be
    written there, checked before the folder is made and again on every file created."""

    def __init__(self, out, protected=()):
        self.out = os.path.abspath(out)
        self.protected = list(protected)
        self._check_protected(resolved(self.out))
        self.check_root()
        os.makedirs(self.out, exist_ok=True)
        self.check_root()
        self._final = _final_path(self.out).rstrip('\\').lower()

    def _check_protected(self, path):
        for root in self.protected:
            if within(path, root):
                raise UnsafeOutput(f'{shown(path)} is inside the input ({shown(root)}); the input is only ever read - '
                                   'choose an output folder on another drive or outside the input')

    def check_root(self):
        if os.path.lexists(self.out) and is_link(os.lstat(self.out)):
            raise UnsafeOutput(f'output folder is a link (symlink or junction): {self.out}')

    def _relative(self, path):
        rel = os.path.relpath(os.path.join(self.out, path), self.out)
        parts = rel.split(os.sep)
        if os.path.isabs(rel) or not parts or '..' in parts or rel == '.':
            raise UnsafeOutput(f'not inside the output folder: {path}')
        return parts

    def makedirs(self, rel_dir):
        """Create rel_dir under the output folder one folder at a time; refuse links."""
        current = self.out
        for part in self._relative(rel_dir):
            current = os.path.join(current, part)
            with contextlib.suppress(FileExistsError):
                os.mkdir(long_path(current))
            st = os.lstat(long_path(current))
            if is_link(st) or not stat.S_ISDIR(st.st_mode):
                raise UnsafeOutput(f'not a plain folder (link planted in the output?): {current}')
        return current

    def create(self, rel_path, text=False, replace=False, **open_args):
        """A new file at rel_path, opened for writing. replace: remove an existing file of
        that name first (reports rewritten with --force); otherwise an existing name fails."""
        parts = self._relative(rel_path)
        folder = self.makedirs(os.sep.join(parts[:-1])) if len(parts) > 1 else self.out
        self.check_root()
        path = long_path(os.path.join(folder, parts[-1]))
        if replace and os.path.lexists(path):
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode) and not is_link(st):
                raise UnsafeOutput(f'a folder is in the way of an output file: {path}')
            try:
                os.remove(path)     # the file or link itself, never a link's target
            except (IsADirectoryError, PermissionError):
                os.rmdir(path)      # a junction or directory symlink
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOINHERIT', 0)
        fd = os.open(path, flags, 0o600)
        try:
            final = _final_path(fd=fd).lower()
            if self._final and not final.startswith(self._final + '\\'):
                raise UnsafeOutput(f'output file ended up outside the output folder: {final}')
            self._check_protected(final or path)
            mode = 'w' if text else 'wb'
            return os.fdopen(fd, mode, **open_args)
        except BaseException:
            os.close(fd)
            raise
