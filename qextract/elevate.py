"""Restart as administrator (UAC) when a live drive is read without admin rights."""

import ctypes
import os
import subprocess  # nosec B404 - only list2cmdline, nothing is run through it
import sys


def is_admin():
    if sys.platform != 'win32':
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def can_relaunch():
    """Only the built exe restarts itself: from source the elevated process would not find
    the package (UAC starts it with a fresh environment)."""
    return sys.platform == 'win32' and getattr(sys, 'frozen', False)


def relaunch(argv):
    """Start this exe again elevated with argv, in a new console window. -> True when it
    was started, False when UAC was cancelled or the start failed. Paths in argv must be
    absolute: the elevated process does not keep the working folder."""
    params = subprocess.list2cmdline(argv)
    shell = ctypes.windll.shell32
    shell.ShellExecuteW.restype = ctypes.c_void_p
    result = shell.ShellExecuteW(None, 'runas', sys.executable, params, os.getcwd(), 1)
    return (result or 0) > 32
