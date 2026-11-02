"""Tells about a newer qextract release. It only asks GitHub which version is the newest:
nothing is downloaded or installed."""

import json
import re
import threading
import urllib.request

from . import __version__

LATEST = 'https://api.github.com/repos/havnaroth/qextract/releases/latest'
DOWNLOAD = 'https://github.com/havnaroth/qextract/releases/latest'
HOST = 'api.github.com'
TIMEOUT = 3
MAX_REPLY = 256 * 1024
_VERSION = re.compile(r'v?(\d{1,4})\.(\d{1,4})\.(\d{1,6})')


def parse(text):
    """'v0.1.10' -> (0, 1, 10); anything else -> None."""
    m = _VERSION.fullmatch(text) if isinstance(text, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


def latest_version(timeout=TIMEOUT):
    """Tag of the newest release, or None. The reply is not trusted: size-capped, and only a
    plain version number is accepted."""
    request = urllib.request.Request(LATEST, headers={'Accept': 'application/vnd.github+json',
                                                      'User-Agent': f'qextract/{__version__}'})
    with urllib.request.urlopen(request, timeout=timeout) as reply:   # noqa: S310  # nosec B310 - fixed https URL
        body = reply.read(MAX_REPLY + 1)
    if len(body) > MAX_REPLY:
        return None
    data = json.loads(body)
    tag = data.get('tag_name') if isinstance(data, dict) else None
    return tag if parse(tag) else None


class Check:
    """Runs in the background, so a slow or missing network never delays the work."""

    def __init__(self, current=__version__):
        self.current, self.latest, self.error = current, None, None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self.latest = latest_version()
        except Exception as e:  # noqa: BLE001 - offline, proxy, TLS, bad reply: all mean "no answer"
            self.error = type(e).__name__

    def result(self, wait=TIMEOUT):
        """-> (notice in capitals or '', summary text)."""
        self._thread.join(wait)
        if self._thread.is_alive() or not self.latest:
            return '', f'asked {HOST}: no answer'
        newest, current = parse(self.latest), parse(self.current)
        if current and newest > current:
            return (f'NEW VERSION AVAILABLE: QEXTRACT {".".join(map(str, newest))} '
                    f'(THIS ONE IS {self.current}). DOWNLOAD: {DOWNLOAD}',
                    f'asked {HOST}: {self.latest} available')
        return '', f'asked {HOST}: up to date ({self.latest})'
