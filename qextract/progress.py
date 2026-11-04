"""A sign of life on the console: when nothing has been printed for a while, say what qextract
is doing and for how long, so a long step (a raw drive search, $MFT, a big log) does not look
like a hang. Console only: these lines do not go into qextract.log."""

import contextlib
import threading
import time


class Heartbeat:
    def __init__(self, write=print, quiet_seconds=10.0, clock=time.monotonic):
        self._write, self._quiet, self._clock = write, quiet_seconds, clock
        self._lock = threading.Lock()
        self._what, self._since = 'starting', clock()
        self._last = clock()
        self._paused = False
        self._stop = threading.Event()
        self._thread = None

    def printed(self):
        """Something was printed: the quiet time starts again."""
        with self._lock:
            self._last = self._clock()

    def status(self, what):
        """What is being done now (a short phrase: 'searching C: for Avast Antivirus'). The time
        counts from the start of the step: 'reading $MFT: 45% ...' after 'reading $MFT: 40% ...'
        is the same step (the part before ':')."""
        with self._lock:
            if what.split(':', 1)[0] != self._what.split(':', 1)[0]:
                self._since = self._clock()
            self._what = what

    def pause(self, paused=True):
        """While the user is asked something, no line may break the question."""
        with self._lock:
            self._paused = paused
            self._last = self._clock()

    def tick(self):
        """One check; returns the line written or None (the thread calls it every second)."""
        with self._lock:
            now = self._clock()
            if self._paused or now - self._last < self._quiet:
                return None
            line = f'  ... {self._what} ({int(now - self._since)} s)'
            self._last = now
        self._write(line)
        return line

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name='qextract-heartbeat', daemon=True)
            self._thread.start()
        return self

    def _run(self):
        while not self._stop.wait(1.0):
            with contextlib.suppress(Exception):   # a broken console must not stop the collection
                self.tick()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
