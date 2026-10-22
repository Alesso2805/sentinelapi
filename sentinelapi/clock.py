"""The only module that reads the time (AR-16).

Everything else receives a `Clock`, so windows, expiries and timestamps
can be tested with a clock that moves only when the test says so.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Wall-clock seconds since the epoch: timestamps and token expiry."""
        ...

    def monotonic(self) -> float:
        """Seconds that never go backwards: windows and time-to-live."""
        ...


class SystemClock:
    def now(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()


SYSTEM_CLOCK = SystemClock()
