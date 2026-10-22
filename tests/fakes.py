from __future__ import annotations

import time


class FakeClock:
    """A Clock that moves only when the test calls `advance`.

    Wall-clock time starts at the real time, so tokens signed with PyJWT,
    which checks `exp` against the real clock, stay valid in tests.
    """

    def __init__(self) -> None:
        self._now = time.time()
        self._monotonic = 1_000.0

    def now(self) -> float:
        return self._now

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: float) -> None:
        self._now += seconds
        self._monotonic += seconds
