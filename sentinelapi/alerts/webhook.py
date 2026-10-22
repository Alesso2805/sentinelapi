"""A webhook for CRITICAL events: a Slack-compatible message, sent off the
request path, at most one per fingerprint and threat per cooldown, retried
with backoff.

An operator should not have to watch the logs to hear that a stolen token
was replayed. But an attack produces many identical events, and a chat
channel that gets one message per request is one nobody reads, so repeats
from the same source are held back for the cooldown.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import urllib.request
from collections.abc import Awaitable, Callable, Sequence

from sentinelapi.clock import SYSTEM_CLOCK, Clock
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel
from sentinelapi.logging_config import security_logger
from sentinelapi.privacy import Pseudonymizer

Send = Callable[[str, dict[str, str]], Awaitable[None]]
Sleep = Callable[[float], Awaitable[None]]


async def post_json(url: str, payload: dict[str, str]) -> None:
    """The standard library in a thread: no HTTP client to depend on for one POST."""

    def post() -> None:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5):  # raises on a non-2xx answer
            pass

    await asyncio.to_thread(post)


class WebhookAlerter:
    def __init__(
        self,
        url: str,
        pseudonymize: Pseudonymizer,
        *,
        cooldown_seconds: float = 600,
        backoff_seconds: Sequence[float] = (1, 2, 4),
        send: Send = post_json,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = SYSTEM_CLOCK,
    ) -> None:
        self._url = url
        self._pseudonymize = pseudonymize
        self._cooldown = cooldown_seconds
        self._backoff = tuple(backoff_seconds)
        self._send = send
        self._sleep = sleep
        self._clock = clock
        self._last_sent: dict[tuple[str, str], float] = {}
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=1_000)
        self._sender: asyncio.Task[None] | None = None

    async def __call__(self, event: SecurityEvent) -> None:
        """Never waits on the network: the request goes on at once."""
        if event.threat_level is not ThreatLevel.CRITICAL:
            return
        now = self._clock.monotonic()
        key = (event.fingerprint.key, event.threat_type.value)
        if now - self._last_sent.get(key, -self._cooldown) < self._cooldown:
            return
        self._last_sent[key] = now
        self._forget_old(now)
        with contextlib.suppress(asyncio.QueueFull):
            self._queue.put_nowait(event)

    def start(self) -> None:
        self._sender = asyncio.create_task(self._send_forever())

    async def close(self) -> None:
        """Gives what is queued a few seconds to go out, then stops."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._queue.join(), timeout=5)
        if self._sender is not None:
            self._sender.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sender

    def message(self, event: SecurityEvent) -> dict[str, str]:
        """Slack's incoming-webhook shape, which many chat tools accept. The
        source appears as its keyed hash, as in the audit trail (ADR-0006)."""
        threat = event.threat_type.value.replace("_", " ")
        source = self._pseudonymize(event.fingerprint.key)
        return {
            "text": (
                f":rotating_light: SentinelAPI, CRITICAL {threat} on {event.path}: {event.detail}. "
                f"Source {source}; repeats from it are held back for {int(self._cooldown // 60)} minutes."
            )
        }

    async def _send_forever(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._deliver(event)
            finally:
                self._queue.task_done()

    async def _deliver(self, event: SecurityEvent) -> None:
        payload = self.message(event)
        for attempt, wait in enumerate((*self._backoff, None), start=1):
            try:
                await self._send(self._url, payload)
                return
            except Exception:
                if wait is None:
                    await security_logger.aexception(
                        "alert_failed", threat_type=event.threat_type.value, attempts=attempt
                    )
                    return
                await self._sleep(wait)

    def _forget_old(self, now: float) -> None:
        if len(self._last_sent) > 10_000:
            self._last_sent = {k: t for k, t in self._last_sent.items() if now - t < self._cooldown}
