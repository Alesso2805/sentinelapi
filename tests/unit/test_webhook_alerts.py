"""CRITICAL events reach a webhook, once per target and threat per cooldown, off the request path."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import structlog

from sentinelapi.alerts.webhook import WebhookAlerter
from sentinelapi.detectors.fingerprint import build_fingerprint
from sentinelapi.domain.entities import SecurityEvent, ThreatLevel, ThreatType
from sentinelapi.privacy import Pseudonymizer
from tests.fakes import FakeClock

PSEUDONYMIZE = Pseudonymizer("test-key")


def event(level: ThreatLevel = ThreatLevel.CRITICAL, source: str = "198.51.100.200") -> SecurityEvent:
    return SecurityEvent(
        threat_type=ThreatType.JWT_REPLAY,
        threat_level=level,
        fingerprint=build_fingerprint(source, "test"),
        path="/auth/refresh",
        detail="a single-use token was presented again",
        occurred_at=1_800_000_000.0,
    )


class Receiver:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.attempts = 0
        self.delivered: list[dict[str, str]] = []

    async def __call__(self, url: str, payload: dict[str, str]) -> None:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise ConnectionError("the receiver is down")
        self.delivered.append(payload)


async def no_wait(seconds: float) -> None:
    return None


def alerter(receiver: Receiver, clock: FakeClock | None = None) -> WebhookAlerter:
    return WebhookAlerter(
        "https://hooks.example.test/x", PSEUDONYMIZE, send=receiver, sleep=no_wait, clock=clock or FakeClock()
    )


async def delivered(alerts: WebhookAlerter) -> None:
    alerts.start()
    await alerts.close()  # drains the queue


async def test_only_critical_events_are_sent() -> None:
    receiver = Receiver()
    alerts = alerter(receiver)
    await alerts(event(ThreatLevel.HIGH))
    await alerts(event(ThreatLevel.CRITICAL))
    await delivered(alerts)
    assert len(receiver.delivered) == 1
    assert "CRITICAL jwt replay on /auth/refresh" in receiver.delivered[0]["text"]


async def test_one_alert_per_source_and_threat_per_cooldown() -> None:
    receiver, clock = Receiver(), FakeClock()
    alerts = alerter(receiver, clock)
    for _ in range(50):
        await alerts(event())
    await alerts(event(source="198.51.100.201"))  # another source
    clock.advance(601)
    await alerts(event())  # the same source, after the cooldown
    await delivered(alerts)
    assert len(receiver.delivered) == 3


async def test_an_attack_on_one_account_from_many_sources_is_one_alert() -> None:
    """Credential stuffing comes from a new address every time, so its alerts are held back
    per account, not per source."""
    receiver = Receiver()
    alerts = alerter(receiver)

    def stuffing(source: str, account: str = "account-id-1") -> SecurityEvent:
        return replace(
            event(source=source),
            threat_type=ThreatType.BRUTE_FORCE,
            path="/auth/login",
            detail="account locked, 15 attempts against it in this window",
            subject=account,
        )

    for i in range(20):
        await alerts(stuffing(f"198.51.100.{i}"))
    await alerts(stuffing("198.51.100.0", account="account-id-2"))  # another account
    await delivered(alerts)
    assert len(receiver.delivered) == 2
    text = receiver.delivered[0]["text"]
    assert f"Account {PSEUDONYMIZE('account-id-1')}" in text and "account-id-1" not in text


async def test_a_failing_receiver_is_retried_with_backoff() -> None:
    receiver = Receiver(failures=2)
    alerts = alerter(receiver)
    await alerts(event())
    await delivered(alerts)
    assert (receiver.attempts, len(receiver.delivered)) == (3, 1)


async def test_a_receiver_that_stays_down_is_logged_and_given_up() -> None:
    receiver = Receiver(failures=99)
    alerts = alerter(receiver)
    await alerts(event())
    with structlog.testing.capture_logs() as logs:
        await delivered(alerts)
    assert receiver.attempts == 4  # the first try and three retries
    assert [(e["event"], e["attempts"]) for e in logs] == [("alert_failed", 4)]


async def test_reporting_never_waits_on_the_network() -> None:
    release = asyncio.Event()

    async def slow(url: str, payload: dict[str, str]) -> None:
        await release.wait()

    alerts = WebhookAlerter("https://hooks.example.test/x", PSEUDONYMIZE, send=slow, sleep=no_wait)
    alerts.start()
    await asyncio.wait_for(alerts(event()), timeout=0.1)  # returns at once
    release.set()
    await alerts.close()


async def test_the_message_names_the_source_by_its_keyed_hash_only() -> None:
    text = alerter(Receiver()).message(event())["text"]
    assert "198.51.100.200" not in text
    source = PSEUDONYMIZE(event().fingerprint.key)
    assert source is not None and source in text
