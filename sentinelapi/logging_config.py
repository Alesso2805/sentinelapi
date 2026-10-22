from __future__ import annotations

import logging
import sys

import structlog

from sentinelapi.domain.entities import SecurityEvent
from sentinelapi.privacy import Pseudonymizer


def configure_logging(json_output: bool = True) -> None:
    """Call once at app startup. JSON output in production so security
    events are directly queryable in whatever log aggregator you use
    (CloudWatch, Datadog, ELK, ...); pretty console output in dev."""
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    # In JSON, a traceback is a field too, so a log aggregator keeps it with its line.
    renderer: list[structlog.typing.Processor] = (
        [structlog.processors.dict_tracebacks, structlog.processors.JSONRenderer()]
        if json_output
        else [structlog.dev.ConsoleRenderer()]
    )

    structlog.configure(
        processors=[*shared_processors, *renderer],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        # Not cached, so configuring again (a second app, a test) takes effect at once.
        cache_logger_on_first_use=False,
    )
    logging.basicConfig(level=logging.INFO)


security_logger = structlog.get_logger("sentinelapi.security")


async def log_event(event: SecurityEvent, pseudonymize: Pseudonymizer | None = None) -> None:
    """The first place every event goes, before any sink: one structured
    line, written at once, that a log aggregator can query. With a
    pseudonymizer (the installer always passes one), identifiers are its
    keyed hashes, as in the audit table (AR-13)."""
    fingerprint = pseudonymize(event.fingerprint.key) if pseudonymize else event.fingerprint.key
    await security_logger.awarning(
        "security_event",
        threat_type=event.threat_type.value,
        threat_level=event.threat_level.value,
        path=event.path,
        fingerprint=fingerprint,
        client=pseudonymize(event.fingerprint.ip) if pseudonymize else None,
        subject=pseudonymize(event.subject) if pseudonymize else None,
        detail=event.detail,
    )
