from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(json_output: bool = True) -> None:
    """Call once at app startup. JSON output in production so security
    events are directly queryable in whatever log aggregator you use
    (CloudWatch, Datadog, ELK, ...); pretty console output in dev."""
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=logging.INFO)


security_logger = structlog.get_logger("sentinelapi.security")
