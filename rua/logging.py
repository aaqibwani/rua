"""Structured logging — one JSON object per line, to stdout.

The README promises "structured JSON to stdout". That has to hold for *every* line,
not just the ones this package emits: APScheduler, uvicorn, SQLAlchemy and psycopg
all log through the standard library, and a log shipper that hits one bare line
mid-stream will drop or mangle the batch. Stdlib records are therefore routed
through structlog's ``ProcessorFormatter`` so they come out in the same shape.

SECURITY.md lists credential disclosure as in scope. Two rules follow, and they
apply everywhere in this package:

* Never pass a credential, token, session cookie or password hash to a logger,
  including inside an exception being logged. ``SecretStr`` helps but is not a
  guarantee — ``.get_secret_value()`` returns a plain ``str``.
* Never log full report contents. Aggregate reports carry sending IP addresses,
  which may be personal data; log counts and identifiers instead.
"""

from __future__ import annotations

import logging
import sys

import structlog

# Loggers that are noisy at INFO and say nothing an operator needs.
_NOISY = ("uvicorn.access", "httpx", "httpcore", "apscheduler.executors.default")

# Applied to structlog events and to stdlib records alike, so both render the same
# keys in the same order.
_SHARED_PROCESSORS: list = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
    structlog.processors.StackInfoRenderer(),
]


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog and the stdlib root logger to emit JSON lines.

    Idempotent: existing root handlers are removed first, which matters because
    ``rua serve`` and ``rua scheduler`` both call this at start-up and uvicorn
    may have installed handlers of its own.
    """
    numeric = getattr(logging, level.upper(), logging.INFO)

    structlog.configure(
        processors=[
            *_SHARED_PROCESSORS,
            # Hands the event dict to the stdlib formatter below rather than
            # rendering here, so there is exactly one renderer for both sources.
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        # Records from libraries that know nothing about structlog get the same
        # treatment on the way in.
        foreign_pre_chain=_SHARED_PROCESSORS,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric)

    for name in _NOISY:
        logging.getLogger(name).setLevel(max(numeric, logging.WARNING))


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
