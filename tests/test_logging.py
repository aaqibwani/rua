"""Logging tests.

The README promises "structured JSON to stdout". A log shipper that hits one bare
line mid-stream drops or mangles the batch, so the promise has to hold for library
output too — APScheduler, uvicorn and SQLAlchemy all log through the standard
library and know nothing about structlog.
"""

from __future__ import annotations

import json
import logging

import pytest

from rua.logging import configure_logging, get_logger


@pytest.fixture(autouse=True)
def _restore_logging():
    """Undo handler surgery so one test cannot silence another."""
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        root.removeHandler(handler)
    for handler in saved_handlers:
        root.addHandler(handler)
    root.setLevel(saved_level)


def _lines(capsys) -> list[str]:
    return [line for line in capsys.readouterr().out.splitlines() if line.strip()]


def test_structlog_events_are_json(capsys) -> None:
    configure_logging("INFO")
    get_logger("rua.test").info("ingest_finished", reports=3, domains=60)

    (line,) = _lines(capsys)
    payload = json.loads(line)
    assert payload["event"] == "ingest_finished"
    assert payload["reports"] == 3
    assert payload["domains"] == 60
    assert payload["level"] == "info"
    assert payload["timestamp"].endswith("Z")


def test_stdlib_library_records_are_json_too(capsys) -> None:
    """APScheduler logs "Scheduler started" through the stdlib logger."""
    configure_logging("INFO")
    logging.getLogger("apscheduler.scheduler").info("Scheduler started")

    (line,) = _lines(capsys)
    payload = json.loads(line)
    assert payload["event"] == "Scheduler started"
    assert payload["logger"] == "apscheduler.scheduler"
    assert payload["level"] == "info"


def test_every_emitted_line_parses_as_json(capsys) -> None:
    configure_logging("INFO")
    get_logger("rua.test").warning("structlog_line")
    logging.getLogger("sqlalchemy.engine").warning("stdlib line with 'quotes' and \\backslash")
    logging.getLogger("rua.other").error("another")

    lines = _lines(capsys)
    assert len(lines) == 3
    for line in lines:
        json.loads(line)  # raises if any line is not a single JSON object


def test_level_filtering_is_applied(capsys) -> None:
    configure_logging("WARNING")
    log = get_logger("rua.test")
    log.info("should_not_appear")
    log.warning("should_appear")

    (line,) = _lines(capsys)
    assert json.loads(line)["event"] == "should_appear"


def test_configure_is_idempotent(capsys) -> None:
    # serve and scheduler both call it; uvicorn may add handlers of its own.
    configure_logging("INFO")
    configure_logging("INFO")
    get_logger("rua.test").info("once")

    assert len(_lines(capsys)) == 1, "duplicate handlers would double every line"


def test_exception_info_is_rendered_into_the_json(capsys) -> None:
    configure_logging("INFO")
    try:
        raise ValueError("boom")
    except ValueError:
        get_logger("rua.test").exception("operation_failed")

    (line,) = _lines(capsys)
    payload = json.loads(line)
    assert payload["event"] == "operation_failed"
    assert "ValueError" in payload.get("exception", "")
