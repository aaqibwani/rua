"""Ingestion: mailbox to rows.

Milestone 4's definition of done:

* a fixture report ingests into ``report`` and ``report_row``;
* ingesting it twice changes nothing;
* a corrupt report is recorded as a failure with the others still processed;
* the scheduler survives Graph returning 401 without crash-looping.

Each has a test named for it. The Graph client is faked throughout — these
exercise the pipeline, not Microsoft.
"""

from __future__ import annotations

import datetime as dt
import gzip
from pathlib import Path

from sqlalchemy import func, select

from rua import settings_store as store
from rua.graph import GraphError, MailAttachment, MailMessage
from rua.ingest import INGEST_CHECKPOINT, run_ingestion
from rua.models import IngestOutcome, IngestRun, Report, ReportRow, TlsReport, TlsResultRow

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeGraph:
    """A mailbox in a dict. Raises whatever the test asks it to."""

    def __init__(self, messages=None, attachments=None, list_error=None, attachment_error=None):
        self._messages = messages or []
        self._attachments = attachments or {}
        self._list_error = list_error
        self._attachment_error = attachment_error
        self.list_calls = 0

    def list_messages(self, mailbox, since=None, page_size=50):
        self.list_calls += 1
        if self._list_error:
            raise self._list_error
        for message in self._messages:
            if since is None or message.received > since:
                yield message

    def get_attachments(self, mailbox, message_id):
        if self._attachment_error:
            raise self._attachment_error
        return self._attachments.get(message_id, [])


def _message(msg_id: str, subject: str = "Report Domain: fabrikam.com", minutes: int = 0):
    return MailMessage(
        id=msg_id,
        subject=subject,
        received=dt.datetime(2026, 1, 2, 12, 0, tzinfo=dt.UTC) + dt.timedelta(minutes=minutes),
        has_attachments=True,
    )


def _attachment(name: str, content: bytes, content_type: str = "application/gzip"):
    return MailAttachment(name=name, content_type=content_type, content=content)


def _configure(session) -> None:
    store.set_value(session, store.GRAPH_TENANT_ID, "tenant-id")
    store.set_value(session, store.GRAPH_CLIENT_ID, "client-id")
    store.set_value(session, store.GRAPH_CLIENT_SECRET, "client-secret")
    store.set_value(session, store.GRAPH_MAILBOX, "dmarc-reports@example.com")


def _counts(session) -> tuple[int, int]:
    return (
        session.scalar(select(func.count()).select_from(Report)),
        session.scalar(select(func.count()).select_from(ReportRow)),
    )


# ── acceptance: a fixture report ingests ──


def test_aggregate_report_ingests(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(
        messages=[_message("m1")],
        attachments={
            "m1": [_attachment("report.xml.gz", gzip.compress(fixture("aggregate_google.xml")))]
        },
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.outcome is IngestOutcome.SUCCESS
    assert result.reports_parsed == 1
    reports, rows = _counts(clean_db)
    assert reports == 1
    assert rows == 3

    report = clean_db.scalar(select(Report))
    assert report.report_id == "7038306147107031780"
    assert report.org_name == "google.com"
    assert report.source_message_id == "m1"
    assert sum(r.count for r in report.rows) == 1697


def test_tls_report_ingests(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(
        messages=[_message("t1", subject="TLS Report")],
        attachments={
            "t1": [
                _attachment(
                    "tls.json.gz",
                    gzip.compress(fixture("tlsrpt_google.json")),
                    "application/tlsrpt+gzip",
                )
            ]
        },
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.reports_parsed == 1
    assert clean_db.scalar(select(func.count()).select_from(TlsReport)) == 1
    assert clean_db.scalar(select(func.count()).select_from(TlsResultRow)) == 3


# ── acceptance: ingesting twice changes nothing ──


def test_ingesting_the_same_message_twice_is_idempotent(clean_db) -> None:
    _configure(clean_db)
    attachments = {
        "m1": [_attachment("report.xml.gz", gzip.compress(fixture("aggregate_google.xml")))]
    }

    first = run_ingestion(clean_db, client=FakeGraph([_message("m1")], attachments))
    before = _counts(clean_db)

    # The checkpoint would normally stop a re-read; clear it so the second run
    # genuinely re-processes the message and idempotency is what saves us.
    store.delete(clean_db, INGEST_CHECKPOINT)
    second = run_ingestion(clean_db, client=FakeGraph([_message("m1")], attachments))

    assert first.reports_parsed == 1
    assert second.reports_parsed == 0
    assert second.duplicates_skipped == 1
    assert _counts(clean_db) == before


def test_the_checkpoint_stops_the_mailbox_being_re_read(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(
        messages=[_message("m1")],
        attachments={
            "m1": [_attachment("report.xml.gz", gzip.compress(fixture("aggregate_google.xml")))]
        },
    )
    run_ingestion(clean_db, client=graph)

    second = run_ingestion(clean_db, client=graph)

    assert second.messages_seen == 0, "the checkpoint should exclude an already-read message"


# ── acceptance: a corrupt report fails alone ──


def test_a_corrupt_report_does_not_stop_the_batch(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(
        messages=[
            _message("good", minutes=0),
            _message("bad", minutes=1),
            _message("also-good", minutes=2),
        ],
        attachments={
            "good": [_attachment("a.xml.gz", gzip.compress(fixture("aggregate_google.xml")))],
            "bad": [_attachment("b.xml.gz", gzip.compress(fixture("malformed_not_xml.xml")))],
            "also-good": [
                _attachment("c.xml.gz", gzip.compress(fixture("aggregate_microsoft.xml")))
            ],
        },
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.reports_parsed == 2, "both good reports must survive the bad one"
    assert result.reports_failed == 1
    assert result.outcome is IngestOutcome.PARTIAL
    assert _counts(clean_db)[0] == 2


def test_a_decompression_bomb_fails_alone(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(
        messages=[_message("bomb"), _message("good", minutes=1)],
        attachments={
            "bomb": [_attachment("bomb.xml.gz", gzip.compress(b"<" + b"\0" * (8 * 1024 * 1024)))],
            "good": [_attachment("a.xml.gz", gzip.compress(fixture("aggregate_google.xml")))],
        },
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.reports_parsed == 1
    assert result.reports_failed == 1
    assert _counts(clean_db)[0] == 1


# ── acceptance: the scheduler survives a 401 ──


def test_graph_401_is_recorded_not_raised(clean_db) -> None:
    """A crash here would take the scheduler down over an expired secret."""
    _configure(clean_db)
    graph = FakeGraph(list_error=GraphError("Graph rejected the token (401)."))

    result = run_ingestion(clean_db, client=graph)

    assert result.outcome is IngestOutcome.FAILURE
    assert "401" in result.error_text
    run = clean_db.scalar(select(IngestRun))
    assert run.outcome is IngestOutcome.FAILURE
    assert run.finished_at is not None


def test_the_scheduler_job_swallows_everything(monkeypatch) -> None:
    """APScheduler must never see an exception from this job."""
    from rua.cli import _ingest_job

    monkeypatch.setattr(
        "rua.ingest.run_ingestion",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    _ingest_job()  # must not raise


# ── every run is recorded ──


def test_every_run_writes_an_ingest_run_row(clean_db) -> None:
    """A failure that only reaches stdout is invisible; Settings reads this table."""
    _configure(clean_db)
    run_ingestion(clean_db, client=FakeGraph())
    run_ingestion(clean_db, client=FakeGraph(list_error=GraphError("nope")))

    runs = clean_db.scalars(select(IngestRun).order_by(IngestRun.id)).all()
    assert len(runs) == 2
    assert runs[0].outcome is IngestOutcome.SUCCESS
    assert runs[1].outcome is IngestOutcome.FAILURE
    assert all(r.finished_at is not None for r in runs)


def test_unconfigured_ingestion_records_a_failure_rather_than_crashing(clean_db) -> None:
    result = run_ingestion(clean_db, client=FakeGraph())

    assert result.outcome is IngestOutcome.FAILURE
    assert "setup wizard" in result.error_text
    assert clean_db.scalar(select(func.count()).select_from(IngestRun)) == 1


# ── forensic reports ──


def test_forensic_reports_are_discarded_unparsed(clean_db) -> None:
    """A deliberate privacy position, not an omission: ruf reports carry message
    content and recipient addresses, and Rua does not hold either."""
    _configure(clean_db)
    graph = FakeGraph(
        messages=[_message("f1", subject="Forensic Report for fabrikam.com")],
        attachments={
            "f1": [
                _attachment(
                    "report.eml", b"From: someone@example.com\r\n\r\nbody", "message/rfc822"
                )
            ]
        },
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.forensic_discarded == 1
    assert result.reports_parsed == 0
    assert result.reports_failed == 0, "discarding is not a failure"
    assert _counts(clean_db) == (0, 0)


def test_feedback_report_content_type_is_discarded(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(
        messages=[_message("f2", subject="Report Domain: example.com")],
        attachments={
            "f2": [
                _attachment("part.txt", b"Feedback-Type: auth-failure", "message/feedback-report")
            ]
        },
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.forensic_discarded == 1
    assert _counts(clean_db) == (0, 0)


def test_error_text_carries_no_report_contents(clean_db) -> None:
    """The operator needs to know what broke, not to receive the payload."""
    _configure(clean_db)
    secret_ish = b"<feedback>CONFIDENTIAL-RECIPIENT-DATA</feedback>"
    graph = FakeGraph(
        messages=[_message("m1")],
        attachments={"m1": [_attachment("r.xml.gz", gzip.compress(secret_ish))]},
    )

    result = run_ingestion(clean_db, client=graph)

    assert result.reports_failed == 1
    assert "CONFIDENTIAL-RECIPIENT-DATA" not in (result.error_text or "")
