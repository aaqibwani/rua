"""Reading the report mailbox and turning it into rows.

Three properties this module exists to guarantee:

**Every run is recorded.** An ``ingest_run`` row is written whether the run
succeeds, partly succeeds or fails outright. A failure that only reaches stdout
is invisible: Settings reads this table, the stale banner is derived from it, and
"ingestion silently stopped three weeks ago" is the failure mode that makes a
tool like this untrustworthy.

**One bad report cannot take down a batch.** Each report is persisted inside its
own savepoint. A malformed document, a decompression bomb or a constraint
violation rolls back that report alone; the rest of the run continues and the
failure is counted.

**Re-reading a message changes nothing.** Reports are keyed by their report id,
which is unique in the database. Ingesting the same mailbox twice inserts nothing
the second time.

Forensic (``ruf``) reports are discarded without being parsed. They contain
message content and recipient addresses, and not holding them is a documented
privacy position rather than an omission.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from rua import settings_store as store
from rua.graph import GraphClient, GraphCredentials, GraphError, MailAttachment, MailMessage
from rua.logging import get_logger
from rua.models import (
    Disposition,
    IngestOutcome,
    IngestRun,
    PolicyMode,
    Report,
    ReportRow,
    TlsReport,
    TlsResultRow,
)
from rua.reports import (
    ExtractionError,
    extract_documents,
    parse_aggregate_report,
    parse_tls_report,
)
from rua.reports.aggregate import ReportParseError
from rua.reports.tlsrpt import TlsReportParseError

log = get_logger(__name__)

INGEST_CHECKPOINT = "ingest.last_message_at"

# Content types and file extensions that carry a forensic report rather than an
# aggregate one. RFC 6591 forensic reports are message/feedback-report, and the
# offending message is attached as message/rfc822.
FORENSIC_CONTENT_TYPES = frozenset({"message/feedback-report", "message/rfc822"})
FORENSIC_SUBJECT = re.compile(
    r"\b(forensic|auth(?:entication)?[- ]failure|failure report)\b", re.IGNORECASE
)


@dataclass
class IngestResult:
    outcome: IngestOutcome
    messages_seen: int = 0
    reports_parsed: int = 0
    reports_failed: int = 0
    forensic_discarded: int = 0
    duplicates_skipped: int = 0
    error_text: str | None = None
    failures: list[str] = field(default_factory=list)


def _credentials(session: Session) -> tuple[GraphCredentials, str] | None:
    tenant = store.get(session, store.GRAPH_TENANT_ID)
    client = store.get(session, store.GRAPH_CLIENT_ID)
    secret = store.get(session, store.GRAPH_CLIENT_SECRET)
    mailbox = store.get(session, store.GRAPH_MAILBOX)
    if not (tenant and client and secret and mailbox):
        return None
    return GraphCredentials(tenant_id=tenant, client_id=client, client_secret=secret), mailbox


def _is_forensic(message: MailMessage, attachment: MailAttachment) -> bool:
    content_type = attachment.content_type.split(";", 1)[0].strip().lower()
    if content_type in FORENSIC_CONTENT_TYPES:
        return True
    if attachment.name.lower().endswith(".eml"):
        return True
    return bool(FORENSIC_SUBJECT.search(message.subject))


def run_ingestion(session: Session, client: GraphClient | None = None) -> IngestResult:
    """Poll the report mailbox once and persist what it finds.

    ``client`` is injectable so tests can drive the whole pipeline without a
    tenant. Never raises for an operational failure: the outcome is returned and
    recorded, because the scheduler must not crash-loop on a bad credential.
    """
    run = IngestRun(outcome=IngestOutcome.FAILURE)
    session.add(run)
    session.flush()

    result = _execute(session, run, client)

    run.outcome = result.outcome
    run.messages_seen = result.messages_seen
    run.reports_parsed = result.reports_parsed
    run.reports_failed = result.reports_failed
    run.error_text = result.error_text
    run.finished_at = dt.datetime.now(dt.UTC)
    session.flush()

    log.info(
        "ingest_run_finished",
        outcome=result.outcome.value,
        messages=result.messages_seen,
        parsed=result.reports_parsed,
        failed=result.reports_failed,
        forensic_discarded=result.forensic_discarded,
        duplicates=result.duplicates_skipped,
    )
    return result


def _execute(session: Session, run: IngestRun, client: GraphClient | None) -> IngestResult:
    configured = _credentials(session)
    if configured is None:
        return IngestResult(
            outcome=IngestOutcome.FAILURE,
            error_text="Ingestion is not configured: finish the setup wizard first.",
        )

    credentials, mailbox = configured
    graph = client or GraphClient(credentials)
    result = IngestResult(outcome=IngestOutcome.SUCCESS)

    checkpoint_raw = store.get(session, INGEST_CHECKPOINT)
    checkpoint = dt.datetime.fromisoformat(checkpoint_raw) if checkpoint_raw else None
    newest_seen = checkpoint

    try:
        messages = list(graph.list_messages(mailbox, since=checkpoint))
    except GraphError as exc:
        # A 401 here is the common case — an expired or rotated client secret.
        # It is recorded and returned, never raised, so the scheduler keeps its
        # next slot instead of dying.
        return IngestResult(outcome=IngestOutcome.FAILURE, error_text=str(exc))

    for message in messages:
        result.messages_seen += 1
        try:
            attachments = graph.get_attachments(mailbox, message.id)
        except GraphError as exc:
            result.reports_failed += 1
            result.failures.append(f"{message.id}: {exc}")
            continue

        for attachment in attachments:
            if _is_forensic(message, attachment):
                # Discarded before any parsing. Nothing about it is stored.
                result.forensic_discarded += 1
                log.info("forensic_report_discarded", attachment=attachment.name)
                continue
            _ingest_attachment(session, message, attachment, result)

        if newest_seen is None or message.received > newest_seen:
            newest_seen = message.received

    if newest_seen is not None:
        store.set_value(session, INGEST_CHECKPOINT, newest_seen.isoformat())

    if result.reports_failed and result.reports_parsed:
        result.outcome = IngestOutcome.PARTIAL
    elif result.reports_failed and not result.reports_parsed:
        result.outcome = IngestOutcome.FAILURE

    if result.failures:
        # Bounded, and free of report contents: the operator needs to know what
        # broke, not to receive the payload in a log line.
        result.error_text = "; ".join(result.failures[:10])
        if len(result.failures) > 10:
            result.error_text += f"; and {len(result.failures) - 10} more"

    return result


def _ingest_attachment(
    session: Session, message: MailMessage, attachment: MailAttachment, result: IngestResult
) -> None:
    try:
        documents = extract_documents(attachment.name, attachment.content)
    except ExtractionError as exc:
        result.reports_failed += 1
        result.failures.append(f"{attachment.name}: {exc}")
        log.warning("report_extraction_failed", attachment=attachment.name, reason=str(exc))
        return

    for document in documents:
        # A savepoint per document: a constraint violation or a parse failure
        # rolls back this report alone and leaves the batch intact.
        savepoint = session.begin_nested()
        try:
            stored = _persist(session, message, document)
        except (ReportParseError, TlsReportParseError) as exc:
            savepoint.rollback()
            result.reports_failed += 1
            result.failures.append(f"{document.filename}: {exc}")
            log.warning("report_parse_failed", document=document.filename, reason=str(exc))
        except SQLAlchemyError as exc:
            savepoint.rollback()
            result.reports_failed += 1
            result.failures.append(f"{document.filename}: database error")
            log.error(
                "report_persist_failed", document=document.filename, error_type=type(exc).__name__
            )
        else:
            savepoint.commit()
            if stored:
                result.reports_parsed += 1
            else:
                result.duplicates_skipped += 1


def _persist(session: Session, message: MailMessage, document) -> bool:
    """Store one document. Returns False when it was already ingested."""
    if document.kind == "json":
        return _persist_tls(session, message, document.content)
    return _persist_aggregate(session, message, document.content)


def _persist_aggregate(session: Session, message: MailMessage, content: bytes) -> bool:
    parsed = parse_aggregate_report(content)

    existing = session.scalar(select(Report.id).where(Report.report_id == parsed.report_id))
    if existing is not None:
        return False

    report = Report(
        report_id=parsed.report_id,
        org_name=parsed.org_name,
        org_email=parsed.org_email,
        date_begin=parsed.date_begin,
        date_end=parsed.date_end,
        source_message_id=message.id,
    )
    session.add(report)
    session.flush()

    report_date = parsed.date_begin.date()
    for row in parsed.rows:
        session.add(
            ReportRow(
                report_pk=report.id,
                domain_name=row.header_from,
                source_ip=row.source_ip,
                # Reverse-DNS resolution of the sending org is a separate,
                # configurable step rather than a side effect of parsing — see
                # rua/reports/__init__.py. Left null until the Sources screen
                # needs it.
                source_org=None,
                count=row.count,
                disposition=Disposition(row.disposition),
                spf_aligned=row.spf_aligned,
                dkim_aligned=row.dkim_aligned,
                date=report_date,
            )
        )
    session.flush()

    log.info(
        "aggregate_report_ingested",
        report_id=parsed.report_id,
        org=parsed.org_name,
        rows=len(parsed.rows),
        skipped_records=parsed.skipped_records,
    )
    return True


def _persist_tls(session: Session, message: MailMessage, content: bytes) -> bool:
    parsed = parse_tls_report(content)

    existing = session.scalar(select(TlsReport.id).where(TlsReport.report_id == parsed.report_id))
    if existing is not None:
        return False

    report = TlsReport(
        report_id=parsed.report_id,
        org_name=parsed.org_name,
        date_begin=parsed.date_begin,
        date_end=parsed.date_end,
        source_message_id=message.id,
    )
    session.add(report)
    session.flush()

    report_date = parsed.date_begin.date()
    for entry in parsed.results:
        session.add(
            TlsResultRow(
                tls_report_pk=report.id,
                policy_domain=entry.policy_domain,
                policy_mode=PolicyMode(entry.policy_mode),
                result_type=entry.result_type,
                success_count=entry.success_count,
                failure_count=entry.failure_count,
                date=report_date,
            )
        )
    session.flush()

    log.info(
        "tls_report_ingested",
        report_id=parsed.report_id,
        org=parsed.org_name,
        results=len(parsed.results),
    )
    return True
