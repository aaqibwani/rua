"""Retention: roll raw report rows up into daily aggregates, then delete them.

Two windows from the environment:

``RETENTION_RAW_DAYS`` (default 90)
    Raw ``report_row`` records — one per source IP per report — are kept this
    long. They carry sending IP addresses, which is the field most likely to be
    personal data, so this is the number a privacy policy cares about. TLS-RPT
    rows and their report headers follow the same window; they have no rollup
    because nothing on the TLS screen is historical beyond it.

``RETENTION_ROLLUP_DAYS`` (default 730)
    ``daily_rollup`` rows — one per domain per day, no IPs — are kept this long.
    ``ingest_run`` history follows the same window.

Rolling up preserves exactly what the readiness score needs: volume, aligned
passes, and the known/unclassified split of the failures. The split is decided
at rollup time using the ``source`` table as it stands *then*; classifying a
sender later does not rewrite history, which is the honest reading of "what did
we know when the row was still raw".

A late report for a day that has already been rolled up lands as raw rows and is
*added* to that day's rollup on the next run, so nothing is double counted and
nothing is dropped. Every write is idempotent: running twice on the same day is
a no-op the second time.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import case, delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from rua.logging import get_logger
from rua.models import (
    DailyRollup,
    IngestRun,
    Report,
    ReportRow,
    TlsReport,
    TlsResultRow,
)
from rua.queries import SourceClassifier
from rua.readiness import VolumeSplit

log = get_logger(__name__)


@dataclass
class RetentionResult:
    raw_cutoff: dt.date
    rollup_cutoff: dt.date
    days_rolled_up: int = 0
    rollups_written: int = 0
    raw_rows_deleted: int = 0
    reports_deleted: int = 0
    tls_rows_deleted: int = 0
    tls_reports_deleted: int = 0
    rollups_deleted: int = 0
    ingest_runs_deleted: int = 0


def run_retention(
    session: Session,
    raw_days: int,
    rollup_days: int,
    today: dt.date | None = None,
) -> RetentionResult:
    """Roll up and delete. Dates strictly before ``today - days`` are affected."""
    if rollup_days < raw_days:
        raise ValueError("RETENTION_ROLLUP_DAYS must be at least RETENTION_RAW_DAYS")
    today = today or dt.datetime.now(dt.UTC).date()
    raw_cutoff = today - dt.timedelta(days=raw_days)
    rollup_cutoff = today - dt.timedelta(days=rollup_days)
    result = RetentionResult(raw_cutoff=raw_cutoff, rollup_cutoff=rollup_cutoff)

    _roll_up(session, raw_cutoff, result)
    _delete_raw(session, raw_cutoff, result)
    _delete_old_rollups(session, rollup_cutoff, result)
    session.flush()

    log.info(
        "retention_finished",
        raw_cutoff=raw_cutoff.isoformat(),
        rollup_cutoff=rollup_cutoff.isoformat(),
        days_rolled_up=result.days_rolled_up,
        raw_rows_deleted=result.raw_rows_deleted,
        tls_rows_deleted=result.tls_rows_deleted,
        rollups_deleted=result.rollups_deleted,
    )
    return result


def _roll_up(session: Session, cutoff: dt.date, result: RetentionResult) -> None:
    """Aggregate every raw row dated before ``cutoff`` into ``daily_rollup``."""
    classifier = SourceClassifier.load(session)
    aligned = ReportRow.spf_aligned | ReportRow.dkim_aligned

    rows = session.execute(
        select(
            ReportRow.domain_name,
            ReportRow.date,
            ReportRow.source_ip,
            func.sum(ReportRow.count),
            func.sum(case((aligned, ReportRow.count), else_=0)),
        )
        .where(ReportRow.date < cutoff)
        .group_by(ReportRow.domain_name, ReportRow.date, ReportRow.source_ip)
    )

    splits: dict[tuple[str, dt.date], VolumeSplit] = {}
    for domain, date, ip, count, passed in rows:
        source = classifier.classify(str(ip))
        failing = int(count) - int(passed)
        known = source is not None and source.classification.value == "known"
        part = VolumeSplit(int(passed), failing if known else 0, 0 if known else failing)
        splits[(domain, date)] = splits.get((domain, date), VolumeSplit()) + part

    if not splits:
        return

    values = [
        {
            "domain_name": domain,
            "date": date,
            "volume": split.total,
            "pass_count": split.aligned_pass,
            "fail_known": split.fail_known,
            "fail_unclassified": split.fail_unclassified,
        }
        for (domain, date), split in splits.items()
    ]
    stmt = insert(DailyRollup).values(values)
    # A late report for an already rolled-up day adds to it rather than
    # replacing it: the raw rows that produced the existing rollup are gone.
    stmt = stmt.on_conflict_do_update(
        constraint="uq_daily_rollup_domain_date",
        set_={
            "volume": DailyRollup.volume + stmt.excluded.volume,
            "pass_count": DailyRollup.pass_count + stmt.excluded.pass_count,
            "fail_known": DailyRollup.fail_known + stmt.excluded.fail_known,
            "fail_unclassified": DailyRollup.fail_unclassified + stmt.excluded.fail_unclassified,
        },
    )
    session.execute(stmt)
    result.rollups_written = len(values)
    result.days_rolled_up = len({date for _, date in splits})


def _delete_raw(session: Session, cutoff: dt.date, result: RetentionResult) -> None:
    result.raw_rows_deleted = session.execute(
        delete(ReportRow).where(ReportRow.date < cutoff)
    ).rowcount
    # Report headers whose rows are all gone. date_end is a timestamp; a report
    # ending before the cutoff midnight has no row dated on or after it.
    cutoff_ts = dt.datetime.combine(cutoff, dt.time(), tzinfo=dt.UTC)
    result.reports_deleted = session.execute(
        delete(Report).where(Report.date_end < cutoff_ts)
    ).rowcount

    result.tls_rows_deleted = session.execute(
        delete(TlsResultRow).where(TlsResultRow.date < cutoff)
    ).rowcount
    result.tls_reports_deleted = session.execute(
        delete(TlsReport).where(TlsReport.date_end < cutoff_ts)
    ).rowcount


def _delete_old_rollups(session: Session, cutoff: dt.date, result: RetentionResult) -> None:
    result.rollups_deleted = session.execute(
        delete(DailyRollup).where(DailyRollup.date < cutoff)
    ).rowcount
    cutoff_ts = dt.datetime.combine(cutoff, dt.time(), tzinfo=dt.UTC)
    result.ingest_runs_deleted = session.execute(
        delete(IngestRun).where(IngestRun.started_at < cutoff_ts)
    ).rowcount


@dataclass(frozen=True, slots=True)
class RetentionFacts:
    """What the Settings page shows about stored data."""

    raw_rows: int
    oldest_raw: dt.date | None
    rollups: int
    oldest_rollup: dt.date | None
    tls_rows: int
    ingest_runs: int


def retention_facts(session: Session) -> RetentionFacts:
    raw_rows, oldest_raw = session.execute(
        select(func.count(), func.min(ReportRow.date)).select_from(ReportRow)
    ).one()
    rollups, oldest_rollup = session.execute(
        select(func.count(), func.min(DailyRollup.date)).select_from(DailyRollup)
    ).one()
    tls_rows = session.scalar(select(func.count()).select_from(TlsResultRow))
    runs = session.scalar(select(func.count()).select_from(IngestRun))
    return RetentionFacts(
        raw_rows=int(raw_rows),
        oldest_raw=oldest_raw,
        rollups=int(rollups),
        oldest_rollup=oldest_rollup,
        tls_rows=int(tls_rows or 0),
        ingest_runs=int(runs or 0),
    )
