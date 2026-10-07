"""Retention against a real database.

Milestone 9's definition of done: shortening the retention window deletes the
expected rows on the next run and leaves rollups intact.
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import func, select

from rua import queries
from rua.models import DailyRollup, IngestOutcome, IngestRun, Report, ReportRow, TlsResultRow
from rua.retention import retention_facts, run_retention
from rua.seed import seed_demo
from rua.seed_reports import seed_demo_reports

TODAY = dt.date(2026, 10, 7)


def _count(session, model) -> int:
    return session.scalar(select(func.count()).select_from(model))


@pytest.fixture
def seeded(db_session):
    seed_demo(db_session)
    seed_demo_reports(db_session, today=TODAY)
    return db_session


def test_nothing_to_do_inside_the_window(seeded) -> None:
    before = _count(seeded, ReportRow)
    result = run_retention(seeded, raw_days=90, rollup_days=730, today=TODAY)
    assert result.raw_rows_deleted == 0 and result.rollups_written == 0
    assert _count(seeded, ReportRow) == before


def test_shortening_the_window_rolls_up_then_deletes(seeded) -> None:
    cutoff = TODAY - dt.timedelta(days=30)
    old_rows = seeded.scalar(
        select(func.count()).select_from(ReportRow).where(ReportRow.date < cutoff)
    )
    old_volume = seeded.scalar(select(func.sum(ReportRow.count)).where(ReportRow.date < cutoff))
    assert old_rows > 0

    result = run_retention(seeded, raw_days=30, rollup_days=730, today=TODAY)

    assert result.raw_rows_deleted == old_rows
    # 90 seeded days; the cutoff day itself stays raw, so 59 days are older than it.
    assert result.days_rolled_up == 59
    assert seeded.scalar(select(func.min(ReportRow.date))) == cutoff
    assert seeded.scalar(select(func.sum(DailyRollup.volume))) == old_volume, (
        "every deleted message survives in a rollup"
    )
    assert seeded.scalar(select(func.max(DailyRollup.date))) == cutoff - dt.timedelta(days=1)
    assert _count(seeded, Report) == seeded.scalar(
        select(func.count(func.distinct(ReportRow.report_pk)))
    ), "report headers without rows are gone"


def test_rollups_preserve_the_readiness_split(seeded) -> None:
    """The known/unclassified distinction must survive rollup — the spec insists."""
    win = queries.window(90, TODAY)
    before = queries.domain_splits(seeded, win)

    run_retention(seeded, raw_days=7, rollup_days=730, today=TODAY)
    after = queries.domain_splits(seeded, win)

    assert after == before, "raw + rollup over the window equals raw alone before"


def test_retention_is_idempotent(seeded) -> None:
    run_retention(seeded, raw_days=30, rollup_days=730, today=TODAY)
    volume = seeded.scalar(select(func.sum(DailyRollup.volume)))
    rollups = _count(seeded, DailyRollup)

    second = run_retention(seeded, raw_days=30, rollup_days=730, today=TODAY)

    assert second.raw_rows_deleted == 0 and second.rollups_written == 0
    assert seeded.scalar(select(func.sum(DailyRollup.volume))) == volume
    assert _count(seeded, DailyRollup) == rollups


def test_late_report_for_a_rolled_up_day_is_added_not_duplicated(seeded) -> None:
    run_retention(seeded, raw_days=30, rollup_days=730, today=TODAY)
    day = TODAY - dt.timedelta(days=40)
    before = seeded.scalar(
        select(DailyRollup.volume).where(
            DailyRollup.domain_name == "fabrikam.com", DailyRollup.date == day
        )
    )
    late = Report(
        report_id="late-1",
        org_name="late.example",
        date_begin=dt.datetime.combine(day, dt.time(), tzinfo=dt.UTC),
        date_end=dt.datetime.combine(day, dt.time(23, 59), tzinfo=dt.UTC),
    )
    seeded.add(late)
    seeded.flush()
    seeded.add(
        ReportRow(
            report_pk=late.id,
            domain_name="fabrikam.com",
            source_ip="203.0.113.250",
            count=500,
            disposition="none",
            spf_aligned=False,
            dkim_aligned=False,
            date=day,
        )
    )
    seeded.flush()

    run_retention(seeded, raw_days=30, rollup_days=730, today=TODAY)

    row = seeded.execute(
        select(DailyRollup.volume, DailyRollup.fail_unclassified).where(
            DailyRollup.domain_name == "fabrikam.com", DailyRollup.date == day
        )
    ).one()
    assert row.volume == before + 500
    assert row.fail_unclassified >= 500


def test_rollups_past_their_own_window_are_deleted_and_newer_ones_kept(seeded) -> None:
    run_retention(seeded, raw_days=7, rollup_days=730, today=TODAY)
    assert _count(seeded, DailyRollup) > 0

    result = run_retention(seeded, raw_days=7, rollup_days=30, today=TODAY)

    assert result.rollups_deleted > 0
    assert seeded.scalar(select(func.min(DailyRollup.date))) == TODAY - dt.timedelta(days=30)
    assert _count(seeded, DailyRollup) > 0, "rollups inside the window are intact"


def test_tls_rows_and_ingest_runs_follow_their_windows(seeded) -> None:
    seeded.add(
        IngestRun(started_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC), outcome=IngestOutcome.SUCCESS)
    )
    seeded.add(
        IngestRun(
            started_at=dt.datetime.combine(TODAY, dt.time(), tzinfo=dt.UTC),
            outcome=IngestOutcome.SUCCESS,
        )
    )
    seeded.flush()
    tls_before = _count(seeded, TlsResultRow)

    result = run_retention(seeded, raw_days=30, rollup_days=365, today=TODAY)

    assert 0 < result.tls_rows_deleted < tls_before
    assert seeded.scalar(select(func.min(TlsResultRow.date))) == TODAY - dt.timedelta(days=30)
    assert result.ingest_runs_deleted == 1
    assert _count(seeded, IngestRun) == 1


def test_rollup_window_must_cover_raw_window(db_session) -> None:
    with pytest.raises(ValueError):
        run_retention(db_session, raw_days=90, rollup_days=30, today=TODAY)


def test_facts(seeded) -> None:
    facts = retention_facts(seeded)
    assert facts.raw_rows > 0 and facts.rollups == 0
    assert facts.oldest_raw == TODAY - dt.timedelta(days=89)
    run_retention(seeded, raw_days=30, rollup_days=730, today=TODAY)
    facts = retention_facts(seeded)
    assert facts.rollups > 0 and facts.oldest_rollup == TODAY - dt.timedelta(days=89)
