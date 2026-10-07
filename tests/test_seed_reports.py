"""The demo report seed against a real database."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select

from rua import queries
from rua.models import Domain, Report, ReportRow, Source, TlsReport
from rua.seed import seed_demo
from rua.seed_reports import DAYS, DEMO_PREFIX, seed_demo_reports


def _count(session, model) -> int:
    return session.scalar(select(func.count()).select_from(model))


def test_seed_reports_replaces_rather_than_appends(db_session) -> None:
    seed_demo(db_session)
    first = seed_demo_reports(db_session)
    rows = _count(db_session, ReportRow)
    second = seed_demo_reports(db_session)

    assert first == second
    assert _count(db_session, Report) == first[0]
    assert _count(db_session, TlsReport) == first[1]
    assert _count(db_session, ReportRow) == rows
    assert _count(db_session, Source) == 4


def test_seed_reports_is_deterministic_for_a_given_day(db_session) -> None:
    seed_demo(db_session)
    today = dt.date(2026, 10, 7)
    seed_demo_reports(db_session, today=today)
    first = queries.domain_splits(db_session, queries.window(30, today))
    seed_demo_reports(db_session, today=today)
    assert queries.domain_splits(db_session, queries.window(30, today)) == first


def test_seed_reports_cover_exactly_the_last_n_days(db_session) -> None:
    seed_demo(db_session)
    today = dt.date(2026, 10, 7)
    seed_demo_reports(db_session, today=today)
    oldest, newest = db_session.execute(
        select(func.min(ReportRow.date), func.max(ReportRow.date))
    ).one()
    assert newest == today
    assert oldest == today - dt.timedelta(days=DAYS - 1)


def test_seed_reports_leave_real_reports_alone(db_session) -> None:
    seed_demo(db_session)
    real = Report(
        report_id="real-report-1",
        org_name="google.com",
        date_begin=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        date_end=dt.datetime(2026, 1, 2, tzinfo=dt.UTC),
    )
    db_session.add(real)
    db_session.flush()

    seed_demo_reports(db_session)
    seed_demo_reports(db_session)

    assert db_session.scalar(select(Report).where(Report.report_id == "real-report-1")) is not None
    assert all(
        rid.startswith(DEMO_PREFIX) or rid == "real-report-1"
        for rid in db_session.scalars(select(Report.report_id))
    )


def test_seed_reports_never_touch_the_domain_table(db_session) -> None:
    seed_demo(db_session)
    before = {
        d.name: (d.dmarc, d.spf, d.dkim, d.mtasts, d.tlsrpt, d.rua_matches)
        for d in db_session.scalars(select(Domain))
    }
    seed_demo_reports(db_session)
    after = {
        d.name: (d.dmarc, d.spf, d.dkim, d.mtasts, d.tlsrpt, d.rua_matches)
        for d in db_session.scalars(select(Domain))
    }
    assert before == after


def test_seed_reports_only_for_domains_that_send(db_session) -> None:
    seed_demo(db_session)
    seed_demo_reports(db_session)
    reported = set(db_session.scalars(select(ReportRow.domain_name).distinct()))
    assert "contoso.onmicrosoft.com" not in reported
    assert "fabrikam.com" in reported
    tls_domains = set(
        db_session.scalars(
            select(Domain.name).where(Domain.tlsrpt == "present").where(Domain.name.in_(reported))
        )
    )
    assert tls_domains, "the demo has TLS-RPT publishers that send mail"
