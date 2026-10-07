"""The five UI states (handoff spec, Interactions): loading, empty, error, stale, day zero.

Day zero is the one that matters most. It must show live DNS posture with
report-derived columns pending, name the rua= mismatches, and disappear the
moment the first report from any domain parses, leaving no banner behind.
"""

from __future__ import annotations

import datetime as dt

import pytest

from rua import settings_store as store
from rua.models import (
    Disposition,
    IngestOutcome,
    IngestRun,
    Report,
    ReportRow,
)
from rua.seed import RUA_MISMATCHES, seed_demo


def _complete_setup(session) -> None:
    store.set_bool(session, store.SETUP_COMPLETE, True)
    session.commit()


def _first_report(session, when: dt.datetime | None = None) -> None:
    when = when or dt.datetime.now(dt.UTC)
    report = Report(
        report_id="first-ever",
        org_name="google.com",
        date_begin=when - dt.timedelta(days=1),
        date_end=when,
    )
    session.add(report)
    session.flush()
    session.add(
        ReportRow(
            report_pk=report.id,
            domain_name="fabrikam.com",
            source_ip="198.51.100.10",
            count=120,
            disposition=Disposition.NONE,
            spf_aligned=True,
            dkim_aligned=True,
            date=when.date(),
        )
    )
    session.commit()


def _run(session, outcome: IngestOutcome, ago: dt.timedelta, parsed: int = 0) -> None:
    session.add(
        IngestRun(
            started_at=dt.datetime.now(dt.UTC) - ago,
            finished_at=dt.datetime.now(dt.UTC) - ago,
            outcome=outcome,
            reports_parsed=parsed,
            error_text="401 from Graph" if outcome == IngestOutcome.FAILURE else None,
        )
    )
    session.commit()


# ─── Day zero ──


def test_day_zero_page_shows_dns_posture_and_mismatches(client, clean_db) -> None:
    seed_demo(clean_db)
    _complete_setup(clean_db)
    _run(clean_db, IngestOutcome.SUCCESS, dt.timedelta(minutes=20))

    html = client.get("/").text

    assert "Ingestion is running. No reports yet." in html
    assert "Waiting for first reports" in html
    assert "What we already know from DNS" in html
    assert "Three domains will never send you a report" in html
    for name, value in RUA_MISMATCHES.items():
        assert name in html and value in html
    assert "20 min ago" in html, "last poll comes from ingest_run"
    assert "Go to the dashboard" in html and "Ingestion log" in html


def test_day_zero_page_is_not_stale_and_has_no_stale_banner(client, clean_db) -> None:
    """The waiting page has its own facts; the stale banner belongs to the data pages."""
    seed_demo(clean_db)
    _complete_setup(clean_db)
    _run(clean_db, IngestOutcome.FAILURE, dt.timedelta(hours=9))
    html = client.get("/").text
    assert "Data may be stale" not in html
    assert "outcome: failure" in html, "but the failed poll is still visible"


def test_day_zero_disappears_on_the_first_parsed_report(client, clean_db) -> None:
    seed_demo(clean_db)
    _complete_setup(clean_db)
    _run(clean_db, IngestOutcome.SUCCESS, dt.timedelta(minutes=5), parsed=1)
    assert "No reports yet" in client.get("/").text

    _first_report(clean_db)

    html = client.get("/").text
    assert "No reports yet" not in html
    assert "Waiting for first reports" not in html
    assert "Data may be stale" not in html, "nothing left behind"
    assert "DMARC pass rate" in html, "the Overview took its place"


def test_the_dashboard_is_reachable_on_day_zero(client, clean_db) -> None:
    """DNS columns ready, volume columns empty, on the same row."""
    seed_demo(clean_db)
    _complete_setup(clean_db)
    html = client.get("/overview").text
    assert "DMARC pass rate" in html and "waiting for first reports" in html
    table = client.get("/domains").text
    assert "p=reject" in table and "pending" in table


def test_demo_mode_never_shows_the_waiting_page(client, clean_db) -> None:
    seed_demo(clean_db)
    store.set_bool(clean_db, store.SETUP_DEMO_MODE, True)
    clean_db.commit()
    html = client.get("/").text
    assert "No reports yet" not in html
    assert "Sample data" in html


# ─── Stale ──


def test_stale_banner_names_the_age_of_the_last_success(client, clean_db) -> None:
    seed_demo(clean_db)
    _complete_setup(clean_db)
    _first_report(clean_db)
    _run(clean_db, IngestOutcome.SUCCESS, dt.timedelta(hours=7), parsed=1)
    _run(clean_db, IngestOutcome.FAILURE, dt.timedelta(minutes=30))

    html = client.get("/domains").text

    assert "Data may be stale" in html
    assert "7 h ago" in html
    assert 'ended in <span class="mono">failure</span>' in html
    assert 'data-tone="warn"' in html.split("ingest-pill")[1][:40], "header dot turns amber"


def test_fresh_data_has_no_banner(client, clean_db) -> None:
    seed_demo(clean_db)
    _complete_setup(clean_db)
    _first_report(clean_db)
    _run(clean_db, IngestOutcome.SUCCESS, dt.timedelta(minutes=10), parsed=1)
    html = client.get("/domains").text
    assert "Data may be stale" not in html
    assert "Last poll 10 min ago" in html


def test_never_succeeded_is_stale(client, clean_db) -> None:
    seed_demo(clean_db)
    _complete_setup(clean_db)
    _first_report(clean_db)
    _run(clean_db, IngestOutcome.FAILURE, dt.timedelta(minutes=5))
    html = client.get("/sources").text
    assert "never completed successfully" in html


# ─── Error ──


@pytest.fixture
def lenient_client(clean_db):
    """TestClient re-raises server exceptions by default; a browser just sees the page."""
    from fastapi.testclient import TestClient

    from rua.main import create_app

    with TestClient(
        create_app(), follow_redirects=False, raise_server_exceptions=False
    ) as test_client:
        yield test_client


def test_error_state_renders_the_failing_request(lenient_client, clean_db, monkeypatch) -> None:
    client = lenient_client
    _complete_setup(clean_db)

    def boom(*args, **kwargs):
        raise RuntimeError("database exploded with password=hunter2")

    monkeypatch.setattr("rua.routes.pages.api.overview_summary", boom)
    response = client.get("/domains?days=7")

    assert response.status_code == 500
    assert "Something failed while building this page" in response.text
    assert "GET /domains?days=7" in response.text
    assert "View ingestion log" in response.text and "Retry" in response.text
    assert "hunter2" not in response.text, "exception detail stays in the logs"


def test_api_errors_are_json(lenient_client, clean_db, monkeypatch) -> None:
    client = lenient_client
    _complete_setup(clean_db)
    monkeypatch.setattr(
        "rua.api.queries.has_report_data", lambda s: (_ for _ in ()).throw(RuntimeError("x"))
    )
    response = client.get("/api/domains")
    assert response.status_code == 500
    assert response.json()["detail"] == "Internal error"


# ─── Ingestion log, loading ──


def test_ingestion_log_lists_runs_newest_first(client, clean_db) -> None:
    _complete_setup(clean_db)
    _run(clean_db, IngestOutcome.SUCCESS, dt.timedelta(hours=2), parsed=4)
    _run(clean_db, IngestOutcome.FAILURE, dt.timedelta(minutes=1))
    html = client.get("/settings/ingestion").text
    assert html.index('data-outcome="failure"') < html.index('data-outcome="success"')
    assert "401 from Graph" in html


def test_ingestion_log_empty_state(client, clean_db) -> None:
    _complete_setup(clean_db)
    assert "No runs yet" in client.get("/settings/ingestion").text


def test_domains_page_ships_a_skeleton_in_the_shape_of_the_table(client, clean_db) -> None:
    _complete_setup(clean_db)
    html = client.get("/domains").text
    assert '<template id="domains-skeleton">' in html
    assert html.count("drow--skeleton") == 14


STATE_PAGES = ("/", "/overview", "/domains", "/sources", "/tls", "/settings/ingestion")


@pytest.mark.parametrize("path", STATE_PAGES)
def test_every_page_renders_with_setup_complete_and_nothing_else(client, clean_db, path) -> None:
    """A real deployment minutes after the wizard: no domains synced yet, no runs."""
    _complete_setup(clean_db)
    assert client.get(path).status_code == 200
