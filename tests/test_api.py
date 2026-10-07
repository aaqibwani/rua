"""The JSON API on an empty database: nulls, not zeros.

Milestone 6's definition of done: every endpoint has a test asserting shape on
both an empty and a seeded database (the seeded half is ``test_api_seeded.py``),
and the empty case returns nulls — not zeros — for every report-derived figure.
The frontend tells "no data yet" from "zero" by that null.
"""

from __future__ import annotations

import datetime as dt

import pytest

from rua import settings_store as store
from rua.seed import seed_demo

REPORT_FIELDS = ("volume", "pass_rate", "readiness", "readiness_detail")


def _open(session) -> None:
    """Let the setup gate through without finishing the wizard."""
    store.set_bool(session, store.SETUP_DEMO_MODE, True)
    session.commit()


@pytest.fixture
def empty_client(client, clean_db):
    _open(clean_db)
    return client


# ─── Empty database: nulls, not zeros ──


def test_domains_empty_database(empty_client) -> None:
    body = empty_client.get("/api/domains").json()
    assert body == {"window_days": 30, "has_reports": False, "domains": []}


def test_domains_without_reports_carry_posture_but_null_volume(empty_client, clean_db) -> None:
    """Day zero: DNS-derived columns ready, report-derived columns empty, same row."""
    seed_demo(clean_db)
    clean_db.commit()
    body = empty_client.get("/api/domains").json()

    assert body["has_reports"] is False
    assert len(body["domains"]) == 60
    fabrikam = next(d for d in body["domains"] if d["name"] == "fabrikam.com")
    assert fabrikam["dmarc"] in {"reject", "quarantine", "none", "missing"}
    assert fabrikam["rua_matches"] is True
    for field in REPORT_FIELDS:
        assert fabrikam[field] is None, f"{field} must be null, not zero, before reports"
    assert isinstance(fabrikam["gaps"], int) and isinstance(fabrikam["warns"], int)


def test_overview_summary_empty_database(empty_client) -> None:
    body = empty_client.get("/api/overview/summary").json()
    assert body["has_reports"] is False and body["has_tls_reports"] is False
    assert body["domains_monitored"] == 0
    for field in ("dmarc_pass_rate", "tls_success_rate", "message_volume", "tls_sessions"):
        assert body[field] is None, field
    assert body["readiness_callout"] is None
    assert body["ingest"] == {
        "last_run_at": None,
        "last_outcome": None,
        "last_success_at": None,
        "reports_parsed_total": 0,
    }


def test_trend_empty_database_has_a_point_per_day_with_nulls(empty_client) -> None:
    body = empty_client.get("/api/overview/trend?days=7").json()
    assert body["has_reports"] is False
    assert len(body["points"]) == 7
    assert all(p["volume"] is None and p["pass_rate"] is None for p in body["points"])
    dates = [dt.date.fromisoformat(p["date"]) for p in body["points"]]
    assert dates == sorted(dates) and dates[-1] - dates[0] == dt.timedelta(days=6)


def test_sources_empty_database(empty_client) -> None:
    body = empty_client.get("/api/sources").json()
    assert body == {"window_days": 30, "has_reports": False, "domain": None, "sources": []}


def test_tls_summary_empty_database(empty_client) -> None:
    body = empty_client.get("/api/tls/summary").json()
    assert body["has_tls_reports"] is False
    for field in ("sessions", "successes", "failures_total", "success_rate"):
        assert body[field] is None, field
    assert body["failures"] == [] and body["reporters"] == []


def test_domain_detail_404_for_unknown_domain(empty_client) -> None:
    assert empty_client.get("/api/domains/nope.example").status_code == 404


def test_domain_detail_without_reports(empty_client, clean_db) -> None:
    seed_demo(clean_db)
    clean_db.commit()
    body = empty_client.get("/api/domains/fabrikam.com").json()
    assert body["has_reports"] is False
    assert body["domain"]["volume"] is None
    assert body["sources"] == []
    assert body["tls"]["success_rate"] is None


# ─── Window parameter ──


@pytest.mark.parametrize("days", [7, 14, 30, 90])
def test_window_accepts_the_range_pickers_values(empty_client, days) -> None:
    assert empty_client.get(f"/api/domains?days={days}").json()["window_days"] == days


@pytest.mark.parametrize("days", [1, 15, 365, "abc"])
def test_window_rejects_anything_else(empty_client, days) -> None:
    """PINNED: one global window. An arbitrary integer would let panels disagree."""
    assert empty_client.get(f"/api/domains?days={days}").status_code == 422


def test_api_is_behind_the_setup_gate(client) -> None:
    response = client.get("/api/domains")
    assert response.status_code == 303 and response.headers["location"] == "/setup"
