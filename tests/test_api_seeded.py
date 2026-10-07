"""The JSON API on the seeded demo tenant.

Seeding 90 days of demo reports takes several seconds, so it happens once per
module rather than once per test. Nothing here mutates the seeded report data;
the two tests that add rows add operational ones (ingest runs) that no other
assertion in this file depends on.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import SQLAlchemyError

from rua import settings_store as store
from rua.models import Domain, IngestOutcome, IngestRun
from rua.readiness import MIN_VOLUME
from rua.seed import seed_demo
from rua.seed_reports import seed_demo_reports


@pytest.fixture(scope="module")
def seeded_client() -> Iterator[TestClient]:
    from rua.db import Base, get_engine, reset_engine, session_scope
    from rua.main import create_app
    from rua.models import Domain  # noqa: F401 - registers every table on Base

    reset_engine()
    try:
        with get_engine().connect() as probe:
            if not inspect(probe).has_table("domain"):
                pytest.skip("schema not migrated; run `alembic upgrade head` first")
    except SQLAlchemyError as exc:
        pytest.skip(f"no database reachable: {type(exc).__name__}")

    truncate = text(f"TRUNCATE {', '.join(sorted(Base.metadata.tables))} RESTART IDENTITY CASCADE")
    with session_scope() as session:
        session.execute(truncate)
    with session_scope() as session:
        seed_demo(session)
        seed_demo_reports(session)
        store.set_bool(session, store.SETUP_DEMO_MODE, True)

    with TestClient(create_app(), follow_redirects=False) as client:
        yield client

    with session_scope() as session:
        session.execute(truncate)
    reset_engine()


@pytest.fixture
def seeded_session(seeded_client) -> Iterator:
    from rua.db import session_scope

    with session_scope() as session:
        yield session


def test_domains_seeded(seeded_client) -> None:
    body = seeded_client.get("/api/domains").json()
    assert body["has_reports"] is True
    assert len(body["domains"]) == 60
    by_name = {d["name"]: d for d in body["domains"]}

    fabrikam = by_name["fabrikam.com"]
    assert fabrikam["volume"] > 0
    assert 0 < fabrikam["pass_rate"] <= 100
    assert fabrikam["readiness"] is not None
    detail = fabrikam["readiness_detail"]
    assert (
        detail["aligned_pass"] + detail["fail_known"] + detail["fail_unclassified"]
        == fabrikam["volume"]
    )

    tenant = by_name["contoso.onmicrosoft.com"]
    assert tenant["volume"] == 0, "a real zero once reports exist"
    assert tenant["pass_rate"] is None and tenant["readiness"] is None
    assert tenant["readiness_detail"]["verdict"] == "not_applicable"


def test_demo_tenant_exercises_every_verdict(seeded_client) -> None:
    verdicts = {
        d["readiness_detail"]["verdict"]
        for d in seeded_client.get("/api/domains?days=30").json()["domains"]
    }
    assert verdicts == {"at_reject", "ready", "not_ready", "insufficient_data", "not_applicable"}


def test_low_volume_domains_get_no_verdict(seeded_client) -> None:
    for d in seeded_client.get("/api/domains").json()["domains"]:
        if d["dmarc"] in ("none", "quarantine") and d["volume"] < MIN_VOLUME:
            assert d["readiness_detail"]["verdict"] == "insufficient_data", d["name"]


def test_window_changes_volume(seeded_client) -> None:
    small = seeded_client.get("/api/domains/fabrikam.com?days=7").json()["domain"]["volume"]
    large = seeded_client.get("/api/domains/fabrikam.com?days=90").json()["domain"]["volume"]
    assert 0 < small < large


def test_overview_summary_seeded(seeded_client) -> None:
    body = seeded_client.get("/api/overview/summary").json()
    assert body["has_reports"] and body["has_tls_reports"]
    assert body["domains_monitored"] == 60
    assert body["rua_mismatches"] == 3
    assert body["message_volume"] > 0
    assert 0 < body["dmarc_pass_rate"] <= 100
    assert 0 < body["tls_success_rate"] <= 100

    callout = body["readiness_callout"]
    assert callout is not None
    assert callout["dmarc"] in ("none", "quarantine"), "already-at-reject domains are not suggested"
    assert callout["verdict"] == "ready", "the demo tenant has a safe promotion to suggest"
    assert callout["unclassified_volume"] <= callout["failing_volume"]


def test_overview_summary_totals_match_the_domains_endpoint(seeded_client) -> None:
    summary = seeded_client.get("/api/overview/summary?days=14").json()
    domains = seeded_client.get("/api/domains?days=14").json()["domains"]
    assert summary["message_volume"] == sum(d["volume"] for d in domains)


def test_trend_seeded(seeded_client) -> None:
    body = seeded_client.get("/api/overview/trend?days=14").json()
    assert body["has_reports"] is True
    assert len(body["points"]) == 14
    for point in body["points"]:
        assert point["volume"] > 0
        assert 0 < point["pass_rate"] <= 100


def test_sources_seeded(seeded_client) -> None:
    body = seeded_client.get("/api/sources").json()
    rows = body["sources"]
    assert rows and rows == sorted(rows, key=lambda r: -r["volume"]), "volume descending"

    classes = {r["classification"] for r in rows}
    assert classes == {"known", "unclassified"}
    for row in rows:
        if row["classification"] == "unclassified":
            assert row["ip"] == row["name"], "an unclassified sender is its IP"
        else:
            assert row["ip"] is None
        assert 0 <= row["spf_alignment"] <= 100 and 0 <= row["dkim_alignment"] <= 100
    assert rows[0]["name"] == "Microsoft 365"


def test_sources_filtered_to_one_domain(seeded_client) -> None:
    body = seeded_client.get("/api/sources?domain=fabrikam.com").json()
    assert body["domain"] == "fabrikam.com"
    assert all(r["domain_count"] == 1 for r in body["sources"])
    detail = seeded_client.get("/api/domains/fabrikam.com").json()
    assert detail["sources"] == body["sources"]


def test_tls_summary_seeded(seeded_client) -> None:
    body = seeded_client.get("/api/tls/summary").json()
    assert body["has_tls_reports"] is True
    assert body["sessions"] == body["successes"] + body["failures_total"]
    assert body["failures"] == sorted(body["failures"], key=lambda f: -f["count"])
    assert {f["owner"] for f in body["failures"]} <= {"receiver", "sender", "unknown"}
    assert body["reporters"][0]["org_name"] == "google.com"


def test_tls_summary_for_a_domain_without_tlsrpt_is_zero_not_null(
    seeded_client, seeded_session
) -> None:
    """Once TLS reports exist, a domain nobody reports on has zero sessions — a real zero."""
    silent = seeded_session.scalar(select(Domain.name).where(Domain.tlsrpt == "missing"))
    body = seeded_client.get(f"/api/tls/summary?domain={silent}").json()
    assert body["has_tls_reports"] is True
    assert body["sessions"] == 0 and body["success_rate"] is None
    assert body["reporters"] == []


def test_ingest_status_reflects_runs(seeded_client, seeded_session) -> None:
    seeded_session.add(
        IngestRun(outcome=IngestOutcome.FAILURE, error_text="401 from Graph", reports_parsed=0)
    )
    seeded_session.add(
        IngestRun(outcome=IngestOutcome.SUCCESS, reports_parsed=12, messages_seen=12)
    )
    seeded_session.commit()
    ingest = seeded_client.get("/api/overview/summary").json()["ingest"]
    assert ingest["reports_parsed_total"] == 12
    assert ingest["last_success_at"] is not None
    assert ingest["last_outcome"] in ("success", "failure")
