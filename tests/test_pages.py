"""The server-rendered dashboard pages on an empty and a day-zero database.

Milestone 7's definition of done is visual, so the suite does not chase it.
What it pins is the part that can regress silently: every page renders in
every data state, day zero shows posture with pending volume and no false
zeros, and the presentation helpers say what they mean. The seeded half lives
in ``test_pages_seeded.py`` because its fixture is module-scoped and must not
share a module with fixtures that truncate the database.
"""

from __future__ import annotations

import pytest

from rua import settings_store as store
from rua.presentation import LABELS, compact_number, pill, relative_age
from rua.seed import seed_demo

PAGES = ("/", "/domains", "/sources", "/tls", "/domains/fabrikam.com")


@pytest.fixture
def empty(client, clean_db):
    store.set_bool(clean_db, store.SETUP_DEMO_MODE, True)
    clean_db.commit()
    return client


@pytest.fixture
def dns_only(client, clean_db):
    """Day zero: domains synced, no reports."""
    seed_demo(clean_db)
    store.set_bool(clean_db, store.SETUP_DEMO_MODE, True)
    clean_db.commit()
    return client


@pytest.mark.parametrize("path", PAGES[:4])
def test_pages_render_on_an_empty_database(empty, path) -> None:
    response = empty.get(path)
    assert response.status_code == 200
    assert "Waiting for first reports" in response.text or "Sample data" in response.text


@pytest.mark.parametrize("path", PAGES)
def test_pages_render_on_day_zero(dns_only, path) -> None:
    """DNS posture live, report-derived columns pending — on the same page."""
    response = dns_only.get(path)
    assert response.status_code == 200
    if path.startswith("/domains"):
        assert "p=reject" in response.text or "not configured" in response.text
        assert "pending" in response.text
        assert ">0<" not in response.text, "no report-derived zero may appear before reports"


def test_pages_are_behind_the_setup_gate(client) -> None:
    for path in PAGES[:4]:
        assert client.get(path).status_code == 303, path


def test_table_sorts_volume_with_pending_last(dns_only) -> None:
    html = dns_only.get("/fragments/domains-table?sort=volume&dir=desc").text
    # 14 table rows plus their 14 phone cards; every one pending, none zero.
    assert html.count("vol--pending") == 28, "every row is pending on day zero, none is zero"
    assert "vol--none" not in html


def test_overview_on_day_zero_has_no_zeros(dns_only) -> None:
    html = dns_only.get("/").text
    assert "waiting for first reports" in html
    assert "0.0%" not in html


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "—"),
        (0, "0"),
        (999, "999"),
        (12_300, "12.3K"),
        (157_000, "157K"),
        (1_234_567, "1.2M"),
    ],
)
def test_compact_number(value, expected) -> None:
    assert compact_number(value) == expected


def test_every_posture_value_has_a_label() -> None:
    from rua.models import DkimPosture, DmarcPosture, MtaStsPosture, SpfPosture, TlsRptPosture

    for signal, enum in (
        ("dmarc", DmarcPosture),
        ("spf", SpfPosture),
        ("dkim", DkimPosture),
        ("mtasts", MtaStsPosture),
        ("tlsrpt", TlsRptPosture),
    ):
        for member in enum:
            p = pill(signal, member.value)
            assert p.label, f"{signal}={member.value} has no word"
            if member.value != "na":
                assert member.value in LABELS[signal]


def test_relative_age() -> None:
    import datetime as dt

    now = dt.datetime(2026, 10, 7, 12, tzinfo=dt.UTC)
    assert relative_age(None, now) == "never"
    assert relative_age(now - dt.timedelta(seconds=30), now) == "just now"
    assert relative_age(now - dt.timedelta(minutes=45), now) == "45 min ago"
    assert relative_age(now - dt.timedelta(hours=5), now) == "5 h ago"
    assert relative_age(now - dt.timedelta(days=3), now) == "3 d ago"
