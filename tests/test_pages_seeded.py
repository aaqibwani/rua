"""The dashboard pages on the seeded demo tenant.

Seeded once per module (see test_api_seeded.py for why). Nothing here writes.
The two PINNED Domains-table constraints are asserted on the markup.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError

from rua import settings_store as store
from rua.seed import seed_demo
from rua.seed_reports import seed_demo_reports

PAGES = ("/", "/domains", "/sources", "/tls", "/domains/fabrikam.com")


@pytest.fixture(scope="module")
def seeded() -> Iterator[TestClient]:
    from rua.db import Base, get_engine, reset_engine, session_scope
    from rua.main import create_app
    from rua.models import Domain  # noqa: F401

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


@pytest.mark.parametrize("path", PAGES)
def test_pages_render_on_the_seeded_tenant(seeded, path) -> None:
    response = seeded.get(path)
    assert response.status_code == 200
    assert "Traceback" not in response.text


def test_unknown_domain_is_a_404_page(seeded) -> None:
    response = seeded.get("/domains/nope.example")
    assert response.status_code == 404
    assert "No such domain" in response.text


def test_window_is_global_and_travels_on_every_link(seeded) -> None:
    html = seeded.get("/sources?days=90").text
    for href in ("/overview?days=90", "/domains?days=90", "/tls?days=90"):
        assert f'href="{href}"' in html, href
    assert 'aria-current="true">90d' in html


def test_unknown_window_falls_back_rather_than_erroring(seeded) -> None:
    response = seeded.get("/domains?days=12")
    assert response.status_code == 200
    assert 'aria-current="true">30d' in response.text


def test_no_external_resources_are_referenced(seeded) -> None:
    """ "No outbound call the operator did not configure" includes the browser."""
    for path in PAGES:
        html = seeded.get(path).text
        for url in re.findall(r'(?:src|href)="(https?://[^"]+)"', html):
            assert "testserver" in url, f"{path} references {url}"


def test_every_status_has_a_word_not_just_a_colour(seeded) -> None:
    html = seeded.get("/domains?sort=dmarc&dir=desc").text + seeded.get("/domains").text
    pills = re.findall(r'<span class="pill" data-tone="(\w+)"[^>]*>\s*([^<]+?)\s*</span>', html)
    assert pills, "no pills rendered"
    for tone, word in pills:
        assert word.strip(), f"a {tone} pill rendered with no text"
    words = {w.strip() for _, w in pills}
    assert {"not configured", "p=reject", "pass"} <= words


def test_fully_missing_row_is_distinguishable_without_reading_cells(seeded) -> None:
    """Marker, row tint and bold name — all three, together."""
    html = seeded.get("/domains?q=fabrikam.net").text
    assert 'class="drow drow--critical"' in html
    assert 'drow__domain drow__domain--bold">fabrikam.net' in html
    assert '<span class="sev" data-tone="gap"' in html


def test_clean_row_has_none_of_the_critical_treatment(seeded) -> None:
    html = seeded.get("/domains?q=fabrikam.com").text
    row = html[html.index("fabrikam.com") - 400 : html.index("fabrikam.com") + 100]
    assert "drow--critical" not in row
    assert "drow__domain--bold" not in row


def test_mobile_cards_carry_self_naming_pills(seeded) -> None:
    html = seeded.get("/domains").text
    assert 'class="dcard"' in html
    assert '<span class="pill__name">DMARC</span>' in html
    assert '<span class="pill__name">TLS-RPT</span>' in html


def test_table_pages_fourteen_rows(seeded) -> None:
    html = seeded.get("/fragments/domains-table").text
    assert len(re.findall(r'class="drow(?: drow--critical)?" role="row"', html)) == 14
    assert "1–14 of 60" in html  # noqa: RUF001 - the design renders an en dash
    last = seeded.get("/fragments/domains-table?page=4").text
    assert "57–60 of 60" in last  # noqa: RUF001 - the design renders an en dash
    assert 'aria-disabled="true" tabindex="-1">Next' in last


def test_table_search_and_gaps_filter(seeded) -> None:
    html = seeded.get("/fragments/domains-table?q=tailspin&gaps=1").text
    names = re.findall(r'data-domain="([^"]+)"', html)
    assert names and all("tailspin" in n for n in names)
    assert "tailspin.com" not in names, "a fully protected domain is not a gap"


def test_table_sorts_status_columns_by_severity(seeded) -> None:
    html = seeded.get("/fragments/domains-table?sort=dmarc&dir=desc").text
    first = re.search(r'data-signal="dmarc" data-value="(\w+)"', html).group(1)
    assert first == "na", "n/a sorts after missing on a descending severity sort"
    html = seeded.get("/fragments/domains-table?sort=dmarc&dir=asc").text
    first = re.search(r'data-signal="dmarc" data-value="(\w+)"', html).group(1)
    assert first == "reject"


def test_table_empty_hint_differs_by_cause(seeded) -> None:
    only_search = seeded.get("/fragments/domains-table?q=zzz").text
    both = seeded.get("/fragments/domains-table?q=zzz&gaps=1").text
    assert "No domains match" in only_search and "No domains match" in both
    assert "contains that text" in only_search
    assert "Try one or the other" in both


def test_drill_down_shows_tiles_readiness_and_sources(seeded) -> None:
    html = seeded.get("/domains/mail.fabrikam.com").text
    assert html.count('class="tile"') == 5
    assert "Readiness for p=reject" in html
    assert "Aligned pass" in html and "Unclassified sender" in html
    assert "Sources sending as mail.fabrikam.com" in html
    assert "Back to domains" in html


def test_overview_renders_chart_with_html_axis_labels(seeded) -> None:
    html = seeded.get("/?days=14").text
    assert 'viewBox="0 0 900 240"' in html and 'preserveAspectRatio="none"' in html
    assert html.count('class="chart__ylabel"') == 5
    assert "<text" not in html, "axis labels are positioned HTML, not SVG text"
    assert 'class="chart__line"' in html


def test_overview_callout_names_a_promotable_domain(seeded) -> None:
    html = seeded.get("/").text
    assert "would still pass at" in html
    assert "Promotion stays a manual change" in html
