"""Webhook alerting: the two events, the dedupe rules, and silence when unset."""

from __future__ import annotations

import httpx
import pytest

from rua import alerts
from rua.alerts import GapTransition
from rua.domain_sync import run_domain_sync
from rua.models import IngestOutcome
from tests.test_domain_sync import FakeGraph, _configure
from tests.test_posture import fully_protected

WEBHOOK = "https://hooks.example/abc"


def _webhook(monkeypatch, url: str | None) -> None:
    """Point ALERT_WEBHOOK_URL at ``url`` (or unset it) *after* fixtures cached Settings."""
    from rua.config import get_settings

    if url is None:
        monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    else:
        monkeypatch.setenv("ALERT_WEBHOOK_URL", url)
    get_settings.cache_clear()


@pytest.fixture
def posted(monkeypatch):
    """Capture webhook posts instead of sending them."""
    calls: list[dict] = []

    def fake_post(url, json, timeout, follow_redirects):
        calls.append({"url": url, **json})
        return httpx.Response(200)

    monkeypatch.setattr(alerts.httpx, "post", fake_post)
    return calls


# ─── Unset means silence ──


def test_unset_webhook_posts_nothing_and_does_not_error(monkeypatch) -> None:
    _webhook(monkeypatch, None)

    def never(*a, **k):
        raise AssertionError("no HTTP call may be made without a webhook")

    monkeypatch.setattr(alerts.httpx, "post", never)
    assert alerts.post("t", "x") is False
    assert alerts.alert_ingest_failure("401") is False
    assert alerts.alert_new_gaps([GapTransition("a.example", "dmarc", "reject")]) is False


def test_webhook_outage_is_logged_not_raised(monkeypatch) -> None:
    def down(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(alerts.httpx, "post", down)
    assert alerts.post("t", "x", url=WEBHOOK) is False


def test_rejected_post_returns_false(monkeypatch) -> None:
    monkeypatch.setattr(alerts.httpx, "post", lambda *a, **k: httpx.Response(400))
    assert alerts.post("t", "x", url=WEBHOOK) is False


# ─── Payloads ──


def test_gap_alert_names_domain_signal_and_previous_value(posted) -> None:
    ok = alerts.alert_new_gaps(
        [
            GapTransition("mail.fabrikam.com", "spf", "pass"),
            GapTransition("fabrikam.com", "dmarc", "reject"),
        ],
        url=WEBHOOK,
    )
    assert ok and len(posted) == 1
    body = posted[0]
    assert body["url"] == WEBHOOK
    assert body["title"] == "Rua: 2 new gaps detected"
    assert "- fabrikam.com: DMARC was reject, now not configured" in body["text"]
    assert "- mail.fabrikam.com: SPF was pass, now not configured" in body["text"]
    assert "title" in body and "text" in body, "Teams reads both, Slack reads text"


def test_ingest_failure_alert_carries_the_reason(posted) -> None:
    alerts.alert_ingest_failure("401 from Graph: invalid client secret", url=WEBHOOK)
    assert "401 from Graph" in posted[0]["text"]
    assert posted[0]["title"] == "Rua: ingestion failed"


# ─── Gap detection in the sync ──


def test_sync_alerts_when_a_configured_signal_goes_missing(clean_db, posted, monkeypatch) -> None:
    _webhook(monkeypatch, WEBHOOK)
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=fully_protected())
    assert posted == [], "the first sync of a domain is not a transition"

    broken = fully_protected()
    broken._txt.pop("_dmarc.example.com")
    result = run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=broken)

    assert [(t.domain, t.signal, t.previous) for t in result.new_gaps] == [
        ("example.com", "dmarc", "reject")
    ]
    assert len(posted) == 1 and "example.com: DMARC was reject" in posted[0]["text"]


def test_sync_does_not_alert_on_a_failed_lookup(clean_db, posted, monkeypatch) -> None:
    """A timeout keeps the old value and must never page anyone."""
    _webhook(monkeypatch, WEBHOOK)
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=fully_protected())

    flaky = fully_protected()
    flaky._fail.add("_dmarc.example.com")
    result = run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=flaky)

    assert result.new_gaps == [] and posted == []


def test_sync_does_not_alert_twice_for_the_same_gap(clean_db, posted, monkeypatch) -> None:
    _webhook(monkeypatch, WEBHOOK)
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=fully_protected())
    broken = fully_protected()
    broken._txt.pop("_dmarc.example.com")
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=broken)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=broken)
    assert len(posted) == 1, "missing yesterday and missing today is not news"


def test_sync_without_webhook_records_gaps_but_posts_nothing(clean_db, posted, monkeypatch) -> None:
    _webhook(monkeypatch, None)
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=fully_protected())
    broken = fully_protected()
    broken._txt.pop("_dmarc.example.com")
    result = run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=broken)
    assert len(result.new_gaps) == 1 and posted == []


# ─── Ingestion failure in the poll ──


def test_ingest_alerts_once_per_outage(clean_db, posted, monkeypatch) -> None:
    from rua.ingest import run_ingestion

    _webhook(monkeypatch, WEBHOOK)
    # Unconfigured ingestion fails deterministically with a recorded reason.
    first = run_ingestion(clean_db)
    second = run_ingestion(clean_db)

    assert first.outcome == second.outcome == IngestOutcome.FAILURE
    assert len(posted) == 1, "the second consecutive failure is the same outage"
    assert "setup wizard" in posted[0]["text"]


def test_ingest_failure_without_webhook_is_silent(clean_db, posted, monkeypatch) -> None:
    from rua.ingest import run_ingestion

    _webhook(monkeypatch, None)
    assert run_ingestion(clean_db).outcome == IngestOutcome.FAILURE
    assert posted == []
