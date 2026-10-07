"""The daily sync against a real database, with Graph and DNS faked."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select

from rua import settings_store as store
from rua.domain_sync import LAST_SYNC_AT, check_domains, run_domain_sync
from rua.graph import GraphError
from rua.models import Domain
from tests.test_posture import MAILBOX, FakeResolver, fully_protected


def _configure(session) -> None:
    store.set_value(session, store.GRAPH_TENANT_ID, "tenant-id")
    store.set_value(session, store.GRAPH_CLIENT_ID, "client-id")
    store.set_value(session, store.GRAPH_CLIENT_SECRET, "client-secret")
    store.set_value(session, store.GRAPH_MAILBOX, MAILBOX)


class FakeGraph:
    def __init__(self, domains=None, error=None):
        self._domains = domains or []
        self._error = error

    def verified_domains(self):
        if self._error:
            raise self._error
        return list(self._domains)


def test_sync_creates_domains_with_posture(clean_db) -> None:
    _configure(clean_db)
    result = run_domain_sync(
        clean_db,
        graph=FakeGraph(["example.com", "contoso.onmicrosoft.com"]),
        resolver=fully_protected(),
    )

    assert result.ok and result.created == 2
    rows = {d.name: d for d in clean_db.scalars(select(Domain))}
    assert rows["example.com"].dmarc.value == "reject"
    assert rows["example.com"].rua_matches is True
    assert rows["example.com"].dns_checked_at is not None
    assert rows["contoso.onmicrosoft.com"].dmarc.value == "na"
    assert rows["contoso.onmicrosoft.com"].rua_matches is None
    assert store.get(clean_db, LAST_SYNC_AT) is not None


def test_sync_is_an_upsert(clean_db) -> None:
    _configure(clean_db)
    graph = FakeGraph(["example.com"])
    run_domain_sync(clean_db, graph=graph, resolver=fully_protected())
    second = run_domain_sync(clean_db, graph=graph, resolver=fully_protected())

    assert (second.created, second.updated) == (0, 1)
    assert clean_db.scalar(select(func.count()).select_from(Domain)) == 1


def test_posture_changes_are_picked_up(clean_db) -> None:
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=fully_protected())

    weakened = fully_protected()
    weakened._txt["_dmarc.example.com"] = ["v=DMARC1; p=none; rua=mailto:elsewhere@x.example"]
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=weakened)

    row = clean_db.scalar(select(Domain).where(Domain.name == "example.com"))
    assert row.dmarc.value == "none"
    assert row.rua_matches is False


def test_transient_failure_keeps_the_previous_value(clean_db) -> None:
    """A timeout must not become a gap in the table and an alert."""
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=fully_protected())
    first_checked = clean_db.scalar(select(Domain.dns_checked_at))

    flaky = fully_protected()
    flaky._fail.add("_dmarc.example.com")
    result = run_domain_sync(clean_db, graph=FakeGraph(["example.com"]), resolver=flaky)

    row = clean_db.scalar(select(Domain).where(Domain.name == "example.com"))
    assert result.unresolved == 1
    assert row.dmarc.value == "reject", "the old verdict stands"
    assert row.rua_matches is True
    assert row.dns_checked_at == first_checked, "a partial check does not advance the timestamp"


def test_new_domain_with_failed_lookup_satisfies_the_check_constraint(clean_db) -> None:
    """A fresh row must get every column; the DB pairs rua_matches with dmarc."""
    _configure(clean_db)
    flaky = FakeResolver(fail={"_dmarc.new.example"})
    result = run_domain_sync(clean_db, graph=FakeGraph(["new.example"]), resolver=flaky)

    row = clean_db.scalar(select(Domain).where(Domain.name == "new.example"))
    assert result.created == 1
    assert row.dmarc.value == "missing" and row.rua_matches is None
    assert row.dns_checked_at is None, "nothing certain was learned yet"


def test_domains_removed_from_graph_are_kept(clean_db) -> None:
    _configure(clean_db)
    run_domain_sync(
        clean_db, graph=FakeGraph(["a.example", "b.example"]), resolver=fully_protected()
    )
    run_domain_sync(clean_db, graph=FakeGraph(["a.example"]), resolver=fully_protected())

    assert clean_db.scalar(select(func.count()).select_from(Domain)) == 2


def test_graph_failure_is_recorded_not_raised(clean_db) -> None:
    _configure(clean_db)
    result = run_domain_sync(clean_db, graph=FakeGraph(error=GraphError("401")))
    assert result.ok is False and "401" in result.error_text


def test_unconfigured_sync_does_not_crash(clean_db) -> None:
    result = run_domain_sync(clean_db, graph=FakeGraph(["x.example"]))
    assert result.ok is False and "setup wizard" in result.error_text


def test_check_domains_survives_a_resolver_crash(clean_db) -> None:
    class Exploding(FakeResolver):
        def txt(self, name):
            if "bad" in name:
                raise RuntimeError("resolver bug")
            return super().txt(name)

    result = check_domains(clean_db, ["bad.example", "example.com"], MAILBOX, Exploding())
    assert result.skipped == ["bad.example"]
    assert result.created == 1


def test_seed_then_sync_coexist(clean_db) -> None:
    """Demo rows and real rows share the table; the sync updates, never duplicates."""
    from rua.seed import seed_demo

    seed_demo(clean_db)
    _configure(clean_db)
    run_domain_sync(clean_db, graph=FakeGraph(["fabrikam.com"]), resolver=fully_protected())

    assert clean_db.scalar(select(func.count()).select_from(Domain)) == 60
    row = clean_db.scalar(select(Domain).where(Domain.name == "fabrikam.com"))
    assert row.dns_checked_at is not None
    assert row.dns_checked_at.tzinfo is not None or isinstance(row.dns_checked_at, dt.datetime)
