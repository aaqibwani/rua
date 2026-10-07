"""The daily domain sync: Graph ``/domains`` plus a live DNS check of each one.

Runs at ``DOMAIN_SYNC_HOUR`` UTC and on demand — the wizard's final step shows a
domain count, which needs a sync to have happened. It is the job that populates
the DNS-derived half of the product, and it is safe to run as often as you like:
every write is an upsert keyed on domain name.

Two rules protect the table from a bad day at the resolver:

* A signal whose lookup failed outright keeps its previous value. Flipping it to
  ``missing`` on a timeout would raise an alert (M9) and show a gap that is not
  there; the next successful run corrects it. ``dns_checked_at`` is only
  advanced when every signal resolved, so a stale check is visible as stale.
* A domain that vanishes from Graph is not deleted. Its reports are still worth
  seeing, and deletion is a decision for an operator, not a sync job.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from rua import settings_store as store
from rua.graph import GraphClient, GraphCredentials, GraphError
from rua.logging import get_logger
from rua.models import (
    DkimPosture,
    DmarcPosture,
    Domain,
    MtaStsPosture,
    Role,
    SpfPosture,
    TlsRptPosture,
)
from rua.posture import DnsResolver, Posture, Resolver, check_domain

log = get_logger(__name__)

# Role is a seed-data concept the real tenant does not supply; a synced domain
# that has never been classified gets the neutral one.
DEFAULT_ROLE = Role.PRIMARY


@dataclass
class SyncResult:
    ok: bool
    domains_seen: int = 0
    created: int = 0
    updated: int = 0
    unresolved: int = 0
    error_text: str | None = None
    skipped: list[str] = field(default_factory=list)


def _credentials(session: Session) -> tuple[GraphCredentials, str] | None:
    tenant = store.get(session, store.GRAPH_TENANT_ID)
    client = store.get(session, store.GRAPH_CLIENT_ID)
    secret = store.get(session, store.GRAPH_CLIENT_SECRET)
    mailbox = store.get(session, store.GRAPH_MAILBOX)
    if not (tenant and client and secret and mailbox):
        return None
    return GraphCredentials(tenant_id=tenant, client_id=client, client_secret=secret), mailbox


def run_domain_sync(
    session: Session,
    graph: GraphClient | None = None,
    resolver: Resolver | None = None,
) -> SyncResult:
    """Pull the verified domain list and re-check every domain's DNS.

    Never raises for an operational failure; the result says what happened and
    the scheduler keeps its next slot.
    """
    configured = _credentials(session)
    if configured is None:
        return SyncResult(
            ok=False, error_text="Domain sync is not configured: finish the setup wizard first."
        )
    credentials, mailbox = configured

    try:
        names = (graph or GraphClient(credentials)).verified_domains()
    except GraphError as exc:
        return SyncResult(ok=False, error_text=str(exc))

    result = check_domains(session, names, mailbox, resolver or DnsResolver())
    store.set_value(session, LAST_SYNC_AT, dt.datetime.now(dt.UTC).isoformat())
    return result


LAST_SYNC_AT = "domains.last_sync_at"


def check_domains(
    session: Session, names: list[str], mailbox: str, resolver: Resolver
) -> SyncResult:
    """Check each named domain and upsert its posture. Shared with the seed path."""
    result = SyncResult(ok=True, domains_seen=len(names))
    now = dt.datetime.now(dt.UTC)

    existing = {
        d.name: d
        for d in session.scalars(select(Domain).where(Domain.name.in_([n.lower() for n in names])))
    }

    for raw in names:
        name = raw.strip().lower().rstrip(".")
        if not name:
            continue
        try:
            posture = check_domain(name, mailbox, resolver)
        except Exception as exc:  # a resolver bug must not take the run down
            log.error("domain_check_crashed", domain=name, error_type=type(exc).__name__)
            result.skipped.append(name)
            continue

        domain = existing.get(name)
        if domain is None:
            domain = Domain(name=name, role=DEFAULT_ROLE)
            session.add(domain)
            result.created += 1
        else:
            result.updated += 1

        _apply(domain, posture, now)
        if posture.unresolved:
            result.unresolved += 1
            log.info("domain_check_partial", domain=name, unresolved=sorted(posture.unresolved))

    session.flush()
    log.info(
        "domain_sync_finished",
        seen=result.domains_seen,
        created=result.created,
        updated=result.updated,
        unresolved=result.unresolved,
        skipped=len(result.skipped),
    )
    return result


def _apply(domain: Domain, posture: Posture, now: dt.datetime) -> None:
    """Write a posture onto a row, keeping old values for unresolved signals."""
    if "dmarc" not in posture.unresolved:
        domain.dmarc = DmarcPosture(posture.dmarc)
        # rua_matches is only meaningful alongside a resolved DMARC record, and
        # the CHECK constraint pairs the two.
        domain.rua_matches = posture.rua_matches
        domain.rua_value = posture.rua_value
    if "spf" not in posture.unresolved:
        domain.spf = SpfPosture(posture.spf)
    if "dkim" not in posture.unresolved:
        domain.dkim = DkimPosture(posture.dkim)
    if "mtasts" not in posture.unresolved:
        domain.mtasts = MtaStsPosture(posture.mtasts)
    if "tlsrpt" not in posture.unresolved:
        domain.tlsrpt = TlsRptPosture(posture.tlsrpt)

    # A new row needs every column populated even when a lookup failed; the
    # placeholders are honest ("missing") and the stale timestamp flags them.
    for attr, enum in (
        ("dmarc", DmarcPosture),
        ("spf", SpfPosture),
        ("dkim", DkimPosture),
        ("mtasts", MtaStsPosture),
        ("tlsrpt", TlsRptPosture),
    ):
        if getattr(domain, attr) is None:
            setattr(domain, attr, enum("missing"))
    if domain.dmarc in (DmarcPosture.MISSING, DmarcPosture.NA):
        domain.rua_matches = None
        domain.rua_value = None

    if posture.complete:
        domain.dns_checked_at = now
