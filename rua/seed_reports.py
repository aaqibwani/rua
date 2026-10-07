"""Deterministic demo *report* data, layered on the 60 demo domains.

:mod:`rua.seed` writes the DNS-derived half of the demo tenant and is pinned
by digest; this module writes the report-derived half and leaves that generator
untouched. It exists so the dashboard has volume, pass rates, sources and TLS
results to show in demo mode, and so the API tests have a tenant-sized dataset
to assert against.

Shape of the data
-----------------

For every demo domain that can send mail (not the tenant default, not zero
volume) and every day in the last ``DAYS`` days, two reporters each file one
aggregate report. Each report carries up to four records:

* the tenant's own Microsoft 365 egress — aligned, the bulk of the volume;
* a known third-party sender (SendGrid, Mailchimp, Salesforce) — mostly
  aligned, with a misconfigured remainder that fails. This is ``fail_known``;
* an unclassified IP from a documentation range (RFC 5737) that fails. This is
  ``fail_unclassified`` — the number that should stop someone tightening.

The split per domain is driven by the prototype's ``pass_rate`` for that domain
and by a per-domain hash, so some demo domains are ``ready`` for ``p=reject``,
some are blocked by unclassified volume, parked domains land on
``insufficient_data``, and the ones already at reject say so. Every verdict in
:mod:`rua.readiness` appears in the demo tenant on purpose.

Domains publishing TLS-RPT also get one TLS report per day, with a handful of
RFC 8460 failure types weighted by their MTA-STS posture.

Idempotency
-----------

Every demo report id starts with ``demo:``. A run deletes those and re-inserts,
so the final state for a given day is the same however many times it runs, and
yesterday's run does not leave a 91st day behind. Nothing else in the report
tables is touched: a real tenant that also loaded the demo keeps its real rows.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from rua.logging import get_logger
from rua.models import (
    Report,
    ReportRow,
    Source,
    SourceClass,
    TlsReport,
    TlsResultRow,
)
from rua.seed import (
    DEFAULT_DEMO_MAILBOX,
    DEFAULT_TENANT_PREFIX,
    SeedDomain,
    generate_domains,
    hash_frac,
)

log = get_logger(__name__)

DAYS = 90
DEMO_PREFIX = "demo:"

# The demo volume figure is the prototype's "Volume" column, read as a 30-day total.
VOLUME_WINDOW_DAYS = 30


@dataclass(frozen=True, slots=True)
class DemoSource:
    org_name: str
    ip: str
    ranges: tuple[str, ...]


# Documentation and reserved ranges only; none of these addresses route.
M365 = DemoSource("Microsoft 365", "198.51.100.10", ("198.51.100.0/26",))
SAAS: tuple[DemoSource, ...] = (
    DemoSource("SendGrid", "198.51.100.70", ("198.51.100.64/27",)),
    DemoSource("Mailchimp", "198.51.100.100", ("198.51.100.96/27",)),
    DemoSource("Salesforce Marketing Cloud", "198.51.100.130", ("198.51.100.128/27",)),
)
# 203.0.113.0/24 is deliberately *not* on the source table: these are the senders
# nobody has classified.
UNCLASSIFIED_IPS: tuple[str, ...] = tuple(f"203.0.113.{n}" for n in (5, 17, 42, 77, 99, 180))

REPORTERS: tuple[tuple[str, str, float], ...] = (
    ("google.com", "noreply-dmarc-support@google.com", 0.65),
    ("Yahoo", "dmarc_support@yahoo.com", 0.35),
)
TLS_REPORTER = ("google.com", 1.0)


def _demo_sources() -> list[DemoSource]:
    return [M365, *SAAS]


def _daily_volume(domain: SeedDomain, date: dt.date) -> int:
    """Spread the 30-day figure over days, with weekend dips and some jitter."""
    if domain.volume == 0:
        return 0
    base = domain.volume / VOLUME_WINDOW_DAYS
    weekend = 0.45 if date.weekday() >= 5 else 1.0
    jitter = 0.8 + 0.4 * hash_frac(f"{domain.name}{date.isoformat()}")
    return max(1, round(base * weekend * jitter))


def _unclassified_fraction(domain: SeedDomain) -> float:
    """What share of a domain's failing volume comes from unknown senders.

    Bimodal on purpose: roughly a third of domains have most of their failures
    from unclassified sources (not ready), the rest mostly from a known sender
    that is misconfigured (fixable).
    """
    r = hash_frac(domain.name + "unclassified")
    return 0.6 + 0.4 * r if r < 0.33 else 0.05 * r


def _disposition(dmarc: str) -> str:
    return dmarc if dmarc in ("reject", "quarantine") else "none"


def _records(domain: SeedDomain, date: dt.date, share: float) -> list[dict]:
    """The rows one reporter files for one domain on one day."""
    total = round(_daily_volume(domain, date) * share)
    if total == 0:
        return []

    pass_rate = (domain.pass_rate or 99.0) / 100.0
    failing = round(total * (1 - pass_rate))
    aligned = total - failing
    unclassified = round(failing * _unclassified_fraction(domain))
    known_fail = failing - unclassified

    saas = SAAS[int(hash_frac(domain.name + "saas") * len(SAAS)) % len(SAAS)]
    saas_aligned = round(aligned * 0.15)
    m365_aligned = aligned - saas_aligned
    disposition = _disposition(domain.dmarc)

    rows = []
    if m365_aligned:
        rows.append(_row(M365.ip, m365_aligned, "none", spf=True, dkim=True))
    if saas_aligned:
        rows.append(_row(saas.ip, saas_aligned, "none", spf=False, dkim=True))
    if known_fail:
        rows.append(_row(saas.ip, known_fail, disposition, spf=False, dkim=False))
    if unclassified:
        ip = UNCLASSIFIED_IPS[int(hash_frac(domain.name + date.isoformat()) * 6) % 6]
        rows.append(_row(ip, unclassified, disposition, spf=False, dkim=False))
    return rows


def _row(ip: str, count: int, disposition: str, *, spf: bool, dkim: bool) -> dict:
    return {
        "source_ip": ip,
        "count": count,
        "disposition": disposition,
        "spf_aligned": spf,
        "dkim_aligned": dkim,
    }


def _tls_results(domain: SeedDomain, date: dt.date) -> list[dict]:
    volume = _daily_volume(domain, date)
    if volume == 0:
        return []
    sessions = max(1, round(volume * 0.3))
    r = hash_frac(domain.name + "tls" + date.isoformat())

    failures: dict[str, int] = {}
    if domain.mtasts == "enforce":
        failures["starttls-not-supported"] = round(sessions * 0.001 * r)
    elif domain.mtasts == "testing":
        failures["certificate-host-mismatch"] = round(sessions * 0.01 * r)
        failures["starttls-not-supported"] = round(sessions * 0.002)
    else:
        failures["sts-policy-fetch-error"] = round(sessions * 0.02 * r)
        failures["validation-failure"] = round(sessions * 0.004)
    failures = {kind: n for kind, n in failures.items() if n > 0}

    mode = domain.mtasts if domain.mtasts in ("enforce", "testing") else "none"
    results = [
        {
            "policy_domain": domain.name,
            "policy_mode": mode,
            "result_type": "successful-session",
            "success_count": sessions - sum(failures.values()),
            "failure_count": 0,
        }
    ]
    for kind, n in failures.items():
        results.append(
            {
                "policy_domain": domain.name,
                "policy_mode": mode,
                "result_type": kind,
                "success_count": 0,
                "failure_count": n,
            }
        )
    return results


def seed_demo_sources(session: Session) -> int:
    """Upsert the known-sender rows. Returns how many were created."""
    existing = {s.org_name: s for s in session.scalars(select(Source))}
    created = 0
    now = dt.datetime.now(dt.UTC)
    for demo in _demo_sources():
        source = existing.get(demo.org_name)
        if source is None:
            session.add(
                Source(
                    org_name=demo.org_name,
                    classification=SourceClass.KNOWN,
                    ip_ranges=list(demo.ranges),
                    first_seen=now - dt.timedelta(days=DAYS),
                    last_seen=now,
                )
            )
            created += 1
        else:
            source.classification = SourceClass.KNOWN
            source.ip_ranges = list(demo.ranges)
            source.last_seen = now
    session.flush()
    return created


def seed_demo_reports(
    session: Session,
    tenant_prefix: str = DEFAULT_TENANT_PREFIX,
    mailbox: str = DEFAULT_DEMO_MAILBOX,
    today: dt.date | None = None,
    days: int = DAYS,
) -> tuple[int, int]:
    """Replace the demo report data. Returns ``(aggregate_reports, tls_reports)`` written."""
    today = today or dt.datetime.now(dt.UTC).date()
    domains = [
        d
        for d in generate_domains(tenant_prefix=tenant_prefix, mailbox=mailbox)
        if not d.na and d.volume > 0
    ]

    seed_demo_sources(session)

    # Replace, don't append — see the module docstring.
    session.execute(delete(Report).where(Report.report_id.like(f"{DEMO_PREFIX}%")))
    session.execute(delete(TlsReport).where(TlsReport.report_id.like(f"{DEMO_PREFIX}%")))

    reports: list[dict] = []
    rows_by_report: dict[str, list[dict]] = {}
    tls_reports: list[dict] = []
    tls_by_report: dict[str, list[dict]] = {}

    for offset in range(days):
        date = today - dt.timedelta(days=days - 1 - offset)
        begin = dt.datetime.combine(date, dt.time(), tzinfo=dt.UTC)
        end = begin + dt.timedelta(days=1) - dt.timedelta(seconds=1)

        for domain in domains:
            for org, email, share in REPORTERS:
                records = _records(domain, date, share)
                if not records:
                    continue
                report_id = f"{DEMO_PREFIX}{org}:{domain.name}:{date.isoformat()}"
                reports.append(
                    {
                        "report_id": report_id,
                        "org_name": org,
                        "org_email": email,
                        "date_begin": begin,
                        "date_end": end,
                        "source_message_id": None,
                    }
                )
                rows_by_report[report_id] = [
                    {**record, "domain_name": domain.name, "date": date} for record in records
                ]

            if domain.tlsrpt == "present":
                results = _tls_results(domain, date)
                if results:
                    tls_id = f"{DEMO_PREFIX}tls:{TLS_REPORTER[0]}:{domain.name}:{date.isoformat()}"
                    tls_reports.append(
                        {
                            "report_id": tls_id,
                            "org_name": TLS_REPORTER[0],
                            "date_begin": begin,
                            "date_end": end,
                            "source_message_id": None,
                        }
                    )
                    tls_by_report[tls_id] = [{**r, "date": date} for r in results]

    if reports:
        ids = dict(
            session.execute(insert(Report).returning(Report.report_id, Report.id), reports).all()
        )
        session.execute(
            insert(ReportRow),
            [
                {**row, "report_pk": ids[report_id]}
                for report_id, rows in rows_by_report.items()
                for row in rows
            ],
        )
    if tls_reports:
        tls_ids = dict(
            session.execute(
                insert(TlsReport).returning(TlsReport.report_id, TlsReport.id), tls_reports
            ).all()
        )
        session.execute(
            insert(TlsResultRow),
            [
                {**row, "tls_report_pk": tls_ids[report_id]}
                for report_id, rows in tls_by_report.items()
                for row in rows
            ],
        )
    session.flush()

    log.info(
        "seed_demo_reports_complete",
        domains=len(domains),
        days=days,
        reports=len(reports),
        tls_reports=len(tls_reports),
    )
    return len(reports), len(tls_reports)
