"""Read queries shared by the templates and the API.

Kept apart from the models so that the bucketing rules live in one place. The
severity vocabulary here is the same one the Domains table's left marker uses,
and the two must not drift: a domain shown amber in one place and green in
another is worse than either.

Two halves, mirroring the models:

* The posture half reads the ``domain`` table and needs no reports.
* The volume half reads report rows for a :class:`Window` and returns
  :class:`~rua.readiness.VolumeSplit` counts. It is written so that "no reports
  at all" stays distinguishable from "zero in this window": callers check
  :func:`has_report_data` and emit ``null`` rather than ``0`` when it is false.
  The frontend is built on that distinction and conflating them breaks the
  day-zero state.

Sender classification is done here, in Python, by matching each source IP
against the CIDR blocks on the ``source`` table. The table is small (one row per
sending service an operator has named) and the alternative — a lateral join on
``<<=`` — makes a row that matches two overlapping ranges count twice.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass, field

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from rua.models import (
    DailyRollup,
    Domain,
    IngestOutcome,
    IngestRun,
    ReportRow,
    Source,
    SourceClass,
    TlsReport,
    TlsResultRow,
)
from rua.readiness import VolumeSplit

SIGNALS = ("dmarc", "spf", "dkim", "mtasts", "tlsrpt")

# Values that mean "this signal is absent" and "this signal is weak". Anything
# else on a non-na domain counts as healthy.
MISSING = "missing"
WARN_VALUES = frozenset({"quarantine", "none", "softfail", "partial", "testing"})

PROTECTED = "protected"
PARTIAL = "partial"
GAPS = "gaps"
NOT_APPLICABLE = "na"

# PINNED: the time window is global, one picker drives every panel. These are
# the only four values the picker offers, so they are the only four the API
# accepts; an arbitrary integer would let two panels disagree.
WINDOW_DAYS = (7, 14, 30, 90)
DEFAULT_WINDOW_DAYS = 30


# ─── Posture ─────────────────────────────────────────────────────────────────


def posture_bucket(domain: Domain) -> str:
    """Which of the four day-zero buckets a domain falls into.

    Mirrors the row severity marker in the Domains table: red if any signal is
    missing, amber if any is weak, green if clean, grey if the domain cannot
    have posture at all. The spec defines the marker but never wrote the
    aggregate mapping down, so it is written down here.
    """
    values = [getattr(domain, signal).value for signal in SIGNALS]

    if all(value == NOT_APPLICABLE for value in values):
        return NOT_APPLICABLE
    if any(value == MISSING for value in values):
        return GAPS
    if any(value in WARN_VALUES for value in values):
        return PARTIAL
    return PROTECTED


def gap_count(domain: Domain) -> int:
    """Number of ``missing`` signals. Drives the Domains table's sort and severity."""
    return sum(1 for signal in SIGNALS if getattr(domain, signal).value == MISSING)


def warn_count(domain: Domain) -> int:
    """Number of weak-but-present signals."""
    return sum(1 for signal in SIGNALS if getattr(domain, signal).value in WARN_VALUES)


def domain_posture_counts(session: Session) -> dict[str, int]:
    """Count domains per posture bucket. Empty database yields all zeros."""
    counts = {PROTECTED: 0, PARTIAL: 0, GAPS: 0, NOT_APPLICABLE: 0}
    for domain in session.scalars(select(Domain)):
        counts[posture_bucket(domain)] += 1
    return counts


def rua_mismatches(session: Session) -> list[Domain]:
    """Domains whose ``rua=`` tag points somewhere other than this deployment.

    ``IS FALSE`` only — a null means there is no DMARC record to carry a tag,
    which is a different problem and belongs in the gaps count, not in the
    "will never send you a report" list.
    """
    return list(
        session.scalars(select(Domain).where(Domain.rua_matches.is_(False)).order_by(Domain.name))
    )


# ─── Window ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Window:
    """An inclusive range of report dates ending today (UTC)."""

    days: int
    start: dt.date
    end: dt.date

    def dates(self) -> list[dt.date]:
        return [self.start + dt.timedelta(days=i) for i in range(self.days)]


def window(days: int, today: dt.date | None = None) -> Window:
    if days not in WINDOW_DAYS:
        raise ValueError(f"days must be one of {WINDOW_DAYS}, not {days}")
    end = today or dt.datetime.now(dt.UTC).date()
    return Window(days=days, start=end - dt.timedelta(days=days - 1), end=end)


# ─── Report presence ─────────────────────────────────────────────────────────


def has_report_data(session: Session) -> bool:
    """Has any DMARC aggregate report ever been ingested?

    Checks the rollup table too: after retention the raw rows are gone, and a
    tenant with two years of rollups is not on day zero.
    """
    raw = session.scalar(select(ReportRow.id).limit(1))
    if raw is not None:
        return True
    return session.scalar(select(DailyRollup.id).limit(1)) is not None


def has_tls_data(session: Session) -> bool:
    return session.scalar(select(TlsResultRow.id).limit(1)) is not None


# ─── Sender classification ───────────────────────────────────────────────────


@dataclass
class SourceClassifier:
    """Match a source IP to a named sender via the ``source`` table's CIDR blocks."""

    known: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Source]] = field(
        default_factory=list
    )

    @classmethod
    def load(cls, session: Session) -> SourceClassifier:
        classifier = cls()
        for source in session.scalars(select(Source)):
            for raw in source.ip_ranges or ():
                classifier.known.append((ipaddress.ip_network(str(raw), strict=False), source))
        # Longest prefix first, so a /32 carve-out beats the /16 around it.
        classifier.known.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
        return classifier

    def classify(self, ip: str) -> Source | None:
        address = ipaddress.ip_address(ip)
        for network, source in self.known:
            if address.version == network.version and address in network:
                return source
        return None


# ─── Volume by source ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class IpStat:
    """Window totals for one (domain, source IP) pair."""

    domain: str
    ip: str
    count: int
    aligned_pass: int
    spf_aligned: int
    dkim_aligned: int


def ip_stats(session: Session, window: Window, domain: str | None = None) -> list[IpStat]:
    """Raw report rows in the window, grouped by domain and source IP."""
    aligned = case((ReportRow.spf_aligned | ReportRow.dkim_aligned, ReportRow.count), else_=0)
    spf = case((ReportRow.spf_aligned, ReportRow.count), else_=0)
    dkim = case((ReportRow.dkim_aligned, ReportRow.count), else_=0)

    stmt = (
        select(
            ReportRow.domain_name,
            ReportRow.source_ip,
            func.sum(ReportRow.count),
            func.sum(aligned),
            func.sum(spf),
            func.sum(dkim),
        )
        .where(ReportRow.date.between(window.start, window.end))
        .group_by(ReportRow.domain_name, ReportRow.source_ip)
    )
    if domain is not None:
        stmt = stmt.where(ReportRow.domain_name == domain)

    return [
        IpStat(
            domain=name,
            ip=str(ip),
            count=int(count),
            aligned_pass=int(passed),
            spf_aligned=int(spf_count),
            dkim_aligned=int(dkim_count),
        )
        for name, ip, count, passed, spf_count, dkim_count in session.execute(stmt)
    ]


def _split(stat: IpStat, source: Source | None) -> VolumeSplit:
    failing = stat.count - stat.aligned_pass
    if source is not None and source.classification == SourceClass.KNOWN:
        return VolumeSplit(stat.aligned_pass, failing, 0)
    return VolumeSplit(stat.aligned_pass, 0, failing)


def domain_splits(session: Session, window: Window) -> dict[str, VolumeSplit]:
    """Per-domain :class:`VolumeSplit` over the window: raw rows plus rollups.

    Rollup rows only exist for dates whose raw rows retention has deleted, so
    adding the two never double counts. Domains with no rows are absent — the
    caller decides whether that means ``0`` or ``null``.
    """
    classifier = SourceClassifier.load(session)
    splits: dict[str, VolumeSplit] = {}

    for stat in ip_stats(session, window):
        part = _split(stat, classifier.classify(stat.ip))
        splits[stat.domain] = splits.get(stat.domain, VolumeSplit()) + part

    rollups = session.execute(
        select(
            DailyRollup.domain_name,
            func.sum(DailyRollup.pass_count),
            func.sum(DailyRollup.fail_known),
            func.sum(DailyRollup.fail_unclassified),
        )
        .where(DailyRollup.date.between(window.start, window.end))
        .group_by(DailyRollup.domain_name)
    )
    for name, passed, known, unclassified in rollups:
        part = VolumeSplit(int(passed), int(known), int(unclassified))
        splits[name] = splits.get(name, VolumeSplit()) + part

    return splits


def daily_splits(session: Session, window: Window) -> dict[dt.date, VolumeSplit]:
    """Tenant-wide :class:`VolumeSplit` per day in the window. Days without rows are absent."""
    classifier = SourceClassifier.load(session)
    aligned = case((ReportRow.spf_aligned | ReportRow.dkim_aligned, ReportRow.count), else_=0)

    days: dict[dt.date, VolumeSplit] = {}
    rows = session.execute(
        select(
            ReportRow.date,
            ReportRow.source_ip,
            func.sum(ReportRow.count),
            func.sum(aligned),
        )
        .where(ReportRow.date.between(window.start, window.end))
        .group_by(ReportRow.date, ReportRow.source_ip)
    )
    for date, ip, count, passed in rows:
        stat = IpStat("", str(ip), int(count), int(passed), 0, 0)
        part = _split(stat, classifier.classify(stat.ip))
        days[date] = days.get(date, VolumeSplit()) + part

    rollups = session.execute(
        select(
            DailyRollup.date,
            func.sum(DailyRollup.pass_count),
            func.sum(DailyRollup.fail_known),
            func.sum(DailyRollup.fail_unclassified),
        )
        .where(DailyRollup.date.between(window.start, window.end))
        .group_by(DailyRollup.date)
    )
    for date, passed, known, unclassified in rollups:
        part = VolumeSplit(int(passed), int(known), int(unclassified))
        days[date] = days.get(date, VolumeSplit()) + part

    return days


# ─── Sources table ───────────────────────────────────────────────────────────


@dataclass
class SourceRow:
    """One row of the Sources screen.

    Known senders are grouped by name across every IP in their ranges; an
    unclassified sender *is* its IP, because nothing else is known about it.
    """

    name: str
    classification: str
    ip: str | None
    volume: int = 0
    spf_aligned: int = 0
    dkim_aligned: int = 0
    aligned_pass: int = 0
    domains: set[str] = field(default_factory=set)

    @property
    def spf_alignment(self) -> float | None:
        return None if self.volume == 0 else 100.0 * self.spf_aligned / self.volume

    @property
    def dkim_alignment(self) -> float | None:
        return None if self.volume == 0 else 100.0 * self.dkim_aligned / self.volume


def source_rows(session: Session, window: Window, domain: str | None = None) -> list[SourceRow]:
    """The Sources table for the window, volume descending."""
    classifier = SourceClassifier.load(session)
    rows: dict[str, SourceRow] = {}

    for stat in ip_stats(session, window, domain):
        source = classifier.classify(stat.ip)
        if source is None:
            key = f"ip:{stat.ip}"
            row = rows.setdefault(
                key, SourceRow(name=stat.ip, classification="unclassified", ip=stat.ip)
            )
        else:
            key = f"org:{source.org_name}"
            row = rows.setdefault(
                key,
                SourceRow(
                    name=source.org_name, classification=source.classification.value, ip=None
                ),
            )
        row.volume += stat.count
        row.spf_aligned += stat.spf_aligned
        row.dkim_aligned += stat.dkim_aligned
        row.aligned_pass += stat.aligned_pass
        row.domains.add(stat.domain)

    return sorted(rows.values(), key=lambda r: (-r.volume, r.name))


# ─── TLS-RPT ─────────────────────────────────────────────────────────────────

# RFC 8460 §4.3 result types, and who can fix each one. TLS-RPT reports describe
# connections *to this tenant's* MX, so most failures are the policy domain's to
# fix; "sender" marks the ones where the connecting MTA is at fault. Anything
# not listed — the registry is extensible — is "unknown".
SUCCESS_RESULT = "successful-session"
TLS_FAILURE_OWNER: dict[str, str] = {
    "starttls-not-supported": "receiver",
    "certificate-host-mismatch": "receiver",
    "certificate-expired": "receiver",
    "certificate-not-trusted": "receiver",
    "validation-failure": "sender",
    "tlsa-invalid": "receiver",
    "dnssec-invalid": "receiver",
    "dane-required": "sender",
    "sts-policy-fetch-error": "receiver",
    "sts-policy-invalid": "receiver",
    "sts-webpki-invalid": "receiver",
    "unspecified-failure": "unknown",
}


@dataclass
class TlsTotals:
    successes: int = 0
    failures: int = 0

    @property
    def sessions(self) -> int:
        return self.successes + self.failures

    @property
    def success_rate(self) -> float | None:
        return None if self.sessions == 0 else 100.0 * self.successes / self.sessions


@dataclass(frozen=True, slots=True)
class TlsFailure:
    result_type: str
    count: int
    owner: str


@dataclass(frozen=True, slots=True)
class TlsReporter:
    org_name: str
    successes: int
    failures: int


def tls_totals(session: Session, window: Window, domain: str | None = None) -> TlsTotals:
    stmt = select(
        func.coalesce(func.sum(TlsResultRow.success_count), 0),
        func.coalesce(func.sum(TlsResultRow.failure_count), 0),
    ).where(TlsResultRow.date.between(window.start, window.end))
    if domain is not None:
        stmt = stmt.where(TlsResultRow.policy_domain == domain)
    successes, failures = session.execute(stmt).one()
    return TlsTotals(int(successes), int(failures))


def tls_failures(session: Session, window: Window, domain: str | None = None) -> list[TlsFailure]:
    """Failure counts by result type, descending."""
    stmt = (
        select(TlsResultRow.result_type, func.sum(TlsResultRow.failure_count))
        .where(TlsResultRow.date.between(window.start, window.end))
        .where(TlsResultRow.failure_count > 0)
        .group_by(TlsResultRow.result_type)
    )
    if domain is not None:
        stmt = stmt.where(TlsResultRow.policy_domain == domain)
    out = [
        TlsFailure(result_type=kind, count=int(count), owner=TLS_FAILURE_OWNER.get(kind, "unknown"))
        for kind, count in session.execute(stmt)
    ]
    return sorted(out, key=lambda f: (-f.count, f.result_type))


def tls_reporters(session: Session, window: Window) -> list[TlsReporter]:
    """Who sent TLS reports in the window, and what they saw. Sessions descending."""
    stmt = (
        select(
            TlsReport.org_name,
            func.sum(TlsResultRow.success_count),
            func.sum(TlsResultRow.failure_count),
        )
        .join(TlsResultRow, TlsResultRow.tls_report_pk == TlsReport.id)
        .where(TlsResultRow.date.between(window.start, window.end))
        .group_by(TlsReport.org_name)
    )
    out = [
        TlsReporter(org_name=org, successes=int(ok), failures=int(bad))
        for org, ok, bad in session.execute(stmt)
    ]
    return sorted(out, key=lambda r: (-(r.successes + r.failures), r.org_name))


# ─── Ingestion status ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class IngestStatus:
    last_run_at: dt.datetime | None
    last_outcome: str | None
    last_success_at: dt.datetime | None
    reports_parsed_total: int


def ingest_status(session: Session) -> IngestStatus:
    """What the stale banner and the day-zero page need to know about polling."""
    last = session.scalar(select(IngestRun).order_by(IngestRun.started_at.desc()).limit(1))
    last_success = session.scalar(
        select(IngestRun.started_at)
        .where(IngestRun.outcome.in_((IngestOutcome.SUCCESS, IngestOutcome.PARTIAL)))
        .order_by(IngestRun.started_at.desc())
        .limit(1)
    )
    total = session.scalar(select(func.coalesce(func.sum(IngestRun.reports_parsed), 0)))
    return IngestStatus(
        last_run_at=last.started_at if last else None,
        last_outcome=last.outcome.value if last else None,
        last_success_at=last_success,
        reports_parsed_total=int(total or 0),
    )
