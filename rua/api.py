"""The JSON API: six endpoints from the handoff spec, plus per-domain detail.

Every report-derived figure — ``volume``, ``pass_rate``, ``readiness``, TLS rates —
is ``null`` until a report has been ingested. **Not zero, not omitted.** The
frontend tells "no data yet" from "zero" by that null, and the day-zero screen
is built on the distinction: posture columns are ``ready`` while volume columns
are ``empty``, on the same row, at the same time.

Once any report exists, a domain that simply has no rows in the window reports
``volume: 0`` — that is a real zero (a parked domain sends nothing) — and a null
``pass_rate`` and ``readiness``, because a rate over nothing is not a number.

The time window is global (PINNED). ``days`` accepts exactly the four values the
range picker offers, so two panels can never disagree about what "30d" means.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from rua import queries
from rua.db import get_session
from rua.models import Domain
from rua.queries import DEFAULT_WINDOW_DAYS, WINDOW_DAYS, Window
from rua.readiness import (
    Verdict,
    VolumeSplit,
    pass_rate,
    readiness,
    verdict,
)

router = APIRouter(prefix="/api", tags=["api"])

SessionDep = Annotated[Session, Depends(get_session)]


def _window(
    days: Annotated[
        int,
        Query(
            description="Window length in days. One of 7, 14, 30, 90 — the range picker's values."
        ),
    ] = DEFAULT_WINDOW_DAYS,
) -> Window:
    # A Literal[7, 14, 30, 90] annotation would not coerce the query string "7",
    # so the check is explicit and the error says what is accepted.
    if days not in WINDOW_DAYS:
        raise HTTPException(
            status_code=422, detail=f"days must be one of {', '.join(map(str, WINDOW_DAYS))}"
        )
    return queries.window(days)


WindowDep = Annotated[Window, Depends(_window)]


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 2)


# ─── Shapes ──────────────────────────────────────────────────────────────────


class ReadinessDetail(BaseModel):
    """The three-way split behind the readiness figure, and the verdict it supports."""

    aligned_pass: int
    fail_known: int
    fail_unclassified: int
    verdict: Verdict


class DomainRecord(BaseModel):
    """The shape the Domains table and the drill-down tiles need — spec, "Domain record"."""

    name: str
    role: str
    dmarc: str
    spf: str
    dkim: str
    mtasts: str
    tlsrpt: str
    volume: int | None = Field(description="Messages in the window. null until reports exist.")
    pass_rate: float | None = Field(description="DMARC pass %. null without volume.")
    readiness: float | None = Field(description="See rua.readiness. null without volume.")
    # The spec's draft had a plain bool. The implementation is tri-state: null means
    # there is no DMARC record to carry a rua= tag, which is a gap, not a mismatch.
    rua_matches: bool | None
    rua_value: str | None
    gaps: int
    warns: int
    dns_checked: dt.datetime | None
    readiness_detail: ReadinessDetail | None


class DomainsResponse(BaseModel):
    window_days: int
    has_reports: bool
    domains: list[DomainRecord]


class SourceRecord(BaseModel):
    name: str
    ip: str | None = Field(description="Set for unclassified senders, which are their IP.")
    classification: str
    volume: int
    spf_alignment: float | None
    dkim_alignment: float | None
    pass_rate: float | None
    domain_count: int


class SourcesResponse(BaseModel):
    window_days: int
    has_reports: bool
    domain: str | None
    sources: list[SourceRecord]


class TlsFailureRecord(BaseModel):
    result_type: str
    count: int
    owner: str = Field(description="receiver (yours to fix), sender, or unknown.")


class TlsReporterRecord(BaseModel):
    org_name: str
    successes: int
    failures: int
    success_rate: float | None


class TlsSummaryResponse(BaseModel):
    window_days: int
    has_tls_reports: bool
    domain: str | None
    sessions: int | None
    successes: int | None
    failures_total: int | None
    success_rate: float | None
    failures: list[TlsFailureRecord]
    reporters: list[TlsReporterRecord]


class DomainDetailResponse(BaseModel):
    window_days: int
    has_reports: bool
    domain: DomainRecord
    sources: list[SourceRecord]
    tls: TlsSummaryResponse


class TrendPoint(BaseModel):
    date: dt.date
    volume: int | None
    pass_rate: float | None


class TrendResponse(BaseModel):
    window_days: int
    has_reports: bool
    points: list[TrendPoint]


class ReadinessCallout(BaseModel):
    """The one domain the Overview suggests looking at next."""

    domain: str
    role: str
    dmarc: str
    volume: int
    readiness: float | None
    verdict: Verdict
    failing_volume: int
    unclassified_volume: int


class IngestInfo(BaseModel):
    last_run_at: dt.datetime | None
    last_outcome: str | None
    last_success_at: dt.datetime | None
    reports_parsed_total: int


class OverviewSummaryResponse(BaseModel):
    window_days: int
    has_reports: bool
    has_tls_reports: bool
    domains_monitored: int
    domains_with_gaps: int
    rua_mismatches: int
    dmarc_pass_rate: float | None
    tls_success_rate: float | None
    message_volume: int | None
    tls_sessions: int | None
    readiness_callout: ReadinessCallout | None
    ingest: IngestInfo


# ─── Assembly ────────────────────────────────────────────────────────────────


def _domain_record(domain: Domain, split: VolumeSplit | None, has_reports: bool) -> DomainRecord:
    """Build one record. ``split`` is None when the domain had no rows in the window."""
    if not has_reports:
        volume = rate = score = None
        detail = None
    else:
        split = split or VolumeSplit()
        volume = split.total
        rate = _round(pass_rate(split))
        score = _round(readiness(split))
        detail = ReadinessDetail(
            aligned_pass=split.aligned_pass,
            fail_known=split.fail_known,
            fail_unclassified=split.fail_unclassified,
            verdict=verdict(split, domain.dmarc.value),
        )

    return DomainRecord(
        name=domain.name,
        role=domain.role.value,
        dmarc=domain.dmarc.value,
        spf=domain.spf.value,
        dkim=domain.dkim.value,
        mtasts=domain.mtasts.value,
        tlsrpt=domain.tlsrpt.value,
        volume=volume,
        pass_rate=rate,
        readiness=score,
        rua_matches=domain.rua_matches,
        rua_value=domain.rua_value,
        gaps=queries.gap_count(domain),
        warns=queries.warn_count(domain),
        dns_checked=domain.dns_checked_at,
        readiness_detail=detail,
    )


def _source_record(row: queries.SourceRow) -> SourceRecord:
    return SourceRecord(
        name=row.name,
        ip=row.ip,
        classification=row.classification,
        volume=row.volume,
        spf_alignment=_round(row.spf_alignment),
        dkim_alignment=_round(row.dkim_alignment),
        pass_rate=_round(None if row.volume == 0 else 100.0 * row.aligned_pass / row.volume),
        domain_count=len(row.domains),
    )


def _tls_summary(session: Session, win: Window, domain: str | None) -> TlsSummaryResponse:
    has_tls = queries.has_tls_data(session)
    if not has_tls:
        return TlsSummaryResponse(
            window_days=win.days,
            has_tls_reports=False,
            domain=domain,
            sessions=None,
            successes=None,
            failures_total=None,
            success_rate=None,
            failures=[],
            reporters=[],
        )

    totals = queries.tls_totals(session, win, domain)
    return TlsSummaryResponse(
        window_days=win.days,
        has_tls_reports=True,
        domain=domain,
        sessions=totals.sessions,
        successes=totals.successes,
        failures_total=totals.failures,
        success_rate=_round(totals.success_rate),
        failures=[
            TlsFailureRecord(result_type=f.result_type, count=f.count, owner=f.owner)
            for f in queries.tls_failures(session, win, domain)
        ],
        reporters=[]
        if domain is not None
        else [
            TlsReporterRecord(
                org_name=r.org_name,
                successes=r.successes,
                failures=r.failures,
                success_rate=_round(
                    None
                    if r.successes + r.failures == 0
                    else 100.0 * r.successes / (r.successes + r.failures)
                ),
            )
            for r in queries.tls_reporters(session, win)
        ],
    )


def _callout(domains: list[Domain], splits: dict[str, VolumeSplit]) -> ReadinessCallout | None:
    """Pick the domain closest to a safe policy upgrade.

    Candidates publish a DMARC policy weaker than reject and sent mail in the
    window. ``ready`` verdicts rank first, then the readiness figure, then
    volume — so the suggestion is the biggest safe step, not the easiest one.
    """
    ranked: list[tuple[tuple, Domain, VolumeSplit, Verdict]] = []
    for domain in domains:
        if domain.dmarc.value not in ("none", "quarantine"):
            continue
        split = splits.get(domain.name)
        if split is None or split.total == 0:
            continue
        decision = verdict(split, domain.dmarc.value)
        score = readiness(split)
        key = (
            0 if decision == "ready" else 1,
            -(score if score is not None else -1.0),
            -split.total,
        )
        ranked.append((key, domain, split, decision))

    if not ranked:
        return None
    _, domain, split, decision = min(ranked, key=lambda item: item[0])
    return ReadinessCallout(
        domain=domain.name,
        role=domain.role.value,
        dmarc=domain.dmarc.value,
        volume=split.total,
        readiness=_round(readiness(split)),
        verdict=decision,
        failing_volume=split.failing,
        unclassified_volume=split.fail_unclassified,
    )


# ─── Endpoints ───────────────────────────────────────────────────────────────


@router.get("/overview/summary", summary="Overview metric cards and readiness callout")
def overview_summary(session: SessionDep, win: WindowDep) -> OverviewSummaryResponse:
    domains = list(session.scalars(select(Domain).order_by(Domain.name)))
    has_reports = queries.has_report_data(session)
    has_tls = queries.has_tls_data(session)

    splits = queries.domain_splits(session, win) if has_reports else {}
    total = sum(splits.values(), VolumeSplit())
    tls = queries.tls_totals(session, win) if has_tls else None
    status = queries.ingest_status(session)

    return OverviewSummaryResponse(
        window_days=win.days,
        has_reports=has_reports,
        has_tls_reports=has_tls,
        domains_monitored=len(domains),
        domains_with_gaps=sum(1 for d in domains if queries.gap_count(d) > 0),
        rua_mismatches=sum(1 for d in domains if d.rua_matches is False),
        dmarc_pass_rate=_round(pass_rate(total)) if has_reports else None,
        tls_success_rate=_round(tls.success_rate) if tls else None,
        message_volume=total.total if has_reports else None,
        tls_sessions=tls.sessions if tls else None,
        readiness_callout=_callout(domains, splits) if has_reports else None,
        ingest=IngestInfo(
            last_run_at=status.last_run_at,
            last_outcome=status.last_outcome,
            last_success_at=status.last_success_at,
            reports_parsed_total=status.reports_parsed_total,
        ),
    )


@router.get("/overview/trend", summary="Daily aligned-pass rate for the trend chart")
def overview_trend(session: SessionDep, win: WindowDep) -> TrendResponse:
    has_reports = queries.has_report_data(session)
    daily = queries.daily_splits(session, win) if has_reports else {}

    points = []
    for date in win.dates():
        if not has_reports:
            points.append(TrendPoint(date=date, volume=None, pass_rate=None))
            continue
        split = daily.get(date, VolumeSplit())
        points.append(TrendPoint(date=date, volume=split.total, pass_rate=_round(pass_rate(split))))

    return TrendResponse(window_days=win.days, has_reports=has_reports, points=points)


@router.get("/sources", summary="Who is sending mail as your domains")
def sources(
    session: SessionDep,
    win: WindowDep,
    domain: Annotated[str | None, Query(description="Restrict to one domain.")] = None,
) -> SourcesResponse:
    has_reports = queries.has_report_data(session)
    rows = queries.source_rows(session, win, domain) if has_reports else []
    return SourcesResponse(
        window_days=win.days,
        has_reports=has_reports,
        domain=domain,
        sources=[_source_record(r) for r in rows],
    )


@router.get("/domains", summary="Every domain's posture, with window volume")
def domains(session: SessionDep, win: WindowDep) -> DomainsResponse:
    has_reports = queries.has_report_data(session)
    splits = queries.domain_splits(session, win) if has_reports else {}
    rows = session.scalars(select(Domain).order_by(Domain.name))
    return DomainsResponse(
        window_days=win.days,
        has_reports=has_reports,
        domains=[_domain_record(d, splits.get(d.name), has_reports) for d in rows],
    )


@router.get("/domains/{name}", summary="One domain: posture, readiness, sources and TLS")
def domain_detail(name: str, session: SessionDep, win: WindowDep) -> DomainDetailResponse:
    domain = session.scalar(select(Domain).where(Domain.name == name.strip().lower()))
    if domain is None:
        raise HTTPException(status_code=404, detail="No such domain")

    has_reports = queries.has_report_data(session)
    split = queries.domain_splits(session, win).get(domain.name) if has_reports else None
    rows = queries.source_rows(session, win, domain.name) if has_reports else []
    return DomainDetailResponse(
        window_days=win.days,
        has_reports=has_reports,
        domain=_domain_record(domain, split, has_reports),
        sources=[_source_record(r) for r in rows],
        tls=_tls_summary(session, win, domain.name),
    )


@router.get("/tls/summary", summary="TLS-RPT results: success rate, failures, reporters")
def tls_summary(
    session: SessionDep,
    win: WindowDep,
    domain: Annotated[str | None, Query(description="Restrict to one policy domain.")] = None,
) -> TlsSummaryResponse:
    return _tls_summary(session, win, domain)
