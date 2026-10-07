"""The dashboard pages: Overview, Sources, Domains, drill-down, TLS.

Server-rendered Jinja with small islands of vanilla JS, as the handoff spec
recommends. Every page is built from the same functions the JSON API serves, so
a number on screen is always the number the API would return for the same
window — there is no second set of queries to drift.

The time window is global (PINNED): it travels as ``?days=`` on every page link,
and the range picker is the only thing that changes it.

The Domains table is the one surface with real interaction. Sort, search, the
gaps-only switch and pagination are all query parameters on a fragment endpoint,
so the table works with JavaScript disabled (plain links and a form) and the
island merely fetches the fragment and swaps it in without a full page load.
"""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from rua import __version__, api, presentation
from rua import settings_store as store
from rua.config import get_settings
from rua.db import get_session
from rua.logging import get_logger
from rua.models import Domain, IngestRun, Role
from rua.paths import TEMPLATES_DIR
from rua.queries import (
    DEFAULT_WINDOW_DAYS,
    WINDOW_DAYS,
    Window,
    domain_posture_counts,
    rua_mismatches,
    window,
)
from rua.retention import retention_facts
from rua.routes.setup import csrf_token
from rua.settings_store import is_demo_mode, is_setup_complete

log = get_logger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals.update(
    compact=presentation.compact_number,
    percent=presentation.percent,
    thousands=presentation.thousands,
    role_label=presentation.role_label,
    pill=presentation.pill,
    pills=presentation.pills,
    severity_tone=presentation.severity_tone,
    tile_note=presentation.tile_note,
    rate_tone=presentation.rate_tone,
    verdict_label=presentation.VERDICT_LABELS.get,
    readiness_advice=presentation.readiness_advice,
    promotion_target=presentation.promotion_target,
    SIGNAL_NAMES=presentation.SIGNAL_NAMES,
    relative_age=presentation.relative_age,
)

SessionDep = Annotated[Session, Depends(get_session)]

PAGE_SIZE = 14
SORT_KEYS = ("name", "dmarc", "spf", "dkim", "mtasts", "tlsrpt", "volume")

TABS = (
    ("overview", "Overview", "/overview"),
    ("sources", "Sources", "/sources"),
    ("domains", "Domains", "/domains"),
    ("tls", "TLS", "/tls"),
)


def _days(
    days: Annotated[int, Query(description="7, 14, 30 or 90")] = DEFAULT_WINDOW_DAYS,
) -> Window:
    # An unknown value falls back to the default rather than erroring: a stale
    # bookmark should still open the page.
    return window(days if days in WINDOW_DAYS else DEFAULT_WINDOW_DAYS)


WindowDep = Annotated[Window, Depends(_days)]


# ─── Shell context ───────────────────────────────────────────────────────────


def _tenant_name(session: Session) -> str:
    tenant = session.scalar(select(Domain.name).where(Domain.role == Role.TENANT))
    if tenant:
        return tenant
    mailbox = store.get(session, store.GRAPH_MAILBOX)
    if mailbox and "@" in mailbox:
        return mailbox.rsplit("@", 1)[1]
    return "no tenant yet"


STALE_AFTER_INTERVALS = 2


def _staleness(summary: api.OverviewSummaryResponse, demo: bool) -> dict[str, Any] | None:
    """Is the data older than it should be? None when it is not.

    Stale means no *successful* poll within two ingestion intervals. A failed
    run is not fresh data, so the age is measured from the last success, and
    the banner names that age rather than a status code. Demo mode is never
    stale: nothing is being polled.
    """
    if demo or not summary.has_reports:
        return None
    last = summary.ingest.last_success_at
    minutes = get_settings().ingest_interval_minutes
    now = dt.datetime.now(dt.UTC)
    if last is None:
        return {
            "age": "never",
            "text": "Ingestion has never completed successfully.",
            "last_outcome": summary.ingest.last_outcome,
        }
    if now - last <= STALE_AFTER_INTERVALS * dt.timedelta(minutes=minutes):
        return None
    age = presentation.relative_age(last, now)
    return {
        "age": age,
        "text": f"The last successful poll was {age}; polls run every {minutes} minutes.",
        "last_outcome": summary.ingest.last_outcome,
    }


def _ingest_pill(
    summary: api.OverviewSummaryResponse, demo: bool, stale: dict[str, Any] | None
) -> dict[str, str]:
    """The header pill: a word and a dot tone. Amber whenever something is off."""
    if demo:
        return {"text": "Sample data", "tone": "ok"}
    if not summary.has_reports:
        return {"text": "Waiting for first reports", "tone": "warn"}
    if stale is not None:
        return {"text": "Stale: last success " + stale["age"], "tone": "warn"}
    age = presentation.relative_age(summary.ingest.last_success_at)
    return {"text": f"Last poll {age}", "tone": "ok"}


def _shell(request: Request, session: Session, win: Window, tab: str) -> dict[str, Any]:
    summary = api.overview_summary(session, win)
    demo = is_demo_mode(session) and not is_setup_complete(session)
    stale = _staleness(summary, demo)
    return {
        "version": __version__,
        "tab": tab,
        "tabs": [
            {"key": key, "label": label, "href": f"{path}?days={win.days}"}
            for key, label, path in TABS
        ],
        "win": win,
        "window_options": WINDOW_DAYS,
        "tenant_name": _tenant_name(session),
        "demo_mode": demo,
        "pill": _ingest_pill(summary, demo, stale),
        "stale": stale,
        "summary": summary,
        "path": request.url.path,
        "day_zero": not summary.has_reports and not demo,
        "signed_in": request.session.get("admin_id") == 1,
        "csrf_token": csrf_token(request),
    }


def _render(request: Request, name: str, context: dict[str, Any]) -> Response:
    return templates.TemplateResponse(request, name, context)


# ─── Domains table ───────────────────────────────────────────────────────────


def _sort_key(sort: str):
    if sort in presentation.SIGNAL_NAMES:
        # Status columns sort by severity, not alphabetically (spec, Interactions).
        return lambda d: (presentation.SEVERITY.get(getattr(d, sort), 9), d.name)
    return lambda d: d.name


def _table(
    session: Session,
    win: Window,
    q: str,
    gaps: bool,
    sort: str,
    direction: str,
    page: int,
) -> dict[str, Any]:
    response = api.domains(session, win)
    rows = response.domains
    total = len(rows)

    needle = q.strip().lower()
    if needle:
        rows = [d for d in rows if needle in d.name]
    if gaps:
        rows = [d for d in rows if d.gaps > 0]

    sort = sort if sort in SORT_KEYS else "name"
    descending = direction == "desc"
    if sort == "volume":
        # Pending volume (null) is not a small number; those rows always sort last.
        pending = [d for d in rows if d.volume is None]
        rows = sorted(
            (d for d in rows if d.volume is not None),
            key=lambda d: (d.volume, d.name),
            reverse=descending,
        )
        rows.extend(pending)
    else:
        rows.sort(key=_sort_key(sort), reverse=descending)

    matched = len(rows)
    pages = max(1, (matched + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(page, 0), pages - 1)
    start = page * PAGE_SIZE
    visible = rows[start : start + PAGE_SIZE]

    hint = ""
    if not visible:
        if needle and gaps:
            hint = "No domain matches that search and has a missing signal. Try one or the other."
        elif needle:
            hint = "No domain name contains that text."
        elif gaps:
            hint = "Every domain has all five signals configured. Nothing to fix here."
        else:
            hint = "No domains yet. The daily sync reads them from your tenant."

    return {
        "rows": visible,
        "has_reports": response.has_reports,
        "total": total,
        "matched": matched,
        "page": page,
        "pages": pages,
        "range_start": start + 1 if visible else 0,
        "range_end": start + len(visible),
        "q": q,
        "gaps": gaps,
        "sort": sort,
        "dir": "desc" if descending else "asc",
        "empty_hint": hint,
        "sort_keys": SORT_KEYS,
    }


def _table_params(
    q: str = "",
    gaps: int = 0,
    sort: str = "name",
    dir: str = "asc",  # mirrors the query parameter name
    page: int = 0,
) -> dict[str, Any]:
    return {"q": q[:253], "gaps": bool(gaps), "sort": sort, "direction": dir, "page": page}


TableParams = Annotated[dict[str, Any], Depends(_table_params)]


# ─── Pages ───────────────────────────────────────────────────────────────────


@router.get("/", response_class=HTMLResponse, name="home")
def home(request: Request, session: SessionDep, win: WindowDep) -> Response:
    """The waiting page until the first report parses, then the Overview, for good.

    The switch is on the data, not on a flag, so it cannot be left behind: the
    moment ``has_report_data`` is true the page is the Overview, and there is no
    stale banner to clean up because the banner never belonged to this page.
    """
    ctx = _shell(request, session, win, "overview")
    if ctx["day_zero"]:
        return _render(request, "dashboard/dayzero.html", _day_zero(session, ctx))
    return _overview(request, session, win, ctx)


@router.get("/overview", response_class=HTMLResponse, name="overview_page")
def overview(request: Request, session: SessionDep, win: WindowDep) -> Response:
    """The Overview even on day zero: the waiting page's "Go to the dashboard" lands here."""
    return _overview(request, session, win, _shell(request, session, win, "overview"))


def _overview(request: Request, session: Session, win: Window, ctx: dict[str, Any]) -> Response:
    trend = api.overview_trend(session, win)
    ctx["trend"] = trend
    ctx["chart"] = _chart_geometry(trend)
    ctx["attention"] = _needs_attention(session, win)
    return _render(request, "dashboard/overview.html", ctx)


def _day_zero(session: Session, ctx: dict[str, Any]) -> dict[str, Any]:
    """Facts for the waiting page: polling status, DNS counts, rua= mismatches."""
    ingest = ctx["summary"].ingest
    minutes = get_settings().ingest_interval_minutes
    next_poll = ingest.last_run_at + dt.timedelta(minutes=minutes) if ingest.last_run_at else None
    ctx.update(
        counts=domain_posture_counts(session),
        mismatches=rua_mismatches(session),
        last_poll=ingest.last_run_at,
        last_outcome=ingest.last_outcome,
        next_poll=next_poll,
        reports_parsed=ingest.reports_parsed_total,
        poll_minutes=minutes,
    )
    return ctx


@router.get("/settings", response_class=HTMLResponse, name="settings_page")
def settings_page(request: Request, session: SessionDep, win: WindowDep) -> Response:
    """What this deployment is configured to do, and what it holds. Secrets never appear."""
    settings = get_settings()
    ctx = _shell(request, session, win, "settings")
    ctx.update(
        facts=retention_facts(session),
        raw_days=settings.retention_raw_days,
        rollup_days=settings.retention_rollup_days,
        retention_hour=(settings.domain_sync_hour + 1) % 24,
        sync_hour=settings.domain_sync_hour,
        poll_minutes=settings.ingest_interval_minutes,
        alerting=settings.alerting_enabled,
        graph={
            "tenant_id": store.get(session, store.GRAPH_TENANT_ID),
            "client_id": store.get(session, store.GRAPH_CLIENT_ID),
            "mailbox": store.get(session, store.GRAPH_MAILBOX),
            "scoping": store.get(session, store.SETUP_SCOPING_MODE),
        },
        last_sync=store.get(session, "domains.last_sync_at"),
        setup_complete=is_setup_complete(session),
        runs=list(
            session.scalars(select(IngestRun).order_by(IngestRun.started_at.desc()).limit(10))
        ),
    )
    return _render(request, "dashboard/settings.html", ctx)


@router.get("/settings/ingestion", response_class=HTMLResponse, name="ingestion_log")
def ingestion_log(request: Request, session: SessionDep, win: WindowDep) -> Response:
    """The ingestion log: every run, newest first. The error state's "view log" lands here."""
    ctx = _shell(request, session, win, "settings")
    ctx["runs"] = list(
        session.scalars(select(IngestRun).order_by(IngestRun.started_at.desc()).limit(100))
    )
    return _render(request, "dashboard/ingestion_log.html", ctx)


# ─── Error state ─────────────────────────────────────────────────────────────


async def render_error(request: Request, exc: Exception) -> Response:
    """The error state for any page that failed to build.

    Registered on the app for unhandled exceptions. API paths get JSON; pages
    get the spec's error panel: what failed, the request that failed, and a
    way to retry or read the ingestion log. The shell is rendered without a
    database round-trip, because the database is the likeliest thing to be
    broken.
    """
    log.error("page_failed", path=request.url.path, error_type=type(exc).__name__)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Internal error", "path": request.url.path}, status_code=500)

    raw = request.query_params.get("days", "")
    win = window(int(raw) if raw.isdigit() and int(raw) in WINDOW_DAYS else DEFAULT_WINDOW_DAYS)
    target = request.url.path + ("?" + request.url.query if request.url.query else "")
    return templates.TemplateResponse(
        request,
        "dashboard/error.html",
        {
            "version": __version__,
            "tab": None,
            "tabs": [
                {"key": key, "label": label, "href": f"{path}?days={win.days}"}
                for key, label, path in TABS
            ],
            "win": win,
            "window_options": WINDOW_DAYS,
            "tenant_name": "",
            "demo_mode": False,
            "pill": {"text": "Error", "tone": "warn"},
            "signed_in": False,
            "stale": None,
            "day_zero": False,
            "path": request.url.path,
            "request_line": f"GET {target}",
            "retry_href": target,
            "error_type": type(exc).__name__,
        },
        status_code=500,
    )


@router.get("/domains", response_class=HTMLResponse, name="domains_page")
def domains_page(
    request: Request, session: SessionDep, win: WindowDep, params: TableParams
) -> Response:
    ctx = _shell(request, session, win, "domains")
    ctx["table"] = _table(session, win, **params)
    return _render(request, "dashboard/domains.html", ctx)


@router.get("/fragments/domains-table", response_class=HTMLResponse, name="domains_table")
def domains_table(
    request: Request, session: SessionDep, win: WindowDep, params: TableParams
) -> Response:
    """The table alone, for the island to swap in. Same parameters as the page."""
    return _render(
        request,
        "dashboard/_domains_table.html",
        {"table": _table(session, win, **params), "win": win},
    )


@router.get("/domains/{name}", response_class=HTMLResponse, name="domain_page")
def domain_page(name: str, request: Request, session: SessionDep, win: WindowDep) -> Response:
    try:
        detail = api.domain_detail(name, session, win)
    except HTTPException as exc:
        if exc.status_code == 404:
            ctx = _shell(request, session, win, "domains")
            ctx["missing_name"] = name
            return templates.TemplateResponse(
                request, "dashboard/domain_missing.html", ctx, status_code=404
            )
        raise
    ctx = _shell(request, session, win, "domains")
    ctx["detail"] = detail
    ctx["d"] = detail.domain
    ctx["bar"] = _readiness_bar(detail.domain)
    return _render(request, "dashboard/domain.html", ctx)


@router.get("/sources", response_class=HTMLResponse, name="sources_page")
def sources_page(request: Request, session: SessionDep, win: WindowDep) -> Response:
    ctx = _shell(request, session, win, "sources")
    ctx["sources"] = api.sources(session, win, None)
    return _render(request, "dashboard/sources.html", ctx)


@router.get("/tls", response_class=HTMLResponse, name="tls_page")
def tls_page(request: Request, session: SessionDep, win: WindowDep) -> Response:
    ctx = _shell(request, session, win, "tls")
    ctx["tls"] = api.tls_summary(session, win, None)
    return _render(request, "dashboard/tls.html", ctx)


# ─── View models ─────────────────────────────────────────────────────────────

CHART_W, CHART_H = 900, 240
Y_MIN, Y_MAX = 80.0, 100.0


def _chart_geometry(trend: api.TrendResponse) -> dict[str, Any]:
    """Line and area paths for the trend SVG, with the Y domain fixed at 80-100%.

    Pass rates below 80% are clamped to the floor — the spec fixes the domain on
    purpose ("pass rates below 80% are a different problem") — and days with no
    volume break the line rather than being drawn as zero.
    """
    points = trend.points
    n = len(points)
    step = CHART_W / max(1, n - 1)

    def y_of(rate: float) -> float:
        clamped = min(Y_MAX, max(Y_MIN, rate))
        return CHART_H - (clamped - Y_MIN) / (Y_MAX - Y_MIN) * CHART_H

    segments: list[list[tuple[float, float]]] = []
    current: list[tuple[float, float]] = []
    for i, point in enumerate(points):
        if point.pass_rate is None:
            if current:
                segments.append(current)
                current = []
            continue
        current.append((round(i * step, 1), round(y_of(point.pass_rate), 1)))
    if current:
        segments.append(current)

    line = " ".join(
        "M" + " L".join(f"{x},{y}" for x, y in seg) for seg in segments if len(seg) >= 1
    )
    area = ""
    for seg in segments:
        if len(seg) < 2:
            continue
        area += (
            f"M{seg[0][0]},{CHART_H} L"
            + " L".join(f"{x},{y}" for x, y in seg)
            + f" L{seg[-1][0]},{CHART_H} Z "
        )

    # Four to six x ticks, spread evenly, always including the first and last day.
    tick_count = 4 if n <= 14 else 6
    idx = sorted({round(i * (n - 1) / (tick_count - 1)) for i in range(tick_count)}) if n else []
    ticks = [points[i].date.strftime("%d %b").lstrip("0") for i in idx]

    return {
        "line": line.strip(),
        "area": area.strip(),
        "gridlines": [(100, 0), (95, 60), (90, 120), (85, 180), (80, 240)],
        "ticks": ticks,
        "has_line": bool(line.strip()),
    }


def _readiness_bar(d: api.DomainRecord) -> dict[str, Any]:
    """The three-segment stacked bar's percentages and counts."""
    detail = d.readiness_detail
    if detail is None or d.volume in (None, 0):
        return {"ok": 0.0, "warn": 0.0, "gap": 0.0, "empty": True}
    total = d.volume
    return {
        "ok": 100.0 * detail.aligned_pass / total,
        "warn": 100.0 * detail.fail_known / total,
        "gap": 100.0 * detail.fail_unclassified / total,
        "empty": False,
    }


def _needs_attention(session: Session, win: Window) -> list[api.DomainRecord]:
    """Eight domains with the most to fix, for the Overview's attention strip."""
    rows = [d for d in api.domains(session, win).domains if d.dmarc != "na"]
    rows.sort(key=lambda d: (-d.gaps, -d.warns, -(d.volume or 0), d.name))
    return [d for d in rows if d.gaps or d.warns][:8]
