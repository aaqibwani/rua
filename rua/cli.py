"""Console entry points.

``pyproject.toml`` installs a single ``rua`` script; the Dockerfile and
``docker-compose.yml`` both invoke it:

    rua serve      — FastAPI, API and frontend
    rua scheduler  — ingestion poll and daily domain sync

argparse rather than click or typer: uvicorn already brings click in, but a CLI
this small does not justify a dependency of its own.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from rua import __version__
from rua.seed import DEFAULT_DEMO_MAILBOX, DEFAULT_TENANT_PREFIX


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rua",
        description="Self-hosted DMARC and TLS posture dashboard.",
    )
    parser.add_argument("--version", action="version", version=f"rua {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    serve = sub.add_parser("serve", help="Run the web application.")
    serve.add_argument("--host", default="127.0.0.1", help="Bind address (default: %(default)s)")
    serve.add_argument("--port", type=int, default=8080, help="Bind port (default: %(default)s)")
    serve.add_argument(
        "--reload",
        action="store_true",
        help="Reload on source changes. Development only.",
    )

    sub.add_parser("scheduler", help="Run the ingestion and domain-sync scheduler.")
    sub.add_parser("sync-domains", help="Pull verified domains and re-check their DNS now.")
    sub.add_parser("retention", help="Roll up and delete report data past its retention now.")
    sub.add_parser("migrate", help="Apply database migrations (alembic upgrade head).")
    sub.add_parser(
        "reset-setup",
        help="Reopen the setup wizard at the credentials step. Keeps the admin and all data.",
    )

    seed = sub.add_parser("seed", help="Load sample data.")
    seed.add_argument(
        "--demo",
        action="store_true",
        help="Load the deterministic 60-domain demo dataset. Idempotent.",
    )
    seed.add_argument(
        "--tenant-prefix",
        default=DEFAULT_TENANT_PREFIX,
        help="Prefix for the <prefix>.onmicrosoft.com tenant row (default: %(default)s).",
    )
    seed.add_argument(
        "--mailbox",
        default=DEFAULT_DEMO_MAILBOX,
        help="Mailbox the demo rua= tags point at (default: %(default)s).",
    )
    seed.add_argument(
        "--domains-only",
        action="store_true",
        help="Seed the 60 domains but no demo reports (volume, sources, TLS results).",
    )

    return parser


def _migrate() -> int:
    """``alembic upgrade head`` without needing the alembic CLI or a cwd.

    Also run by ``rua serve`` on start, so `docker compose up` on a fresh
    volume produces a working instance rather than a 503 and a README step.
    """
    from alembic import command
    from alembic.config import Config

    from rua.paths import alembic_ini

    command.upgrade(Config(str(alembic_ini())), "head")
    return 0


def _reset_setup() -> int:
    from rua.config import get_settings
    from rua.db import session_scope
    from rua.logging import configure_logging
    from rua.wizard import reset_setup

    configure_logging(get_settings().log_level)
    with session_scope() as session:
        reset_setup(session)
    print(
        "Setup reopened at the credentials step. The admin account, domains and reports "
        "are kept; open the dashboard URL to re-enter the Graph credentials."
    )
    return 0


def _serve(host: str, port: int, reload: bool) -> int:
    import uvicorn

    from rua.config import get_settings
    from rua.logging import configure_logging, get_logger

    settings = get_settings()
    configure_logging(settings.log_level)
    try:
        _migrate()
    except Exception as exc:  # the server still starts; /healthz reports the database
        get_logger("rua.serve").error("migration_failed", error_type=type(exc).__name__)
    uvicorn.run(
        "rua.main:app",
        host=host,
        port=port,
        reload=reload,
        # Logging is configured by the application's lifespan handler, as JSON to
        # stdout. Letting uvicorn install its own dictConfig would undo that.
        log_config=None,
        log_level=settings.log_level.lower(),
        access_log=False,
    )
    return 0


def _ingest_job() -> None:
    """One mailbox poll.

    Wrapped so that nothing escapes into APScheduler. ``run_ingestion`` already
    records operational failures — an expired secret, a 401, a malformed report —
    rather than raising, so anything reaching this handler is a bug. Even then
    the process must stay up: Compose restarts it `unless-stopped`, and a crash
    loop would take the scheduler out entirely over a single bad report.
    """
    from rua.db import session_scope
    from rua.ingest import run_ingestion
    from rua.logging import get_logger

    log = get_logger("rua.scheduler")
    try:
        with session_scope() as session:
            run_ingestion(session)
    except Exception as exc:
        log.exception("ingest_job_crashed", error_type=type(exc).__name__)


def _domain_sync_job() -> None:
    """Graph /domains plus a live DNS check of every domain. Same crash rule."""
    from rua.db import session_scope
    from rua.domain_sync import run_domain_sync
    from rua.logging import get_logger

    log = get_logger("rua.scheduler")
    try:
        with session_scope() as session:
            result = run_domain_sync(session)
        if not result.ok:
            log.warning("domain_sync_failed", error=result.error_text)
    except Exception as exc:
        log.exception("domain_sync_job_crashed", error_type=type(exc).__name__)


def _retention_job() -> None:
    """Nightly rollup and delete. Same crash rule as the other jobs."""
    from rua.config import get_settings
    from rua.db import session_scope
    from rua.logging import get_logger
    from rua.retention import run_retention

    log = get_logger("rua.scheduler")
    settings = get_settings()
    try:
        with session_scope() as session:
            run_retention(session, settings.retention_raw_days, settings.retention_rollup_days)
    except Exception as exc:
        log.exception("retention_job_crashed", error_type=type(exc).__name__)


def _retention_now() -> int:
    """``rua retention``: the nightly job, on demand — after shortening a window, say."""
    from rua.config import get_settings
    from rua.db import session_scope
    from rua.logging import configure_logging
    from rua.retention import run_retention

    settings = get_settings()
    configure_logging(settings.log_level)
    with session_scope() as session:
        r = run_retention(session, settings.retention_raw_days, settings.retention_rollup_days)
    print(
        f"Rolled up {r.days_rolled_up} days into {r.rollups_written} daily rows; deleted "
        f"{r.raw_rows_deleted} raw rows, {r.tls_rows_deleted} TLS rows, "
        f"{r.rollups_deleted} rollups older than {settings.retention_rollup_days} days."
    )
    return 0


def _sync_domains_now() -> int:
    """``rua sync-domains``: the daily job, on demand.

    The wizard's final step shows a verified-domain count, and an operator who
    has just fixed a DNS record should not have to wait until DOMAIN_SYNC_HOUR.
    """
    from rua.config import get_settings
    from rua.db import session_scope
    from rua.domain_sync import run_domain_sync
    from rua.logging import configure_logging

    configure_logging(get_settings().log_level)
    with session_scope() as session:
        result = run_domain_sync(session)

    if not result.ok:
        print(f"Domain sync failed: {result.error_text}", file=sys.stderr)
        return 1
    print(
        f"Checked {result.domains_seen} domains: {result.created} new, "
        f"{result.updated} updated, {result.unresolved} with an unresolved lookup."
    )
    return 0


def _scheduler() -> int:
    import datetime as dt

    from apscheduler.schedulers.blocking import BlockingScheduler

    from rua.config import get_settings
    from rua.logging import configure_logging, get_logger

    settings = get_settings()
    configure_logging(settings.log_level)
    log = get_logger("rua.scheduler")

    scheduler = BlockingScheduler(timezone="UTC")

    scheduler.add_job(
        _ingest_job,
        trigger="interval",
        minutes=settings.ingest_interval_minutes,
        id="ingest",
        name="Poll the report mailbox",
        # A slow run must not queue up behind itself, and a missed slot should be
        # dropped rather than replayed — the next poll covers the same ground.
        max_instances=1,
        coalesce=True,
        misfire_grace_time=300,
        next_run_time=dt.datetime.now(dt.UTC) + dt.timedelta(seconds=15),
    )

    scheduler.add_job(
        _domain_sync_job,
        trigger="cron",
        hour=settings.domain_sync_hour,
        minute=0,
        id="domain_sync",
        name="Sync verified domains and re-check DNS",
        max_instances=1,
        coalesce=True,
        # A daily job that misses its slot by a container restart should still
        # run that day rather than wait for tomorrow.
        misfire_grace_time=6 * 3600,
    )

    scheduler.add_job(
        _retention_job,
        trigger="cron",
        hour=(settings.domain_sync_hour + 1) % 24,
        minute=0,
        id="retention",
        name="Roll up and delete report data past retention",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=6 * 3600,
    )

    log.info(
        "scheduler_starting",
        registered_jobs=len(scheduler.get_jobs()),
        ingest_interval_minutes=settings.ingest_interval_minutes,
        domain_sync_hour=settings.domain_sync_hour,
    )

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("scheduler_stopping")
        scheduler.shutdown(wait=False)
    return 0


def _seed(demo: bool, tenant_prefix: str, mailbox: str, domains_only: bool = False) -> int:
    from rua.config import get_settings
    from rua.db import session_scope
    from rua.logging import configure_logging, get_logger
    from rua.seed import seed_demo

    if not demo:
        print(
            "Nothing to seed. Pass --demo to load the deterministic 60-domain "
            "demo dataset; it is currently the only dataset.",
            file=sys.stderr,
        )
        return 2

    configure_logging(get_settings().log_level)
    log = get_logger("rua.seed")

    from rua.seed_reports import seed_demo_reports

    with session_scope() as session:
        created, updated = seed_demo(session, tenant_prefix=tenant_prefix, mailbox=mailbox)
        reports = tls = 0
        if not domains_only:
            reports, tls = seed_demo_reports(session, tenant_prefix=tenant_prefix, mailbox=mailbox)

    log.info("seed_demo_written", created=created, updated=updated, reports=reports, tls=tls)
    print(
        f"Seeded demo data: {created} domains created, {updated} updated; "
        f"{reports} aggregate reports and {tls} TLS reports over the last 90 days."
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``rua`` console script."""
    args = _build_parser().parse_args(argv)

    if args.command == "serve":
        return _serve(args.host, args.port, args.reload)
    if args.command == "scheduler":
        return _scheduler()
    if args.command == "retention":
        return _retention_now()
    if args.command == "migrate":
        return _migrate()
    if args.command == "reset-setup":
        return _reset_setup()
    if args.command == "sync-domains":
        return _sync_domains_now()
    if args.command == "seed":
        return _seed(args.demo, args.tenant_prefix, args.mailbox, args.domains_only)

    # argparse's required=True makes this unreachable; kept so the function has a
    # total return rather than an implicit None.
    return 2


if __name__ == "__main__":
    sys.exit(main())
