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

    return parser


def _serve(host: str, port: int, reload: bool) -> int:
    import uvicorn

    from rua.config import get_settings

    settings = get_settings()
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


def _scheduler() -> int:
    from apscheduler.schedulers.blocking import BlockingScheduler

    from rua.config import get_settings
    from rua.logging import configure_logging, get_logger

    settings = get_settings()
    configure_logging(settings.log_level)
    log = get_logger("rua.scheduler")

    scheduler = BlockingScheduler(timezone="UTC")

    # Jobs are registered by later milestones:
    #   M4 — mailbox poll every INGEST_INTERVAL_MINUTES
    #   M5 — Graph /domains sync and DNS re-check daily at DOMAIN_SYNC_HOUR
    #   M9 — nightly retention rollup and delete
    # Until then the process starts, stays up and registers nothing. It must not
    # exit: Compose restarts it `unless-stopped`, and exiting would crash-loop.
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


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``rua`` console script."""
    args = _build_parser().parse_args(argv)

    if args.command == "serve":
        return _serve(args.host, args.port, args.reload)
    if args.command == "scheduler":
        return _scheduler()

    # argparse's required=True makes this unreachable; kept so the function has a
    # total return rather than an implicit None.
    return 2


if __name__ == "__main__":
    sys.exit(main())
