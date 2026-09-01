# Contributing

Apache-2.0. Pull requests welcome, with two caveats below.

## Before you write code

**The non-goals are settled.** Multi-tenant hosting, automatic policy promotion, DNS
provider integration, forensic report parsing, and threat detection are refused by design,
not for want of effort. Each one either widens the blast radius or gives away the isolation
that is the reason to self-host. If you disagree, open an issue and make the argument
first — a PR implementing one of them will be closed.

**Open an issue for anything non-trivial.** A parser fix or a docs correction can go
straight to a PR. A new screen, a schema change, or a new permission should be discussed
before you spend time on it.

## Development

```bash
cp .env.example .env        # set POSTGRES_PASSWORD and SECRET_KEY
docker compose up postgres -d

python3.12 -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pip install --no-deps -e .

alembic upgrade head
rua serve --reload
```

pip and `requirements.txt` only — no Poetry, no uv, no lockfile tooling. Runtime pins live
in `requirements.txt`; `pyproject.toml` declares no runtime dependencies so there is one
place to change a version.

Tests: `pytest`. Report-parsing changes need a fixture — real reports, redacted, in
`tests/fixtures/`.

## What good contributions look like

- **Parser robustness.** Real-world reports violate the schema in creative ways. Fixtures
  from reports that broke your instance are the single most useful contribution.
- **DNS edge cases.** Unusual but valid record forms that Rua misreads.
- **Documentation.** Especially the Entra registration steps, which change whenever
  Microsoft rearranges the portal.
- **Accessibility.** Status is never colour-only anywhere in the UI. Hold that line.

## Style

Python: ruff, and the formatter's opinion wins. Frontend: no CSS frameworks, no component
libraries beyond what is already there. Copy is plain and matter-of-fact — no exclamation
marks, no "simply", no emoji.
