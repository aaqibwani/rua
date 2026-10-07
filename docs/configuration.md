# Configuration

Everything is an environment variable, read from the environment or from `.env`. Graph
credentials are the exception: they are entered in the wizard, stored encrypted in the
database, and never displayed again.

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | **Required.** `postgresql+psycopg://user:pass@host:5432/rua`. The psycopg (v3) driver is required; other schemes are rejected at start |
| `SECRET_KEY` | — | **Required**, at least 32 characters. Encrypts the stored client secret (Fernet, key derived with HKDF) and signs the session cookie. Rotating it invalidates both — see [Deploy](deploy.md#rotating-secret_key) |
| `POSTGRES_PASSWORD` | — | Read by `docker-compose.yml` only, for the bundled database. Must match the password inside `DATABASE_URL`; Compose does not interpolate one into the other |
| `BASE_URL` | `http://localhost:8080` | External URL without a trailing slash. When it starts with `https://` the session cookie is marked `Secure` |
| `INGEST_INTERVAL_MINUTES` | `60` | Mailbox poll interval, 1–1440. The dashboard is "stale" after two intervals without a successful poll |
| `DOMAIN_SYNC_HOUR` | `3` | UTC hour for the daily domain list and DNS re-check. Retention runs the following hour |
| `RETENTION_RAW_DAYS` | `90` | Raw report rows (with sending IPs) and TLS-RPT rows are kept this long, then rolled up and deleted |
| `RETENTION_ROLLUP_DAYS` | `730` | Daily per-domain aggregates and ingestion history are kept this long. Must be ≥ `RETENTION_RAW_DAYS` |
| `ALERT_WEBHOOK_URL` | unset | Teams or Slack incoming webhook, `https://` only. Unset means no alerting and no outbound call |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` / `CRITICAL`. Structured JSON on stdout |

A missing required variable, a weak `SECRET_KEY`, a non-`https` webhook or a rollup window
shorter than the raw window stops the process at start with a message that names the
variable. The rejected value is never echoed.

## Commands

The image has one entry point, `rua`:

| Command | What it does |
|---|---|
| `rua serve` | Apply migrations, then serve the API and dashboard |
| `rua scheduler` | Run the poll, sync and retention jobs |
| `rua migrate` | Apply migrations without serving |
| `rua sync-domains` | Pull the verified domain list and re-check DNS now |
| `rua retention` | Run the retention rollup and delete now |
| `rua seed --demo` | Load the 60-domain demo tenant with 90 days of synthetic reports. `--domains-only` skips the reports |
| `rua reset-setup` | Reopen the wizard at the credentials step, keeping the account and all data |

## What is stored where

| Where | What |
|---|---|
| `.env` / environment | Everything above. No secrets beyond `SECRET_KEY` and the database password |
| `setting` table | Graph tenant ID, client ID, mailbox, scoping mode, wizard progress, verification verdicts, and the client secret as a Fernet token |
| `admin_user` table | One row: name, email, Argon2id password hash |
| Everything else | Parsed report data, DNS posture, ingestion runs |

The Settings page shows the configuration without secrets, the schedule, and what retention
currently holds.
