# Deploy

Docker Compose is the supported path. Anything that runs an OCI image will work.

## Requirements

- **A Microsoft 365 tenant**, and a shared mailbox in it that is **already receiving** your
  DMARC aggregate reports — the address in your domains' `rua=` tags. Rua does not create the
  mailbox and does not change DNS to point at it.
- **Docker 24+ with Compose v2**, or any host that can run an OCI image. Two long-running
  processes: the API and the scheduler. The bundled PostgreSQL 16 container, or your own
  PostgreSQL 15 or later.
- **Outbound network:** HTTPS to `login.microsoftonline.com` and `graph.microsoft.com`; DNS
  (UDP/TCP 53) for record lookups; HTTPS to `mta-sts.<your-domains>` to fetch policy files;
  and HTTPS to your webhook host if alerting is on. Nothing else, ever.
- **One inbound HTTP port.** Rua does not terminate TLS. Put a proxy in front of it.
- **Exchange Online PowerShell**, once, to scope the app to the one mailbox.

## Start

```bash
git clone https://github.com/aaqibwani/rua && cd rua
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, the matching password in DATABASE_URL, and SECRET_KEY
docker compose up -d
```

Three services start:

| Service | What it is |
|---|---|
| `api` | The FastAPI process: the JSON API and the dashboard. The only container with an inbound port. Applies database migrations on start. |
| `scheduler` | Mailbox polling (hourly), the domain and DNS sync (daily), retention (nightly). A separate process so a stuck parse cannot take the dashboard down. |
| `postgres` | Data. On a named volume; back it up like anything else you would miss. |

Open `http://localhost:8080`. The first request goes to the setup wizard, and nothing else
works until it completes: there are no credentials in the image and no default account.

## After the wizard

Setup completing signs you in. Every later visit asks for the administrator email and
password from step 1 of the wizard. Sessions last twelve hours.

Domains appear after the first sync. The wizard's last step triggers one; otherwise it runs
daily at `DOMAIN_SYNC_HOUR`, or now with:

```bash
docker compose exec api rua sync-domains
```

Reports appear when receivers send them, usually within 24 hours and sometimes 72. Until
then the dashboard shows a waiting page with everything DNS already says.

## Behind a proxy

Rua expects something in front of it that terminates TLS and, ideally, authenticates
people. There is no rate limiting and no brute-force protection on the local login, so a
reverse proxy with an identity-aware layer or a VPN is the real access control; the local
account is a break-glass credential. Set `BASE_URL` to the external URL so the session
cookie is marked `Secure` (it is whenever `BASE_URL` starts with `https://`).

## Upgrading

```bash
docker compose pull && docker compose up -d
```

Migrations run automatically when the API starts. Read the release notes first: a release
that changes the readiness formula or a posture rule will say so.

## Rotating SECRET_KEY

`SECRET_KEY` encrypts the stored Graph client secret. Rotating it makes that secret
undecryptable, by design. Afterwards run:

```bash
docker compose exec api rua reset-setup
```

This reopens the wizard at the credentials step. The administrator account, the domains and
every report are kept; the Graph credentials and both verification verdicts are cleared, so
the connection and mailbox checks run again before ingestion resumes.

## Without Compose

Run the image twice from the same `.env`, once with `rua serve --host 0.0.0.0 --port 8080`
and once with `rua scheduler`, against any PostgreSQL 15+ reachable from both. `rua migrate`
applies migrations by hand if you would rather not have the API do it.
