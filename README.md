# Rua

**Every domain's authentication posture, in one table, from your own tenant.**

Self-hosted DMARC, SPF, DKIM, MTA-STS and TLS-RPT reporting for a Microsoft 365 tenant.
Apache-2.0.

Rua answers three questions that Microsoft 365 does not answer in one place:

- Which of your verified domains are actually protected?
- Which senders are sending mail claiming to be you?
- Where are TLS connections failing, and which of those failures are yours to fix?

It reads DMARC and TLS-RPT reports from a shared mailbox in your own tenant, plus your
verified domain list and public DNS. It runs on infrastructure you control. Nothing leaves
your deployment and there is no telemetry.

---

## Quick start

```bash
git clone https://github.com/aaqibwani/rua && cd rua
cp .env.example .env

# edit .env: set POSTGRES_PASSWORD and SECRET_KEY
docker compose up -d
```

Open <http://localhost:8080> and follow the first-run wizard. It creates the local admin
account, walks through the Entra app registration, and verifies both the Graph connection
and the report mailbox before it lets you finish.

Most of your posture is readable from DNS immediately. Volume, pass rates and TLS results
appear as aggregate reports arrive, usually within 24 hours.

## What you need first

- A Microsoft 365 tenant.
- A shared mailbox **already receiving** your DMARC aggregate reports — that is, it is the
  address in your domains' `rua=` tags. Rua does not change your DNS.
- Somewhere to run a container and a PostgreSQL 15+ database.
- Exchange Online PowerShell access, once, to scope the app to that one mailbox.

## Permissions, and why they are narrow

Rua authenticates to Graph as an application with two permissions:

| Permission | Why |
|---|---|
| `Mail.Read` | Read the report attachments in the shared mailbox |
| `Domain.Read.All` | Read the tenant's verified domain list |

`Mail.Read`, not `Mail.ReadBasic`. Microsoft's permissions reference is explicit that
`Mail.ReadBasic` "Includes all properties except body, previewBody, **attachments** and
any extended properties" — and DMARC aggregate reports *are* attachments, so the narrower
permission cannot read a single report.

Either permission would be tenant-wide as granted, which is not acceptable on its own.
Setup therefore requires the app to be scoped to the single report mailbox, and will not
complete until it can prove that mailbox is reachable. The wizard offers both mechanisms.

**RBAC for Applications** (recommended — Microsoft has replaced access policies with it):

```powershell
Connect-ExchangeOnline

# ObjectId comes from Enterprise applications, not App registrations
New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "Rua"

New-ManagementScope -Name "Rua report mailbox" `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'dmarc-reports@example.com'"

New-ManagementRoleAssignment -App <enterprise-app-object-id> `
  -Role "Application Mail.Read" `
  -CustomResourceScope "Rua report mailbox"

Test-ServicePrincipalAuthorization -Identity <client-id> -Resource dmarc-reports@example.com
```

With RBAC, grant **only `Domain.Read.All` in Entra**. Granting `Mail.Read` there as well
unions an unscoped grant with the scoped one and leaves the app with no effective scoping
at all.

**Application access policy** (legacy; grant both permissions in Entra first):

```powershell
New-ApplicationAccessPolicy `
  -AppId <client-id> `
  -PolicyScopeGroupId dmarc-reports@example.com `
  -AccessRight RestrictAccess `
  -Description "Rua: report mailbox only"

# should return Denied
Test-ApplicationAccessPolicy -Identity someone-else@example.com -AppId <client-id>
```

Exchange caches permission changes for 30 minutes to 2 hours, so the wizard's mailbox check
can fail briefly after you configure scoping. `Test-ServicePrincipalAuthorization` bypasses
that cache.

There is no code path to any other mailbox. Within the report mailbox, `Mail.Read` does
grant access to message bodies; Rua reads report attachments and stores nothing else.

## What Rua deliberately does not do

- **Never changes your DNS.** No provider integration, and none planned.
- **Never promotes a policy for you.** `none` → `quarantine` → `reject` stays a human decision.
  Rua tells you what share of legitimate volume would survive the change.
- **No forensic (`ruf`) reports.** Higher privacy cost, lower value. Unsupported on purpose.
- **No multi-tenant mode.** Isolation is the point of self-hosting.
- **Not a SIEM.** This is authentication posture, not threat detection.

## Screens

| Screen | What it is for |
|---|---|
| Overview | Tenant health, DMARC pass-rate trend, the domain closest to a safe policy upgrade |
| Sources | Who is sending as you, sorted by volume, unclassified senders flagged |
| Domains | Full posture per domain — the screen that matters. Search, gaps-only, drill-down |
| TLS | RFC 8460 result types ranked by volume, marked by whether the fix is yours |

Every screen works on a phone. On-call checks do not happen at a desk.

## Configuration

Environment variables only. Graph credentials are entered in the wizard and stored
encrypted with `SECRET_KEY`; they never live in `.env`.

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | Required |
| `SECRET_KEY` | — | Required. Encrypts stored credentials. Rotating it invalidates them |
| `BASE_URL` | `http://localhost:8080` | External URL, used for generated links |
| `INGEST_INTERVAL_MINUTES` | `60` | Mailbox poll interval |
| `DOMAIN_SYNC_HOUR` | `3` | UTC hour for the daily domain and DNS re-check |
| `RETENTION_RAW_DAYS` | `90` | Raw report rows before rollup |
| `RETENTION_ROLLUP_DAYS` | `730` | Daily aggregates before deletion |
| `ALERT_WEBHOOK_URL` | unset | Teams or Slack incoming webhook. Unset means no alerting |
| `LOG_LEVEL` | `INFO` | Structured JSON to stdout |

## Security

Rua has no rate limiting and no brute-force protection on the local login. **Put it behind
a TLS-terminating proxy and, ideally, an identity-aware proxy or a VPN.** The local admin
account exists so a fresh deployment is not claimable by the first visitor; it is not a
substitute for access control.

DMARC aggregate reports contain sending IP addresses. Depending on your jurisdiction those
may be personal data — set `RETENTION_RAW_DAYS` to whatever your policy requires rather
than accepting the default.

Vulnerabilities: see [SECURITY.md](SECURITY.md). Do not open a public issue.

## Documentation

Full docs cover deployment, the Entra registration step by step, the DNS records only you
can change, retention and sizing, and troubleshooting.

## Contributing

Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md). The non-goals above are settled — if
you disagree with one, open an issue before writing code.

## Prior art

Commercial DMARC platforms solve this well and cost accordingly. Rua exists for the case
where the data should not leave your tenant, and where one team needs one answer rather
than a suite.
