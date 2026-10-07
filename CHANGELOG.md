# Changelog

## 0.1.0 — 2026-10-07

First release.

- Setup wizard: local administrator, Entra registration guidance for both RBAC for
  Applications and application access policies, Graph connection test, mailbox verification.
  Setup cannot complete without both checks passing.
- Ingestion of DMARC aggregate (RFC 7489) and TLS-RPT (RFC 8460) reports from one shared
  mailbox over Microsoft Graph, parsed in-process with entity-expansion and decompression
  safeguards. Forensic reports are discarded.
- Daily domain sync from Graph with live DNS and MTA-STS checks for DMARC, SPF, DKIM
  (`selector1`/`selector2`), MTA-STS and TLS-RPT, and `rua=` mismatch detection. Failed
  lookups keep the previous value.
- JSON API with a global 7/14/30/90-day window; report-derived figures are `null` until
  the first report exists.
- Readiness score and verdict for `p=reject` promotion. **The formula is a starting point
  flagged for review**; see `rua/readiness.py`.
- Dashboard: Overview, Sources, Domains, per-domain drill-down, TLS, Settings, and the
  day-zero waiting page. Server-rendered, no build step, works without JavaScript. Status is
  never colour alone.
- Nightly retention rollup and delete; webhook alerts on a newly missing signal and on the
  first failed poll of an outage.
- Local login after setup. No rate limiting; run behind a proxy.
- `rua seed --demo` loads a deterministic 60-domain tenant with 90 days of synthetic reports.
