# Security and privacy

What Rua holds, what it can reach, and what it deliberately cannot. For reporting a
vulnerability, see [SECURITY.md](../SECURITY.md).

## What it holds

- Parsed DMARC aggregate data: sending IPs, volumes, dispositions, alignment results, per
  domain per day. IPs are deleted at `RETENTION_RAW_DAYS`; the daily aggregates that remain
  have none.
- Parsed TLS-RPT data: session counts, result types, reporting organisations.
- DNS record state for your domains and when it was checked, including the `rua=` value
  found, verbatim.
- Graph credentials, encrypted with a key derived from `SECRET_KEY`. The client secret is
  never logged, never returned by an endpoint and never shown again after entry.
- One local account: name, email, Argon2id password hash.
- Ingestion history: when each poll ran, how it ended, and an operator-facing error message
  that never contains a credential or report content.

## What it can reach

- One mailbox, through `Mail.Read` scoped by Exchange RBAC or an application access policy.
  `Mail.Read` *can* read message bodies in that mailbox; Rua reads report attachments, parses
  them and stores only the aggregates above. "No message bodies" is a statement about what is
  retained, and a code path that reads or persists more is in scope for disclosure.
- The tenant's verified domain list, through `Domain.Read.All`.
- Public DNS, and `https://mta-sts.<domain>/.well-known/mta-sts.txt` for your domains.
- Your webhook, if you set one.

Nothing else. No telemetry, no update check, no CDN assets in the browser. The interactive
API docs are disabled because they would load from one.

## What it deliberately cannot

- Any other mailbox. There is no code path to one, and the scoping step makes the token
  unable to reach one.
- Anything about recipients: aggregate reports do not contain recipient addresses.
- Forensic (`ruf`) reports, which can contain message content. Detected by content type,
  `.eml` attachment or subject, and discarded unparsed.
- Writing DNS, or changing a DMARC policy. There is no provider integration and none planned.

## Report parsing is attacker-influenced input

Anyone can send mail that causes a receiver to generate a report about your domain, so
every report is treated as hostile: XML is parsed with `defusedxml` (entity expansion is
refused), archives are decompressed under size and ratio caps and never written to disk,
and each report is persisted in its own savepoint so one bad document cannot abort a run.

## The local account

It exists so a fresh deployment is not claimable by whoever reaches the URL first. It is not
access control: there is no rate limiting, no lockout and no reset flow. Put Rua behind a
TLS-terminating reverse proxy and an identity-aware layer or a VPN, and treat the local
account as a break-glass credential. Sessions are signed cookies, twelve hours, `Secure`
whenever `BASE_URL` is `https://`.

## Roadmap, for the avoidance of doubt

Likely: Entra SSO for the dashboard replacing the local account; alert thresholds in the UI;
an exportable posture snapshot. Never: multi-tenant hosting, DNS writing, automatic policy
promotion, forensic parsing, threat detection. See CONTRIBUTING.md.
