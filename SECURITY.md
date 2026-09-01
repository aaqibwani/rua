# Security policy

## Reporting a vulnerability

Email **security@your-org.example** with enough detail to reproduce. Please do not open a
public issue for anything exploitable.

Expect an acknowledgement within 3 working days and an assessment within 10. If you have a
disclosure deadline, say so in the first message and we will work to it.

## Scope

In scope:

- Anything that lets one deployment read data it should not hold.
- Anything that widens the Graph permission beyond the configured report mailbox.
- Authentication bypass on the dashboard or the setup wizard.
- Credential disclosure — stored Graph secrets, session tokens, password hashes.
- Injection or deserialisation issues in report parsing. Reports are attacker-influenced
  input: anyone can send mail that generates a report about your domain.

Out of scope:

- Missing rate limiting on the local login. Documented, deliberate, and the reason the
  README tells you to put Rua behind a proxy.
- Findings that require an attacker to already hold `SECRET_KEY` or database credentials.
- Denial of service by sending very large volumes of reports to your own mailbox.

## What Rua holds

Parsed aggregate data (sending IPs, volumes, dispositions, alignment results), parsed
TLS-RPT data, DNS record state, encrypted Graph credentials, and local password hashes.
No message bodies, no recipient addresses, no forensic reports.

A note on scope versus behaviour. Rua authenticates with `Mail.Read`, because DMARC reports
arrive as attachments and `Mail.ReadBasic` explicitly excludes them. Within the one mailbox
it is scoped to, that permission *can* read message bodies. Rua does not: it reads report
attachments, parses them, and stores only the parsed aggregates listed above. Treat "no
message bodies" as a statement about what is retained, not about what the token could reach.
Reports of a code path that reads or persists anything beyond report attachments are in
scope for disclosure.

## Supported versions

The latest minor release only. There are no long-term support branches.
