# Troubleshooting

## A domain shows no volume

**Check its `rua=` tag first.** If it points at another address, that is the answer: no
report will ever reach the mailbox Rua reads. Rua flags this as `rua≠` in the Domains table
and names the domain on the waiting page. The fix is a DNS change — see
[DNS you have to own](dns-records.md).

**Check the mailbox by hand.** If no compressed XML attachments are arriving, the problem is
upstream of Rua.

**Check the ingestion log** in Settings. An expired client secret fails every poll with a
401; the dashboard shows a stale banner and, if a webhook is set, one alert was sent when it
started.

**Low-volume domains genuinely take days.** Receivers only report when they see mail. A
parked domain that sends nothing generates no reports, which is expected and not a fault; its
DNS posture is still shown, and an unprotected parked domain is exactly what gets spoofed.

## The waiting page will not go away

It disappears the moment the first report from *any* domain is parsed. If polls succeed and
"Reports parsed" stays at 0, nothing in the mailbox is being recognised as a report. Reports
arrive as `.zip`, `.gz` or `.xml` attachments (DMARC) and `.json` or `.json.gz` (TLS-RPT);
forwarded copies with the attachment stripped, and forensic reports, are discarded. The
ingestion log counts messages seen and reports parsed separately for this reason.

## The wizard's connection test fails

- *The client secret is wrong or has expired* — re-copy the value, not the secret ID.
- *A permission is missing* — the test checks the token's roles against the scoping mode
  you chose. With RBAC, `Domain.Read.All` must be in Entra and `Mail.Read` must **not**
  be; with an access policy, both must be.
- *Admin consent* — both grants need it. The token lists only consented roles.

## The wizard's mailbox check fails

Usually scoping. With RBAC, run `Test-ServicePrincipalAuthorization` against the report
mailbox. With an access policy, `Test-ApplicationAccessPolicy` against the report mailbox
should return Granted. Exchange caches permission changes for 30 minutes to 2 hours, so a
correct configuration can fail for a while after you apply it; the wizard is honest about
this and the check can simply be rerun.

Check the mailbox address too: it must be the primary SMTP address, and a shared mailbox
must be licensed or exempt the way Exchange expects.

## The dashboard says "stale"

No poll has succeeded within two `INGEST_INTERVAL_MINUTES`. The banner names how old the
last success is and the outcome of the latest run. Look at the ingestion log; the error text
there is the reason. If the log has no recent rows at all, the scheduler container is not
running.

## Ingestion stopped after I rotated SECRET_KEY

Expected. The stored client secret was encrypted with the old key. Run `rua reset-setup`,
open the dashboard URL and re-enter the credentials; the connection and mailbox checks run
again before ingestion resumes.

## MTA-STS shows "not configured" but the policy is there

Rua fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` from wherever it runs, with
no redirects and a 64 KB cap, and needs the `_mta-sts` TXT record as well. A policy host that
is only reachable internally, a redirect to another host, or a certificate chain that is
incomplete in a way your browser forgives will fail here and not on your laptop. Mode `none`
also reads as not configured, because nothing is enforced.

## DKIM shows "1 of 2 selectors"

Only one of `selector1._domainkey` and `selector2._domainkey` publishes a key. Microsoft
rotates between the two, so this is worth fixing: enable DKIM signing for the domain in the
Defender portal and publish both CNAMEs it gives you. A domain signing only through a
third-party service shows as not configured, because its selectors cannot be discovered.

## TLS success rate is low

Check whether `starttls-not-supported` dominates the failures. That is remote senders without
STARTTLS and is not yours to fix. The TLS tab marks each result type as yours (certificates,
MTA-STS policy, DANE records), the sender's, or unclear.

## I am locked out

There is no password reset; the account is a break-glass credential and the README asks you
to put real access control in front of the container. On the host, with database access, you
can set a new hash:

```bash
docker compose exec api python -c "from rua.security import hash_password; print(hash_password('a new password of at least twelve characters'))"
```

and write it to `admin_user.password_hash` with `psql`.

## /healthz returns 503

The database is unreachable from the API container. Check `DATABASE_URL`, that `postgres` is
healthy (`docker compose ps`), and that the password in `DATABASE_URL` matches
`POSTGRES_PASSWORD` — Compose does not interpolate one into the other.
