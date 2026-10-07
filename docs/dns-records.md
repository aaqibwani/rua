# DNS you have to own

Rua reads DNS. It never writes it. These are the records only you can change.

## The one that stops everything: `rua=`

The single most common reason a freshly deployed instance shows nothing for a domain is that
the domain's `rua=` tag points somewhere other than the mailbox Rua reads. That domain will
never appear in the reporting data, however long you wait. Rua detects the mismatch at every
DNS check and names the domain on the waiting page and in the Domains table (`rua≠`), but the
fix is a DNS change.

```
_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com"
```

Multiple addresses are allowed, so you can keep an existing recipient:

```
rua=mailto:reports@vendor.example!10m,mailto:dmarc-reports@example.com
```

Rua treats the tag as matching if *any* address is the configured mailbox. Size suffixes
(`!10m`) are ignored; the comparison is case-insensitive.

**If the report mailbox is on a different domain** than the one being reported on, RFC 7489
§7.1 requires an authorisation record on the mailbox's domain, or conforming receivers will
refuse to send:

```
example.com._report._dmarc.reports.example.net.  TXT  "v=DMARC1"
```

## What each posture reads

| Signal | Record | Reads as |
|---|---|---|
| DMARC | `_dmarc.<domain>` TXT | `p=reject` / `p=quarantine` / `p=none`; **not configured** if absent, if `p=` is absent, or if **two** DMARC records exist (RFC 7489 §6.6.3: receivers then apply none) |
| SPF | `<domain>` TXT `v=spf1` | **pass** if it ends in `-all`; **softfail** for `~all`, `?all`, `+all` or no `all`; **not configured** if absent or if two SPF records exist (RFC 7208 §3.2) |
| DKIM | `selector1._domainkey.<domain>` and `selector2._domainkey.<domain>` TXT | **pass** when both publish a key; **1 of 2 selectors** when one does; **not configured** when neither does. An empty `p=` is a revoked key and counts as absent |
| MTA-STS | `_mta-sts.<domain>` TXT **and** `https://mta-sts.<domain>/.well-known/mta-sts.txt` | **enforce** or **testing** from the fetched policy's `mode:`; **not configured** if either half is missing, the fetch fails, or mode is `none` |
| TLS-RPT | `_smtp._tls.<domain>` TXT `v=TLSRPTv1` | **configured** / **not configured** |

Two things about DKIM. DNS cannot be enumerated, so selectors must be known in advance; Rua
checks the two Microsoft 365 selectors, which is what a tenant-focused tool can honestly
claim. A domain signing only through a third party shows as not configured for DKIM. Second,
"1 of 2 selectors" is the partial state and it is worth fixing: Microsoft rotates between the
two, so mail signed with the missing one fails.

A lookup that **fails** (timeout, SERVFAIL) is not a gap. Rua keeps the previous value and
leaves the "checked at" time alone, so a bad day at the resolver cannot paint a row red or
raise an alert. The next clean check corrects it.

The tenant default domain (`<tenant>.onmicrosoft.com`) is Microsoft's zone and shows as
**n/a** throughout.

## MTA-STS and TLS-RPT

```
_mta-sts.example.com.  TXT  "v=STSv1; id=20261007T120000"
```

```
# https://mta-sts.example.com/.well-known/mta-sts.txt
version: STSv1
mode: enforce
mx: *.mail.protection.outlook.com
max_age: 604800
```

Bump `id=` whenever the policy file changes. Rua fetches the policy from wherever it runs
with no redirects and a 64 KB cap; a policy host that is only reachable internally, or whose
certificate chain is incomplete in a way your browser papers over, will fail the check.

```
_smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:dmarc-reports@example.com"
```

Without a TLS-RPT record there is no TLS data for that domain. The TLS tab's footnote says
which domains publish one.

## Moving a policy

Rua never promotes a policy for you. The readiness panel on a domain's page tells you what
share of known-legitimate volume already aligns and whether unclassified senders carry
enough volume to stop you; the record change is yours, with whatever review your
organisation applies to DNS.
