# Retention and sizing

Aggregate reports are small individually and large in aggregate. Decide the window before
you fill the disk.

## What a report becomes

Every DMARC aggregate report yields one row per sending IP per authentication result per
day per domain. A tenant with 60 domains and a dozen legitimate senders generates a few
thousand rows a day, most of which nobody will ever look at individually. The demo tenant,
at 60 domains and 90 days, is about 35,000 rows; a real tenant with more reporters and more
sending IPs is several times that.

TLS-RPT reports yield one row per policy domain per result type per day, far fewer.

## The two windows

**Raw rows** are kept for `RETENTION_RAW_DAYS` (90 by default). This is what the Sources
screen, the per-domain sources table and the alignment percentages read from, because only
raw rows know which IP sent what.

Past that window, the nightly job rolls raw rows up into **one row per domain per day**:
volume, aligned passes, and failures split into known-sender and unclassified-sender. That
split is kept on purpose: it is what the readiness score is built from, so the score reads
the same whether a window falls inside raw data, inside rollups, or across the boundary.
Sending IPs do not survive the rollup. Then the raw rows and their report headers are
deleted. TLS-RPT rows follow the same window; they have no rollup because nothing on the TLS
screen is historical beyond it.

**Rollups** are kept for `RETENTION_ROLLUP_DAYS` (730 by default, two years), then deleted.
Ingestion-run history follows the same window.

Senders are classified at rollup time using the source table as it stands then. Naming a
sender later does not rewrite rollups; it changes how raw rows are read from that point on.

## Changing the window

The job enforces the current setting on its next run, an hour after `DOMAIN_SYNC_HOUR`.
Lowering `RETENTION_RAW_DAYS` from 90 to 30 rolls up and deletes 60 days of raw rows the
following night. Rollups inside their own window are untouched. Run it now with:

```bash
docker compose exec api rua retention
```

A report that arrives late for a day already rolled up lands as raw rows and is *added* to
that day's rollup on the next run; nothing is double counted and nothing is dropped.

## Personal data

DMARC aggregate reports contain sending IP addresses. Depending on jurisdiction and
interpretation those may be personal data. Set `RETENTION_RAW_DAYS` to whatever your policy
requires rather than accepting the default, and record the decision where your auditors will
look. Rollups contain no IPs. Forensic (`ruf`) reports, which can contain message content,
are discarded unparsed.

## Database size

Order of magnitude, with indexes: a raw row is roughly 200 bytes; a rollup row roughly 100.
At 5,000 raw rows a day and the defaults, raw data settles around 100 MB and two years of
rollups for 60 domains around 5 MB. The bundled PostgreSQL on a small volume is fine for a
single tenant; the number to watch is raw rows per day, visible on the Settings page.
