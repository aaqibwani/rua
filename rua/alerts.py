"""Webhook alerting. Two events, one URL, and silence when it is unset.

``ALERT_WEBHOOK_URL`` is a Teams or Slack incoming webhook. Both accept a JSON
body with ``text``; Teams also renders ``title``, Slack ignores it. Nothing else
is sent: no domain list beyond the ones named in the alert, no credentials, no
report content. The post is best-effort — a webhook outage must never fail the
job that raised the alert — and it is the one outbound call the operator
configured explicitly, which is why it is the only one.

Events
------

**A newly detected gap.** A signal on a *known* domain goes from a configured
value to ``missing`` between two DNS checks: a DMARC record deleted, an SPF
record that stopped resolving, a DKIM selector revoked. New domains do not
alert; the first sync of a tenant would otherwise send one message per gap the
operator already knows about, and the Domains table is where that list lives.
Transient resolver failures never reach here either: :mod:`rua.domain_sync`
keeps the previous value when a lookup fails.

**Ingestion failure.** A poll ends in ``failure`` after a run that did not. One
alert per outage, not one per hour; recovery is visible on the dashboard and
in the ingestion log, and is not alerted on.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from rua.config import get_settings
from rua.logging import get_logger

log = get_logger(__name__)

TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class GapTransition:
    domain: str
    signal: str
    previous: str


def alerting_enabled() -> bool:
    return get_settings().alerting_enabled


def post(title: str, text: str, url: str | None = None) -> bool:
    """Send one alert. Returns True when the webhook accepted it; never raises."""
    url = url or get_settings().alert_webhook_url
    if not url:
        return False
    try:
        response = httpx.post(
            url,
            json={"title": title, "text": text},
            timeout=TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        log.warning("alert_post_failed", error_type=type(exc).__name__, title=title)
        return False
    if response.status_code >= 300:
        log.warning("alert_post_rejected", status=response.status_code, title=title)
        return False
    log.info("alert_posted", title=title)
    return True


def alert_new_gaps(transitions: list[GapTransition], url: str | None = None) -> bool:
    if not transitions:
        return False
    names = {
        "dmarc": "DMARC",
        "spf": "SPF",
        "dkim": "DKIM",
        "mtasts": "MTA-STS",
        "tlsrpt": "TLS-RPT",
    }
    lines = [
        f"- {t.domain}: {names.get(t.signal, t.signal)} was {t.previous}, now not configured"
        for t in sorted(transitions, key=lambda t: (t.domain, t.signal))
    ]
    count = len(transitions)
    title = f"Rua: {count} new gap{'' if count == 1 else 's'} detected"
    text = (
        "A signal that was configured yesterday is missing from DNS today.\n"
        + "\n".join(lines)
        + "\n\nA failed lookup never produces this alert; the record is really gone."
    )
    return post(title, text, url)


def alert_ingest_failure(error_text: str | None, url: str | None = None) -> bool:
    title = "Rua: ingestion failed"
    text = (
        "The report mailbox poll ended in failure. Until it succeeds again no new reports "
        "arrive and the dashboard will go stale.\n\n"
        f"Reason: {error_text or 'not recorded'}\n\n"
        "The ingestion log in Settings has the run history. "
        "An expired client secret is the usual cause."
    )
    return post(title, text, url)
