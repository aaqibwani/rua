"""Display vocabulary for the dashboard: words, tones, formats and advice copy.

The stored posture values (``reject``, ``partial``, ``missing``…) are identifiers.
What a person reads is decided here, in one place, so that the Domains table, the
drill-down tiles, the mobile cards and the Overview's "needs attention" strip
cannot drift apart.

PINNED (handoff spec): status is never colour alone. Every state has a word, and
every helper here returns the word with the tone rather than the tone by itself.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from rua.queries import SIGNALS

SIGNAL_NAMES = {
    "dmarc": "DMARC",
    "spf": "SPF",
    "dkim": "DKIM",
    "mtasts": "MTA-STS",
    "tlsrpt": "TLS-RPT",
}

# The words. "n/a" is shared; everything else is per signal.
LABELS: dict[str, dict[str, str]] = {
    "dmarc": {
        "reject": "p=reject",
        "quarantine": "p=quarantine",
        "none": "p=none",
        "missing": "not configured",
    },
    "spf": {"pass": "pass", "softfail": "softfail", "missing": "not configured"},
    "dkim": {"pass": "pass", "partial": "1 of 2 selectors", "missing": "not configured"},
    "mtasts": {"enforce": "enforce", "testing": "testing", "missing": "not configured"},
    "tlsrpt": {"present": "configured", "missing": "not configured"},
}

# Tones: ok / warn / gap / na. Same table the seed generator uses for gaps/warns.
TONES: dict[str, dict[str, str]] = {
    "dmarc": {"reject": "ok", "quarantine": "warn", "none": "warn", "missing": "gap"},
    "spf": {"pass": "ok", "softfail": "warn", "missing": "gap"},
    "dkim": {"pass": "ok", "partial": "warn", "missing": "gap"},
    "mtasts": {"enforce": "ok", "testing": "warn", "missing": "gap"},
    "tlsrpt": {"present": "ok", "missing": "gap"},
}

# Severity order for sorting status columns (spec, Interactions table): the
# strongest state first, "missing" last, and n/a after everything.
SEVERITY: dict[str, int] = {
    "reject": 0,
    "pass": 0,
    "enforce": 0,
    "present": 0,
    "quarantine": 1,
    "softfail": 1,
    "partial": 1,
    "testing": 1,
    "none": 2,
    "missing": 3,
    "na": 4,
}

ROLE_LABELS = {
    "primary": "primary",
    "transactional": "transactional",
    "marketing": "marketing",
    "billing": "billing",
    "regional": "regional",
    "parked": "parked",
    "tenant": "tenant default",
}

# The explanatory line under each drill-down tile. Keyed by (signal, value).
TILE_NOTES: dict[tuple[str, str], str] = {
    ("dmarc", "reject"): "Receivers reject mail that fails alignment.",
    ("dmarc", "quarantine"): "Failing mail is quarantined. One step from p=reject.",
    ("dmarc", "none"): "Monitoring only — receivers deliver failing mail as normal.",
    ("dmarc", "missing"): "No _dmarc record. Receivers apply no policy and send no reports.",
    ("spf", "pass"): "Ends in -all.",
    ("spf", "softfail"): "Ends in ~all — tighten to -all.",
    ("spf", "missing"): "No SPF record published.",
    ("dkim", "pass"): "Both Microsoft 365 selectors publish a key.",
    ("dkim", "partial"): "One of selector1 / selector2 is missing or revoked.",
    ("dkim", "missing"): "Neither Microsoft 365 selector publishes a key.",
    ("mtasts", "enforce"): "Policy published and enforced.",
    ("mtasts", "testing"): "Testing mode — failures are reported, not enforced.",
    ("mtasts", "missing"): "No mta-sts.txt published.",
    ("tlsrpt", "present"): "_smtp._tls record present; TLS reports arrive here.",
    ("tlsrpt", "missing"): "No _smtp._tls record. Nobody reports TLS failures for this domain.",
}
NA_NOTE = "Microsoft's zone — not yours to configure."


@dataclass(frozen=True, slots=True)
class Pill:
    signal: str
    name: str  # "DMARC"
    value: str  # stored identifier
    label: str  # the word
    tone: str  # ok / warn / gap / na

    @property
    def self_naming(self) -> str:
        """Mobile cards lose the column header, so the pill names itself."""
        return f"{self.name} {self.label}"


def pill(signal: str, value: str) -> Pill:
    label = "n/a" if value == "na" else LABELS[signal].get(value, value)
    tone = "na" if value == "na" else TONES[signal].get(value, "na")
    return Pill(signal=signal, name=SIGNAL_NAMES[signal], value=value, label=label, tone=tone)


def _value(obj: object, signal: str) -> str:
    """Accept an ORM row (enum attributes) or an API record (plain strings)."""
    raw = getattr(obj, signal)
    return getattr(raw, "value", raw)


def pills(domain: object) -> list[Pill]:
    return [pill(signal, _value(domain, signal)) for signal in SIGNALS]


def tile_note(signal: str, value: str) -> str:
    if value == "na":
        return NA_NOTE
    return TILE_NOTES.get((signal, value), "")


def severity_tone(domain: object) -> str:
    """The row marker's tone: gap > warn > ok, or na when nothing applies."""
    tones = {p.tone for p in pills(domain)}
    if tones == {"na"}:
        return "na"
    if "gap" in tones:
        return "gap"
    if "warn" in tones:
        return "warn"
    return "ok"


def role_label(role: str) -> str:
    return ROLE_LABELS.get(role, role)


# ─── Numbers ─────────────────────────────────────────────────────────────────


def compact_number(value: int | None) -> str:
    """123 → "123", 12_300 → "12.3K", 1_234_567 → "1.2M". None → "—"."""
    if value is None:
        return "—"
    if value < 1000:
        return str(value)
    for threshold, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if value >= threshold:
            scaled = value / threshold
            text = f"{scaled:.1f}" if scaled < 100 else f"{scaled:.0f}"
            return text.rstrip("0").rstrip(".") + suffix
    return str(value)


def percent(value: float | None, digits: int = 1) -> str:
    return "—" if value is None else f"{value:.{digits}f}%"


def thousands(value: int | None) -> str:
    return "—" if value is None else f"{value:,}"


def relative_age(then: dt.datetime | None, now: dt.datetime | None = None) -> str:
    if then is None:
        return "never"
    now = now or dt.datetime.now(dt.UTC)
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 90:
        return "just now"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 36:
        return f"{hours} h ago"
    return f"{hours // 24} d ago"


def rate_tone(value: float | None, good: float = 98.0, fair: float = 94.0) -> str:
    """Tone by threshold for a percentage: >98 ok, >94 warn, else gap (spec, readiness panel)."""
    if value is None:
        return "na"
    if value > good:
        return "ok"
    if value > fair:
        return "warn"
    return "gap"


# ─── Readiness copy ──────────────────────────────────────────────────────────

VERDICT_LABELS = {
    "at_reject": "already at p=reject",
    "ready": "safe to tighten",
    "not_ready": "not ready",
    "insufficient_data": "not enough volume",
    "not_applicable": "n/a",
}


def readiness_advice(verdict: str | None, dmarc: str, has_reports: bool) -> str:
    """The closing sentence of the readiness panel. Varies by state, never by colour."""
    if not has_reports:
        return (
            "Readiness needs aggregate reports. The first ones usually arrive within 24 hours "
            "of setup; until then this panel waits."
        )
    match verdict:
        case "at_reject":
            return (
                "This domain is already at p=reject. Keep an eye on the unclassified senders — "
                "mail from them is being rejected."
            )
        case "ready":
            target = "p=quarantine" if dmarc == "none" else "p=reject"
            return (
                f"Known-legitimate mail is aligned and unclassified volume is small. Moving to "
                f"{target} is a manual DNS change; review the failing senders below first."
            )
        case "insufficient_data":
            return (
                "Too few messages in this window to say anything. Widen the window, or wait — "
                "a handful of passing messages is not evidence."
            )
        case "not_applicable":
            return "The tenant default domain has no policy of its own to tighten."
        case _:
            return (
                "Not ready. Either a known sender is misconfigured (fixable — see the sources "
                "below) or unclassified senders carry too much volume to tighten safely."
            )


def promotion_target(dmarc: str) -> str:
    """What the next policy step would be, for the Overview callout."""
    return {"none": "p=quarantine", "quarantine": "p=reject"}.get(dmarc, "p=reject")
