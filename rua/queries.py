"""Read queries shared by the templates and (from milestone 6) the API.

Kept apart from the models so that the bucketing rules live in one place. The
severity vocabulary here is the same one the Domains table's left marker uses,
and the two must not drift: a domain shown amber in one place and green in
another is worse than either.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rua.models import Domain

SIGNALS = ("dmarc", "spf", "dkim", "mtasts", "tlsrpt")

# Values that mean "this signal is absent" and "this signal is weak". Anything
# else on a non-na domain counts as healthy.
MISSING = "missing"
WARN_VALUES = frozenset({"quarantine", "none", "softfail", "partial", "testing"})

PROTECTED = "protected"
PARTIAL = "partial"
GAPS = "gaps"
NOT_APPLICABLE = "na"


def posture_bucket(domain: Domain) -> str:
    """Which of the four day-zero buckets a domain falls into.

    Mirrors the row severity marker in the Domains table: red if any signal is
    missing, amber if any is weak, green if clean, grey if the domain cannot
    have posture at all. The spec defines the marker but never wrote the
    aggregate mapping down, so it is written down here.
    """
    values = [getattr(domain, signal).value for signal in SIGNALS]

    if all(value == NOT_APPLICABLE for value in values):
        return NOT_APPLICABLE
    if any(value == MISSING for value in values):
        return GAPS
    if any(value in WARN_VALUES for value in values):
        return PARTIAL
    return PROTECTED


def domain_posture_counts(session: Session) -> dict[str, int]:
    """Count domains per posture bucket. Empty database yields all zeros."""
    counts = {PROTECTED: 0, PARTIAL: 0, GAPS: 0, NOT_APPLICABLE: 0}
    for domain in session.scalars(select(Domain)):
        counts[posture_bucket(domain)] += 1
    return counts


def rua_mismatches(session: Session) -> list[Domain]:
    """Domains whose ``rua=`` tag points somewhere other than this deployment.

    ``IS FALSE`` only — a null means there is no DMARC record to carry a tag,
    which is a different problem and belongs in the gaps count, not in the
    "will never send you a report" list.
    """
    return list(
        session.scalars(select(Domain).where(Domain.rua_matches.is_(False)).order_by(Domain.name))
    )
