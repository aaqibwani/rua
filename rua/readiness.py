"""The readiness score: "if I moved this domain to ``p=reject`` today, what share of
my legitimate mail would still be delivered?"

**This formula is a product decision awaiting human review** (handoff spec, "Ask
the human before deciding"). It is deliberately simple so it can be argued with.
Nothing else in the codebase depends on its internals; change the constants or
the shape below and the API, the seed and the UI follow.

Inputs, over the selected window
--------------------------------

Every DMARC aggregate row is one of three things, decided by the receiver's
alignment verdict and by whether the sending source is classified:

``aligned_pass``
    SPF *or* DKIM aligned. This is mail DMARC passed. Only the domain owner's
    infrastructure can align, so it is legitimate by construction — whoever
    sent it, and whether or not anybody has classified the source.

``fail_known``
    Neither aligned, but the source is a *known* sender. Legitimate mail from a
    service that is misconfigured — the SaaS tool nobody added to SPF, the
    relay that signs with the wrong domain. **Fixable**, and it is lost under
    ``p=reject``.

``fail_unclassified``
    Neither aligned, and nobody has said what the source is. Either an unknown
    legitimate service or an attacker; the data cannot tell. This is the number
    that should stop someone tightening, and the spec requires that it never be
    folded into the headline figure.

The formula
-----------

::

    legitimate = aligned_pass + fail_known
    readiness  = 100 * aligned_pass / legitimate        (null when legitimate == 0)

So readiness is the share of *known-legitimate* volume that survives
``p=reject``. Unclassified failures are excluded from the denominator rather than
counted as legitimate or as hostile, because either assumption lies: counting
them as legitimate lets a spoofing campaign drive readiness towards zero on a
domain whose correct next step is exactly ``p=reject``; counting them as hostile
lets an unregistered SaaS sender vanish from the score. They are reported
alongside the percentage, and they gate the verdict below.

The verdict
-----------

The percentage is not the recommendation. :func:`verdict` is, and it is where
the two guards the spec asks for live:

* **Minimum volume.** Under ``MIN_VOLUME`` messages in the window, the verdict
  is ``insufficient_data`` whatever the percentage says. Ten messages that all
  passed is not evidence that tightening is safe.
* **Unclassified share.** If more than ``MAX_UNCLASSIFIED_SHARE`` percent of
  the window's volume failed from unclassified sources, the verdict is
  ``not_ready`` even at 100% readiness — someone has to look at those senders
  first, which is the whole point of the Sources screen.

``ready`` therefore means: enough volume to trust, at least ``READY_THRESHOLD``
percent of known-legitimate mail already aligned, and the unknown remainder
small enough to tolerate. Everything else is ``not_ready``, except a domain
already at ``p=reject`` (``at_reject``) and one that cannot have a policy at all
(``not_applicable``).

Why these numbers
-----------------

``READY_THRESHOLD = 98.0`` matches the drill-down's green tone (the design turns
the readiness figure green above 98). ``MAX_UNCLASSIFIED_SHARE = 1.0`` percent
and ``MIN_VOLUME = 1000`` messages are starting points chosen so that the demo
tenant produces every verdict at least once; they are not derived from real
tenant data and **should be revisited with some**. All three are module
constants for that reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

READY_THRESHOLD = 98.0  # percent of known-legitimate volume that must already align
MAX_UNCLASSIFIED_SHARE = 1.0  # percent of total volume that may fail from unknown senders
MIN_VOLUME = 1000  # messages in the window below which no verdict is offered

Verdict = Literal["at_reject", "ready", "not_ready", "insufficient_data", "not_applicable"]


@dataclass(frozen=True, slots=True)
class VolumeSplit:
    """The three-way split of a domain's window volume. All counts, never rates."""

    aligned_pass: int = 0
    fail_known: int = 0
    fail_unclassified: int = 0

    @property
    def total(self) -> int:
        return self.aligned_pass + self.fail_known + self.fail_unclassified

    @property
    def legitimate(self) -> int:
        """Volume known to be the tenant's own: it aligned, or a known sender sent it."""
        return self.aligned_pass + self.fail_known

    @property
    def failing(self) -> int:
        return self.fail_known + self.fail_unclassified

    def __add__(self, other: VolumeSplit) -> VolumeSplit:
        return VolumeSplit(
            self.aligned_pass + other.aligned_pass,
            self.fail_known + other.fail_known,
            self.fail_unclassified + other.fail_unclassified,
        )


def pass_rate(split: VolumeSplit) -> float | None:
    """DMARC pass rate over *all* observed volume, as a percentage. Null at zero volume.

    Not the readiness score: this one does count unclassified failures, because
    it describes what receivers saw rather than what tightening would cost.
    """
    if split.total == 0:
        return None
    return 100.0 * split.aligned_pass / split.total


def readiness(split: VolumeSplit) -> float | None:
    """Share of known-legitimate volume that would survive ``p=reject``, as a percentage.

    Null when no legitimate volume was observed — including the case where every
    message in the window failed from an unclassified source. There is nothing
    to score then, and 0% or 100% would each claim knowledge nobody has.
    """
    if split.legitimate == 0:
        return None
    return 100.0 * split.aligned_pass / split.legitimate


def unclassified_share(split: VolumeSplit) -> float | None:
    """Percent of total volume that failed from unclassified sources. Null at zero volume."""
    if split.total == 0:
        return None
    return 100.0 * split.fail_unclassified / split.total


def verdict(split: VolumeSplit, dmarc: str) -> Verdict:
    """The recommendation the UI renders beside the percentage. See the module docstring."""
    if dmarc == "na":
        return "not_applicable"
    if dmarc == "reject":
        return "at_reject"
    if split.total < MIN_VOLUME:
        return "insufficient_data"

    score = readiness(split)
    share = unclassified_share(split)
    if score is None or share is None:
        return "not_ready"
    if score >= READY_THRESHOLD and share <= MAX_UNCLASSIFIED_SHARE:
        return "ready"
    return "not_ready"
