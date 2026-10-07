"""The readiness formula, pinned so a change to it is a deliberate one.

The formula itself is flagged for human review (handoff spec). These tests do
not claim it is right; they claim it does what its docstring says.
"""

from __future__ import annotations

import pytest

from rua.readiness import (
    MAX_UNCLASSIFIED_SHARE,
    MIN_VOLUME,
    READY_THRESHOLD,
    VolumeSplit,
    pass_rate,
    readiness,
    unclassified_share,
    verdict,
)


def test_readiness_is_the_share_of_known_legitimate_volume_that_aligned() -> None:
    split = VolumeSplit(aligned_pass=980, fail_known=20, fail_unclassified=500)
    assert readiness(split) == pytest.approx(98.0)
    # pass_rate counts the unclassified failures; readiness deliberately does not.
    assert pass_rate(split) == pytest.approx(100 * 980 / 1500)


def test_readiness_is_null_without_legitimate_volume() -> None:
    """All failures from unclassified senders: nothing to score, not 0% and not 100%."""
    assert readiness(VolumeSplit(0, 0, 400)) is None
    assert readiness(VolumeSplit()) is None
    assert pass_rate(VolumeSplit()) is None
    assert unclassified_share(VolumeSplit()) is None


def test_ready_needs_volume_alignment_and_a_small_unknown_remainder() -> None:
    split = VolumeSplit(aligned_pass=9900, fail_known=50, fail_unclassified=50)
    assert readiness(split) >= READY_THRESHOLD
    assert unclassified_share(split) <= MAX_UNCLASSIFIED_SHARE
    assert verdict(split, "quarantine") == "ready"


def test_unclassified_volume_blocks_even_a_perfect_score() -> None:
    """The distinction the spec says must survive: unknown senders stop a promotion."""
    split = VolumeSplit(aligned_pass=9000, fail_known=0, fail_unclassified=1000)
    assert readiness(split) == 100.0
    assert verdict(split, "none") == "not_ready"


def test_known_misconfiguration_lowers_the_score() -> None:
    split = VolumeSplit(aligned_pass=9000, fail_known=1000, fail_unclassified=0)
    assert readiness(split) == pytest.approx(90.0)
    assert verdict(split, "none") == "not_ready"


def test_minimum_volume_guard() -> None:
    """A handful of passing messages is not evidence."""
    split = VolumeSplit(aligned_pass=MIN_VOLUME - 1, fail_known=0, fail_unclassified=0)
    assert readiness(split) == 100.0
    assert verdict(split, "none") == "insufficient_data"
    assert verdict(VolumeSplit(aligned_pass=MIN_VOLUME), "none") == "ready"


def test_already_at_reject_and_not_applicable_short_circuit() -> None:
    assert verdict(VolumeSplit(), "reject") == "at_reject"
    assert verdict(VolumeSplit(), "na") == "not_applicable"
    assert verdict(VolumeSplit(0, 0, 5000), "missing") == "not_ready"


def test_splits_add() -> None:
    total = VolumeSplit(1, 2, 3) + VolumeSplit(10, 20, 30)
    assert (total.aligned_pass, total.fail_known, total.fail_unclassified) == (11, 22, 33)
    assert total.total == 66 and total.legitimate == 33 and total.failing == 55
