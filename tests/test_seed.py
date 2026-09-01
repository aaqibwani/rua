"""Seed generator tests.

The generator must be bit-for-bit faithful to the prototype in
``DMARC Dashboard.dc.html``: the landing page renders a live dashboard on this
data, and every screenshot and fixture downstream assumes the same 60 rows with
the same posture on every run.

The expected values here are not copied from this implementation. They come from
an independent re-implementation of the prototype's JavaScript, whose FNV core was
first validated against the published FNV-1a-32 vectors (asserted below). A test
that only checks the code against itself would pass on a faithful port and on a
subtly wrong one alike.
"""

from __future__ import annotations

import hashlib

import pytest

from rua.seed import (
    ARCHE,
    FAMILIES,
    RUA_MISMATCHES,
    VARIANTS,
    _js_round,
    generate_domains,
    hash32,
    hash_frac,
    pick,
)

# ─── The hash ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", 0x811C9DC5),
        ("a", 0xE40C292C),
        ("b", 0xE70C2DE5),
        ("c", 0xE60C2C52),
        ("foobar", 0xBF9CF968),
    ],
)
def test_hash_matches_canonical_fnv1a32_vectors(value: str, expected: int) -> None:
    """Published FNV-1a-32 vectors. These anchor everything else in this file."""
    assert hash32(value) == expected


def test_hash_stays_inside_32_bits() -> None:
    # Python ints are arbitrary precision; an unmasked multiply diverges from the
    # second character onward and every posture in the dataset shifts.
    for seed in ("contoso.com", "adventure-works-invoices.com", "x" * 500):
        assert 0 <= hash32(seed) <= 0xFFFFFFFF


def test_hash_frac_divides_by_2_32_minus_1() -> None:
    # Dividing by 2**32 instead shifts every fraction by ~2.3e-10, which is enough
    # to flip a pick() index at a boundary.
    assert hash_frac("") == 0x811C9DC5 / 4294967295


def test_hash_frac_can_reach_exactly_one_and_pick_survives_it() -> None:
    # hash32 can return 4294967295, so floor(1.0 * 4) == 4. The trailing modulo in
    # pick() is what keeps that in range; it is load-bearing, not dead code.
    options = ("a", "b", "c", "d")
    assert pick(options, "anything") in options
    assert options[__import__("math").floor(1.0 * len(options)) % len(options)] == "a"


def test_js_round_rounds_halves_up_not_to_even() -> None:
    # Python's round() is banker's rounding: round(0.5) == 0, round(2.5) == 2.
    # JavaScript's Math.round sends halves toward +infinity.
    assert _js_round(0.5) == 1
    assert _js_round(1.5) == 2
    assert _js_round(2.5) == 3
    assert _js_round(-0.5) == 0
    assert round(0.5) == 0, "sanity: Python still disagrees, so the helper is needed"


# ─── Table integrity ─────────────────────────────────────────────────────────


def test_families_and_variants_are_the_expected_shape() -> None:
    assert len(FAMILIES) == 10
    assert FAMILIES[0] == "contoso"
    assert "adventure-works" in FAMILIES
    assert len(VARIANTS) == 6


def test_arche_weight_lists_keep_their_duplicates() -> None:
    """The weighting IS the repetition; de-duplicating silently re-weights."""
    for role, signals in ARCHE.items():
        for signal, options in signals.items():
            assert len(options) == 4, f"{role}.{signal} must have 4 slots"
    assert ARCHE["primary"]["dmarc"] == ("reject", "reject", "reject", "quarantine")
    assert ARCHE["transactional"]["spf"] == ("pass", "pass", "pass", "softfail")


def test_variant_name_forms() -> None:
    # No dot before "-invoices", and ".co.uk" hangs off the bare family.
    names = [v.name_for("contoso") for v in VARIANTS]
    assert names == [
        "contoso.com",
        "mail.contoso.com",
        "news.contoso.com",
        "contoso-invoices.com",
        "contoso.co.uk",
        "contoso.net",
    ]


# ─── The dataset ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def rows():
    return generate_domains()


@pytest.fixture(scope="module")
def by_name(rows):
    return {r.name: r for r in rows}


def test_exactly_sixty_domains(rows) -> None:
    assert len(rows) == 60


def test_generation_is_deterministic() -> None:
    first = generate_domains()
    second = generate_domains()
    assert first == second


def test_row_zero_is_the_tenant_domain_with_every_posture_na(rows) -> None:
    row = rows[0]
    assert row.name == "contoso.onmicrosoft.com"
    assert row.role == "tenant"
    assert row.posture == ("na", "na", "na", "na", "na")
    assert row.volume == 0
    assert row.pass_rate is None
    assert row.readiness is None
    assert row.gaps == 0
    assert row.warns == 0
    assert row.na is True


def test_contoso_com_is_replaced_not_appended(by_name) -> None:
    # out[0] = {...} overwrites in place. A port that appends the tenant row ends
    # up with 61 rows and a spurious contoso.com.
    assert "contoso.com" not in by_name
    assert "contoso.onmicrosoft.com" in by_name
    assert "fabrikam.com" in by_name, "the first surviving primary row"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "mail.contoso.com",
            {
                "role": "transactional",
                "posture": ("none", "pass", "pass", "testing", "present"),
                "volume": 450000,
                "pass_rate": 98.96528983990785,
                "gaps": 0,
                "warns": 2,
            },
        ),
        (
            "mail.fabrikam.com",
            {
                "role": "transactional",
                "posture": ("quarantine", "pass", "partial", "missing", "present"),
                "volume": 547000,
                "pass_rate": 94.13062406576485,
                "gaps": 1,
                "warns": 2,
            },
        ),
        (
            "lucerne.net",
            {
                "role": "parked",
                "posture": ("missing", "missing", "missing", "missing", "missing"),
                "volume": 31,
                "pass_rate": 86.53862124258619,
                "gaps": 5,
                "warns": 0,
            },
        ),
    ],
)
def test_pinned_rows_are_bit_exact(by_name, name: str, expected: dict) -> None:
    """Hand-traced vectors, exact to the last float bit.

    ``lucerne.net`` is the important one: its penalty accumulates as
    ``5.5 + 3.4 + 2.2 == 11.100000000000001``. Tidying that to ``11.1`` yields
    ``86.5386212425862`` instead of ``86.53862124258619`` and this fails.
    """
    row = by_name[name]
    assert row.role == expected["role"]
    assert row.posture == expected["posture"]
    assert row.volume == expected["volume"]
    assert row.pass_rate == expected["pass_rate"]
    assert row.readiness == expected["pass_rate"]
    assert row.gaps == expected["gaps"]
    assert row.warns == expected["warns"]


def test_full_output_digest(rows) -> None:
    """Pins all 60 rows at once, so no row can drift unnoticed.

    If this fails but the three pinned vectors above pass, diff the generated
    table against §6 of the extraction notes to find which row moved.
    """
    canonical = "\n".join(
        "|".join(
            [
                r.name,
                r.role,
                r.dmarc,
                r.spf,
                r.dkim,
                r.mtasts,
                r.tlsrpt,
                str(r.volume),
                repr(r.pass_rate),
                str(r.gaps),
                str(r.warns),
                str(r.na),
                str(r.rua_matches),
            ]
        )
        for r in rows
    )
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    assert digest == "1ccdd6caba0ee0b47242203abda9b131954b5af031c7f53752b9954cd8f97634"


# ─── Aggregate invariants ────────────────────────────────────────────────────


def test_aggregate_invariants(rows) -> None:
    sending = [r for r in rows if not r.na and r.volume > 100]
    total = sum(r.volume for r in sending)

    assert sum(1 for r in rows if r.na) == 1
    assert sum(1 for r in rows if r.role == "parked") == 10
    assert len(sending) == 49
    assert total == 11117000  # renders as "11.1M"
    assert sum(1 for r in rows if r.gaps > 0) == 41
    assert sum(1 for r in rows if r.gaps >= 4) == 12  # bold name + red row tint


def test_volume_weighted_pass_rate(rows) -> None:
    sending = [r for r in rows if not r.na and r.volume > 100]
    total = sum(r.volume for r in sending)
    weighted = sum(r.pass_rate * r.volume for r in sending) / total
    assert weighted == pytest.approx(96.50010552903117, abs=1e-11)


def test_gap_distribution(rows) -> None:
    distribution: dict[int, int] = {}
    for row in rows:
        distribution[row.gaps] = distribution.get(row.gaps, 0) + 1
    assert distribution == {0: 19, 1: 17, 2: 7, 3: 5, 4: 7, 5: 5}


def test_parked_volumes_use_the_override_formula(rows) -> None:
    # v.vol is 0 for parked, so the standard formula would give 0 for all ten.
    # The override is round(r * 40), and only one of them lands on zero.
    parked = [r.volume for r in rows if r.role == "parked"]
    assert parked == [24, 38, 21, 5, 39, 0, 11, 28, 30, 31]


def test_pass_rate_extremes(rows) -> None:
    rates = [r.pass_rate for r in rows if r.pass_rate is not None]
    assert min(rates) == 86.42747564691292  # woodgrove-invoices.com
    assert max(rates) == 99.78260395507854  # news.tailspin.com


def test_only_the_na_row_has_a_null_pass_rate(rows) -> None:
    # "null while reports are pending" is a separate concept from this generator's
    # null, which means "not applicable". Both must stay distinguishable from 0.
    nulls = [r.name for r in rows if r.pass_rate is None]
    assert nulls == ["contoso.onmicrosoft.com"]


# ─── rua= matching ───────────────────────────────────────────────────────────


def test_exactly_three_domains_have_a_misdirected_rua_tag(rows) -> None:
    """The day-zero mismatch panel lists these, and nothing else."""
    mismatched = {r.name: r.rua_value for r in rows if r.rua_matches is False}
    assert mismatched == RUA_MISMATCHES
    assert len(mismatched) == 3


def test_domains_without_a_dmarc_record_are_null_not_false(rows) -> None:
    # Tri-state on purpose. Collapsing None into False would drop every
    # DMARC-less domain into the "will never send you a report" panel and bury
    # the three that are genuinely misdirected.
    for row in rows:
        if row.dmarc in ("missing", "na"):
            assert row.rua_matches is None, row.name
            assert row.rua_value is None, row.name
        else:
            assert row.rua_matches is not None, row.name


def test_matching_domains_point_at_the_configured_mailbox() -> None:
    rows = generate_domains(mailbox="reports@example.org")
    matching = [r for r in rows if r.rua_matches is True]
    assert matching, "expected some matching domains"
    assert all(r.rua_value == "rua=mailto:reports@example.org" for r in matching)


def test_tenant_prefix_is_parameterised() -> None:
    # The prototype hard-codes "contoso"; the spec writes it as <tenant>.
    rows = generate_domains(tenant_prefix="fourthcoffee")
    assert rows[0].name == "fourthcoffee.onmicrosoft.com"
    assert len(rows) == 60
