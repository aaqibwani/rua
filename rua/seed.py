"""Deterministic demo data.

A faithful port of the sample-data generator in ``DMARC Dashboard.dc.html`` (the
``Component`` class: ``FAMILIES``, ``VARIANTS``, ``ARCHE``, ``domains()``, ``hash()``,
``pick()``). Determinism is the whole point: the same 60 domains with the same
posture on every run, so tests assert exact values and screenshots do not churn.

The generator contains no randomness and reads no clock — the original does not
either, so there is nothing to seed or freeze.

Porting hazards, all of which silently corrupt the output if missed
=================================================================
1. ``Math.imul(h, 16777619)`` is signed 32-bit multiplication with wraparound.
   Python ints are arbitrary precision, so the product must be masked with
   ``& 0xFFFFFFFF`` after every multiply or the hash diverges from the second
   character onward.
2. The divisor is ``4294967295`` (2**32 - 1), **not** ``4294967296``. The
   difference is ~2.3e-10 per unit, which is enough to flip a ``pick()`` index at
   a boundary — and this dataset has a live example: the seed
   ``"mail.contoso.comdmarc"`` lands at ``f * 4 == 3.99967…``, 0.00033 from
   wrapping to a different posture.
3. ``hash()`` can return exactly ``1.0`` (when h == 4294967295), so
   ``floor(1.0 * 4) == 4``. The trailing ``% len`` in :func:`pick` is what rescues
   that back to index 0. It is load-bearing, not defensive dead code.
4. JavaScript's ``Math.round`` rounds half toward +infinity; Python's ``round`` is
   banker's rounding, so ``round(0.5)`` is 1 in JS and 0 in Python. Use
   :func:`_js_round`.
5. ``charCodeAt`` yields UTF-16 code units. Iterate the ``str`` and use ``ord``;
   iterating ``s.encode("utf-8")`` diverges for any non-ASCII seed.
6. The ARCHE weight lists must keep their duplicate entries. The weighting *is*
   the repetition inside a 4-slot list; de-duplicating any list re-weights it and
   changes every downstream row.
7. ``pen`` accumulates as ``5.5 + 3.4 + 2.2 == 11.100000000000001`` in IEEE-754.
   Do not tidy that to ``11.1`` — the resulting pass rate differs in the 15th
   significant digit and the pinned test vectors fail.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from rua.logging import get_logger
from rua.models import (
    DkimPosture,
    DmarcPosture,
    Domain,
    MtaStsPosture,
    Role,
    SpfPosture,
    TlsRptPosture,
)

log = get_logger(__name__)

FNV_OFFSET_BASIS_32 = 2166136261
FNV_PRIME_32 = 16777619
UINT32_MAX = 4294967295  # the divisor; NOT 2**32

FAMILIES: tuple[str, ...] = (
    "contoso",
    "fabrikam",
    "northwind",
    "adventure-works",
    "tailspin",
    "wingtip",
    "litware",
    "proseware",
    "woodgrove",
    "lucerne",
)


@dataclass(frozen=True, slots=True)
class Variant:
    suffix_form: str  # a format string over the bare family name
    role: str
    vol: float

    def name_for(self, family: str) -> str:
        return self.suffix_form.format(f=family)


# Note the exact string forms: "-invoices.com" has no dot before the hyphen, and
# ".co.uk" is a plain suffix on the bare family, so "mail."/"news." never combine
# with it.
VARIANTS: tuple[Variant, ...] = (
    Variant("{f}.com", "primary", 1),
    Variant("mail.{f}.com", "transactional", 0.55),
    Variant("news.{f}.com", "marketing", 0.3),
    Variant("{f}-invoices.com", "billing", 0.08),
    Variant("{f}.co.uk", "regional", 0.12),
    Variant("{f}.net", "parked", 0),
)

# Weighted posture tables. Every list is exactly 4 entries; repetition is the
# weight (see hazard 6). There is no `tenant` key — that row is overwritten.
ARCHE: dict[str, dict[str, tuple[str, ...]]] = {
    "primary": {
        "dmarc": ("reject", "reject", "reject", "quarantine"),
        "spf": ("pass", "pass", "pass", "pass"),
        "dkim": ("pass", "pass", "pass", "pass"),
        "mtasts": ("enforce", "enforce", "testing", "enforce"),
        "tlsrpt": ("present", "present", "present", "present"),
    },
    "transactional": {
        "dmarc": ("reject", "quarantine", "quarantine", "none"),
        "spf": ("pass", "pass", "pass", "softfail"),
        "dkim": ("pass", "pass", "partial", "pass"),
        "mtasts": ("enforce", "testing", "testing", "missing"),
        "tlsrpt": ("present", "present", "present", "missing"),
    },
    "marketing": {
        "dmarc": ("quarantine", "none", "none", "quarantine"),
        "spf": ("pass", "pass", "softfail", "pass"),
        "dkim": ("pass", "partial", "pass", "missing"),
        "mtasts": ("testing", "missing", "testing", "missing"),
        "tlsrpt": ("present", "missing", "present", "missing"),
    },
    "billing": {
        "dmarc": ("quarantine", "none", "missing", "none"),
        "spf": ("pass", "softfail", "missing", "pass"),
        "dkim": ("partial", "missing", "pass", "missing"),
        "mtasts": ("testing", "missing", "missing", "missing"),
        "tlsrpt": ("missing", "missing", "present", "missing"),
    },
    "regional": {
        "dmarc": ("reject", "quarantine", "none", "missing"),
        "spf": ("pass", "pass", "softfail", "missing"),
        "dkim": ("pass", "pass", "missing", "missing"),
        "mtasts": ("enforce", "testing", "missing", "missing"),
        "tlsrpt": ("present", "present", "missing", "missing"),
    },
    "parked": {
        "dmarc": ("reject", "none", "missing", "missing"),
        "spf": ("pass", "missing", "missing", "missing"),
        "dkim": ("missing", "missing", "missing", "missing"),
        "mtasts": ("missing", "missing", "missing", "missing"),
        "tlsrpt": ("missing", "missing", "missing", "missing"),
    },
}

SIGNALS: tuple[str, ...] = ("dmarc", "spf", "dkim", "mtasts", "tlsrpt")

# Tone per posture value, from the prototype's LABELS table. Drives gaps/warns.
# `na` is absent from every sub-table; the prototype's `|| ['', 'na']` fallback
# supplies tone "na", which counts as neither a gap nor a warning.
TONES: dict[str, dict[str, str]] = {
    "dmarc": {"reject": "ok", "quarantine": "warn", "none": "warn", "missing": "gap"},
    "spf": {"pass": "ok", "softfail": "warn", "missing": "gap"},
    "dkim": {"pass": "ok", "partial": "warn", "missing": "gap"},
    "mtasts": {"enforce": "ok", "testing": "warn", "missing": "gap"},
    "tlsrpt": {"present": "ok", "missing": "gap"},
}

# The three domains whose rua= tag does not point at this deployment, taken from
# `Day Zero A Waiting Page.dc.html`. They are what the day-zero mismatch panel
# lists, and they are the highest-value diagnostic in the product: without them a
# domain silently never appears and nobody can say why.
RUA_MISMATCHES: dict[str, str] = {
    "news.tailspin.com": "rua=mailto:dmarc@tailspin-mktg.example",
    "litware-invoices.com": "rua=mailto:reports@dmarcian.example",
    "woodgrove.co.uk": "no rua= tag in the record",
}

DEFAULT_TENANT_PREFIX = "contoso"
DEFAULT_DEMO_MAILBOX = "dmarc@contoso.com"


# ─── The hash ────────────────────────────────────────────────────────────────


def hash32(value: str) -> int:
    """Canonical FNV-1a, 32 bits — the prototype's ``hash()`` before division.

    Validated against the published FNV-1a-32 vectors:
    ``"" -> 0x811c9dc5``, ``"a" -> 0xe40c292c``, ``"foobar" -> 0xbf9cf968``.
    """
    h = FNV_OFFSET_BASIS_32
    for char in value:
        h ^= ord(char)  # UTF-16 code unit in JS; ord() over str matches for ASCII
        h = (h * FNV_PRIME_32) & 0xFFFFFFFF  # hazard 1
    return h


def hash_frac(value: str) -> float:
    """``hash32`` mapped to [0.0, 1.0] **inclusive** — the prototype's ``hash()``."""
    return hash32(value) / UINT32_MAX  # hazard 2


def pick(options: tuple[str, ...], seed: str) -> str:
    """Select from a weighted list. The trailing modulo is load-bearing (hazard 3)."""
    n = len(options)
    return options[math.floor(hash_frac(seed) * n) % n]


def _js_round(x: float) -> int:
    """``Math.round`` semantics: halves go toward +infinity (hazard 4)."""
    return math.floor(x + 0.5)


# ─── The rows ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SeedDomain:
    """One generated row.

    ``volume``, ``pass_rate`` and ``readiness`` are carried here but are **not**
    written to the ``domain`` table — that table is DNS-derived and those three
    are report-derived. They are retained because they pin the generator's
    behaviour in tests and because later milestones synthesise report data from
    them.
    """

    name: str
    role: str
    dmarc: str
    spf: str
    dkim: str
    mtasts: str
    tlsrpt: str
    volume: int
    pass_rate: float | None
    readiness: float | None
    gaps: int
    warns: int
    na: bool
    rua_matches: bool | None
    rua_value: str | None

    @property
    def posture(self) -> tuple[str, str, str, str, str]:
        return (self.dmarc, self.spf, self.dkim, self.mtasts, self.tlsrpt)


def _tone(signal: str, value: str) -> str:
    return TONES[signal].get(value, "na")


def _rua_state(name: str, dmarc: str, mailbox: str) -> tuple[bool | None, str | None]:
    """Resolve the tri-state rua= match. See ``Domain.rua_matches``."""
    if dmarc in ("missing", "na"):
        # No DMARC record, so no rua= tag to compare against. Not a mismatch —
        # reporting it as one would bury the domains that really are misdirected.
        return None, None
    if name in RUA_MISMATCHES:
        return False, RUA_MISMATCHES[name]
    return True, f"rua=mailto:{mailbox}"


def generate_domains(
    tenant_prefix: str = DEFAULT_TENANT_PREFIX,
    mailbox: str = DEFAULT_DEMO_MAILBOX,
) -> list[SeedDomain]:
    """Build the 60 demo domains. Pure, deterministic, no I/O.

    Iteration is family-major, variant-minor, so row index is
    ``family_index * 6 + variant_index``.

    Row 0 is **replaced** in place by the tenant's ``.onmicrosoft.com`` domain,
    not appended — so the count stays exactly 60 and ``contoso.com`` never appears
    in the dataset. ``fabrikam.com`` is the first surviving ``primary`` row.
    """
    rows: list[dict] = []

    # Pass 1 — posture and volume.
    for family in FAMILIES:
        for variant in VARIANTS:
            name = variant.name_for(family)
            arche = ARCHE[variant.role]
            r = hash_frac(name)

            if variant.role == "parked":
                # Overwrites the vol-based formula entirely. Parked domains get a
                # trickle of 0-39 messages, not zero.
                volume = _js_round(r * 40)
            else:
                volume = _js_round(variant.vol * (140000 + r * 900000) / 1000) * 1000

            rows.append(
                {
                    "name": name,
                    "role": variant.role,
                    "dmarc": pick(arche["dmarc"], name + "dmarc"),
                    "spf": pick(arche["spf"], name + "spf"),
                    "dkim": pick(arche["dkim"], name + "dkim"),
                    "mtasts": pick(arche["mtasts"], name + "mtasts"),
                    "tlsrpt": pick(arche["tlsrpt"], name + "tlsrpt"),
                    "volume": volume,
                    "na": False,
                }
            )

    # Row-0 replacement, after the whole double loop.
    rows[0] = {
        "name": f"{tenant_prefix}.onmicrosoft.com",
        "role": "tenant",
        "dmarc": "na",
        "spf": "na",
        "dkim": "na",
        "mtasts": "na",
        "tlsrpt": "na",
        "volume": 0,
        "na": True,
    }

    # Pass 2 — derived values over all 60 rows, including the replaced row 0.
    out: list[SeedDomain] = []
    for row in rows:
        penalty = (
            (5.5 if row["spf"] != "pass" else 0)
            + (3.4 if row["dkim"] != "pass" else 0)
            + (2.2 if row["dmarc"] == "missing" else 0)
        )  # hazard 7: leave the float accumulation exactly as-is
        pass_rate = (
            None
            if row["na"]
            else max(41, min(99.9, 99.8 - penalty - hash_frac(row["name"] + "p") * 2.4))
        )
        rua_matches, rua_value = _rua_state(row["name"], row["dmarc"], mailbox)

        out.append(
            SeedDomain(
                name=row["name"],
                role=row["role"],
                dmarc=row["dmarc"],
                spf=row["spf"],
                dkim=row["dkim"],
                mtasts=row["mtasts"],
                tlsrpt=row["tlsrpt"],
                volume=row["volume"],
                pass_rate=pass_rate,
                # The prototype aliases readiness to passRate. That is explicitly
                # NOT a specification — the real formula is a milestone-6 decision
                # and must be reviewed before anyone acts on it.
                readiness=pass_rate,
                gaps=sum(1 for s in SIGNALS if _tone(s, row[s]) == "gap"),
                warns=sum(1 for s in SIGNALS if _tone(s, row[s]) == "warn"),
                na=row["na"],
                rua_matches=rua_matches,
                rua_value=rua_value,
            )
        )
    return out


def iter_domains(**kwargs) -> Iterator[SeedDomain]:
    yield from generate_domains(**kwargs)


# ─── Persistence ─────────────────────────────────────────────────────────────


def seed_demo(
    session: Session,
    tenant_prefix: str = DEFAULT_TENANT_PREFIX,
    mailbox: str = DEFAULT_DEMO_MAILBOX,
) -> tuple[int, int]:
    """Insert or update the demo domains. Idempotent.

    Returns ``(created, updated)``. Running twice leaves the row count and every
    value unchanged, which is what makes this safe to call from a container
    entrypoint or a test fixture.

    Only DNS-derived columns are written. Report-derived data — volume, pass
    rates, TLS results — is deliberately not seeded here: the readiness formula
    and the known/unclassified split are milestone-6 decisions, and inventing
    them now would bake a guess into every screenshot and test.
    """
    generated = generate_domains(tenant_prefix=tenant_prefix, mailbox=mailbox)

    existing = {
        domain.name: domain
        for domain in session.scalars(
            select(Domain).where(Domain.name.in_([row.name for row in generated]))
        )
    }

    created = updated = 0
    for row in generated:
        domain = existing.get(row.name)
        if domain is None:
            session.add(
                Domain(
                    name=row.name,
                    role=Role(row.role),
                    dmarc=DmarcPosture(row.dmarc),
                    spf=SpfPosture(row.spf),
                    dkim=DkimPosture(row.dkim),
                    mtasts=MtaStsPosture(row.mtasts),
                    tlsrpt=TlsRptPosture(row.tlsrpt),
                    rua_matches=row.rua_matches,
                    rua_value=row.rua_value,
                )
            )
            created += 1
            continue

        changes = {
            "role": Role(row.role),
            "dmarc": DmarcPosture(row.dmarc),
            "spf": SpfPosture(row.spf),
            "dkim": DkimPosture(row.dkim),
            "mtasts": MtaStsPosture(row.mtasts),
            "tlsrpt": TlsRptPosture(row.tlsrpt),
            "rua_matches": row.rua_matches,
            "rua_value": row.rua_value,
        }
        if any(getattr(domain, field) != value for field, value in changes.items()):
            for field, value in changes.items():
                setattr(domain, field, value)
            updated += 1

    session.flush()
    log.info("seed_demo_complete", generated=len(generated), created=created, updated=updated)
    return created, updated
