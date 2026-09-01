"""Seeding against a real database.

Milestone 2's acceptance criterion: ``alembic upgrade head`` then ``rua seed
--demo`` produces exactly 60 domains, including one ``.onmicrosoft.com`` row with
every posture field ``na``, and running it twice is idempotent.

These use PostgreSQL rather than SQLite because the schema depends on
PostgreSQL-specific types (``INET``, ``ARRAY``) and on a partial index, none of
which SQLite would exercise.
"""

from __future__ import annotations

from sqlalchemy import func, select

from rua.models import DmarcPosture, Domain, Role
from rua.seed import RUA_MISMATCHES, seed_demo


def _count(session) -> int:
    return session.scalar(select(func.count()).select_from(Domain))


def test_seed_creates_exactly_sixty_domains(db_session) -> None:
    created, updated = seed_demo(db_session)
    assert (created, updated) == (60, 0)
    assert _count(db_session) == 60


def test_seed_is_idempotent(db_session) -> None:
    seed_demo(db_session)
    first = {
        d.name: (d.role, d.dmarc, d.spf, d.dkim, d.mtasts, d.tlsrpt)
        for d in db_session.scalars(select(Domain))
    }

    created, updated = seed_demo(db_session)

    assert (created, updated) == (0, 0), "a second run must change nothing"
    assert _count(db_session) == 60
    second = {
        d.name: (d.role, d.dmarc, d.spf, d.dkim, d.mtasts, d.tlsrpt)
        for d in db_session.scalars(select(Domain))
    }
    assert first == second


def test_seed_three_times_still_sixty(db_session) -> None:
    for _ in range(3):
        seed_demo(db_session)
    assert _count(db_session) == 60


def test_tenant_row_has_every_posture_field_na(db_session) -> None:
    seed_demo(db_session)
    tenant = db_session.scalar(select(Domain).where(Domain.role == Role.TENANT))

    assert tenant is not None
    assert tenant.name == "contoso.onmicrosoft.com"
    assert tenant.dmarc == DmarcPosture.NA
    assert tenant.spf.value == "na"
    assert tenant.dkim.value == "na"
    assert tenant.mtasts.value == "na"
    assert tenant.tlsrpt.value == "na"
    assert tenant.rua_matches is None


def test_contoso_com_is_never_persisted(db_session) -> None:
    seed_demo(db_session)
    assert db_session.scalar(select(Domain).where(Domain.name == "contoso.com")) is None


def test_seed_repairs_a_drifted_row(db_session) -> None:
    """A domain whose posture has been changed is corrected, not duplicated."""
    seed_demo(db_session)
    target = db_session.scalar(select(Domain).where(Domain.name == "fabrikam.com"))
    original = target.dmarc
    target.dmarc = DmarcPosture.MISSING
    target.rua_matches = None  # keep the CHECK constraint satisfied
    db_session.flush()

    created, updated = seed_demo(db_session)

    assert (created, updated) == (0, 1)
    assert _count(db_session) == 60
    db_session.refresh(target)
    assert target.dmarc == original


def test_rua_mismatches_are_persisted(db_session) -> None:
    seed_demo(db_session)
    rows = db_session.scalars(select(Domain).where(Domain.rua_matches.is_(False))).all()

    assert {r.name: r.rua_value for r in rows} == RUA_MISMATCHES


def test_domains_without_dmarc_have_null_rua_matches(db_session) -> None:
    seed_demo(db_session)
    rows = db_session.scalars(select(Domain)).all()

    for row in rows:
        if row.dmarc.value in ("missing", "na"):
            assert row.rua_matches is None, row.name
        else:
            assert row.rua_matches is not None, row.name


def test_seeded_domains_carry_no_report_derived_data(db_session) -> None:
    """The domain table is DNS-derived only.

    volume / pass_rate / readiness are report-derived and must be absent here, so
    that "no reports yet" cannot be confused with "zero". The day-zero screen is
    built entirely on that distinction.
    """
    seed_demo(db_session)
    columns = {c.name for c in Domain.__table__.columns}

    assert not columns & {"volume", "pass_rate", "readiness"}


def test_seeding_a_different_tenant_prefix(db_session) -> None:
    created, _ = seed_demo(db_session, tenant_prefix="fourthcoffee")
    assert created == 60
    assert db_session.scalar(select(Domain).where(Domain.role == Role.TENANT)).name == (
        "fourthcoffee.onmicrosoft.com"
    )
