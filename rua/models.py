"""Database models.

Two halves, deliberately independent:

* ``Domain`` is DNS-derived. It is populatable with no report data at all, within
  seconds of setup, and it is what makes this tool useful on day zero. Nothing in
  it depends on a report ever arriving.
* Everything else is report-derived and fills in over the following 24-72 hours.

That split is why ``Domain`` carries no ``volume``, ``pass_rate`` or ``readiness``
column. Those three are computed from report data for the selected window and are
``null`` — not zero — until reports exist. Storing them on the domain row would
make "no data yet" and "genuinely zero" indistinguishable, which is precisely the
distinction the day-zero screen is built around.

Enums are rendered as VARCHAR with a CHECK constraint (``native_enum=False``)
rather than PostgreSQL ENUM types. Native enums need ``ALTER TYPE`` to gain a
value and Alembic's autogenerate does not detect changes to them, so ``alembic
check`` in CI would pass over a real drift. The vocabularies here are pinned by
the spec and the integrity is identical.
"""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from rua.db import Base


def _enum(python_enum: type[enum.Enum], name: str) -> Enum:
    """A VARCHAR + CHECK column for a string enum. See the module docstring."""
    return Enum(
        python_enum,
        name=name,
        native_enum=False,
        validate_strings=True,
        values_callable=lambda e: [member.value for member in e],
    )


# ─── Vocabularies ────────────────────────────────────────────────────────────
#
# PINNED (handoff spec): status is never colour alone — every state below has a
# word rendered beside it. These identifiers are the stored values; the display
# strings ("p=reject", "1 of 2 selectors", "not configured") live in the
# presentation layer, not here.


class Role(enum.StrEnum):
    PRIMARY = "primary"
    TRANSACTIONAL = "transactional"
    MARKETING = "marketing"
    BILLING = "billing"
    REGIONAL = "regional"
    PARKED = "parked"
    # Stored as "tenant"; rendered as "tenant default".
    TENANT = "tenant"


class DmarcPosture(enum.StrEnum):
    REJECT = "reject"
    QUARANTINE = "quarantine"
    NONE = "none"
    MISSING = "missing"
    NA = "na"


class SpfPosture(enum.StrEnum):
    PASS = "pass"
    SOFTFAIL = "softfail"
    MISSING = "missing"
    NA = "na"


class DkimPosture(enum.StrEnum):
    PASS = "pass"
    PARTIAL = "partial"
    MISSING = "missing"
    NA = "na"


class MtaStsPosture(enum.StrEnum):
    ENFORCE = "enforce"
    TESTING = "testing"
    MISSING = "missing"
    NA = "na"


class TlsRptPosture(enum.StrEnum):
    PRESENT = "present"
    MISSING = "missing"
    NA = "na"


class Disposition(enum.StrEnum):
    """DMARC policy applied by the receiver (RFC 7489 policy_evaluated)."""

    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class PolicyMode(enum.StrEnum):
    """MTA-STS policy mode as reported in a TLS-RPT policy block."""

    ENFORCE = "enforce"
    TESTING = "testing"
    NONE = "none"


class SourceClass(enum.StrEnum):
    KNOWN = "known"
    UNCLASSIFIED = "unclassified"


class IngestOutcome(enum.StrEnum):
    SUCCESS = "success"
    # Some reports in the batch failed; the rest were committed. A single
    # malformed report must never abort a whole run.
    PARTIAL = "partial"
    FAILURE = "failure"


# ─── DNS-derived ─────────────────────────────────────────────────────────────


class Domain(Base):
    """One verified domain in the tenant, with its DNS-derived posture.

    Populated by the daily Graph ``/domains`` sync plus live DNS checks. Complete
    without any report data.
    """

    __tablename__ = "domain"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    role: Mapped[Role] = mapped_column(_enum(Role, "role"))

    dmarc: Mapped[DmarcPosture] = mapped_column(_enum(DmarcPosture, "dmarc_posture"))
    spf: Mapped[SpfPosture] = mapped_column(_enum(SpfPosture, "spf_posture"))
    dkim: Mapped[DkimPosture] = mapped_column(_enum(DkimPosture, "dkim_posture"))
    mtasts: Mapped[MtaStsPosture] = mapped_column(_enum(MtaStsPosture, "mtasts_posture"))
    tlsrpt: Mapped[TlsRptPosture] = mapped_column(_enum(TlsRptPosture, "tlsrpt_posture"))

    # Tri-state, and deliberately not a plain bool as the spec's draft record had it:
    #   True  — the rua= tag includes the configured report mailbox
    #   False — a rua= tag exists but points elsewhere, or the record has no rua=
    #   None  — there is no DMARC record to parse (dmarc is `missing` or `na`)
    # The day-zero mismatch panel lists `IS FALSE` only. Collapsing None into False
    # would fill that panel with every domain that simply has no DMARC record,
    # burying the handful whose reports are actually being sent somewhere else.
    rua_matches: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # The rua= fragment found in DNS, verbatim, for the mismatch panel to display.
    rua_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    dns_checked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # A rua= mismatch is only meaningful when a DMARC record exists to carry it.
        CheckConstraint(
            "(dmarc IN ('missing', 'na') AND rua_matches IS NULL)"
            " OR (dmarc NOT IN ('missing', 'na') AND rua_matches IS NOT NULL)",
            name="ck_domain_rua_matches_requires_dmarc",
        ),
        Index("ix_domain_rua_mismatch", "rua_matches", postgresql_where="rua_matches IS FALSE"),
    )

    def __repr__(self) -> str:
        return f"<Domain {self.name} role={self.role}>"


# ─── Report-derived: DMARC aggregate ─────────────────────────────────────────


class Report(Base):
    """One ingested DMARC aggregate report."""

    __tablename__ = "report"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # RFC 7489 report_metadata/report_id. Unique because re-reading the same
    # mailbox message must not duplicate rows — this is the idempotency key.
    report_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    org_name: Mapped[str] = mapped_column(String(255), index=True)
    org_email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    date_begin: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    date_end: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))

    # Graph message id the report came from, for tracing a row back to a mailbox
    # item. Not unique: one message can carry more than one report.
    source_message_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    ingested_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    rows: Mapped[list[ReportRow]] = relationship(
        back_populates="report", cascade="all, delete-orphan", passive_deletes=True
    )


class ReportRow(Base):
    """One <record> from an aggregate report: a source IP and what it sent."""

    __tablename__ = "report_row"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    report_pk: Mapped[int] = mapped_column(ForeignKey("report.id", ondelete="CASCADE"), index=True)

    # Not a foreign key to domain.name on purpose. Anyone can send mail that causes
    # a third party to generate a report about a domain, so header_from here may be
    # a domain this tenant has never verified. Dropping those rows would hide
    # exactly the spoofing the tool exists to surface.
    domain_name: Mapped[str] = mapped_column(String(253), index=True)

    source_ip: Mapped[str] = mapped_column(INET, index=True)
    source_org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    count: Mapped[int] = mapped_column(BigInteger)

    disposition: Mapped[Disposition] = mapped_column(_enum(Disposition, "disposition"))
    # DMARC alignment, not raw auth results: this is what policy_evaluated reports.
    spf_aligned: Mapped[bool] = mapped_column(Boolean)
    dkim_aligned: Mapped[bool] = mapped_column(Boolean)

    date: Mapped[dt.date] = mapped_column(Date, index=True)

    report: Mapped[Report] = relationship(back_populates="rows")

    __table_args__ = (
        CheckConstraint("count >= 0", name="ck_report_row_count_non_negative"),
        # Serves the Domains/Sources/Overview queries, which are always
        # "this domain, this window".
        Index("ix_report_row_domain_date", "domain_name", "date"),
    )


# ─── Report-derived: TLS-RPT (RFC 8460) ──────────────────────────────────────


class TlsReport(Base):
    """One ingested TLS-RPT report."""

    __tablename__ = "tls_report"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    org_name: Mapped[str] = mapped_column(String(255), index=True)
    date_begin: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    date_end: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    source_message_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    ingested_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    rows: Mapped[list[TlsResultRow]] = relationship(
        back_populates="report", cascade="all, delete-orphan", passive_deletes=True
    )


class TlsResultRow(Base):
    """One policy/result pair from a TLS-RPT report."""

    __tablename__ = "tls_result_row"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tls_report_pk: Mapped[int] = mapped_column(
        ForeignKey("tls_report.id", ondelete="CASCADE"), index=True
    )

    policy_domain: Mapped[str] = mapped_column(String(253), index=True)
    policy_mode: Mapped[PolicyMode] = mapped_column(_enum(PolicyMode, "policy_mode"))

    # RFC 8460 §4.3 result-type, e.g. "starttls-not-supported",
    # "certificate-expired", "validation-failure". Free text rather than an enum:
    # the registry is extensible and a reporter emitting an unknown type must be
    # recorded, not dropped.
    result_type: Mapped[str] = mapped_column(String(128), index=True)

    success_count: Mapped[int] = mapped_column(BigInteger, default=0)
    failure_count: Mapped[int] = mapped_column(BigInteger, default=0)
    date: Mapped[dt.date] = mapped_column(Date, index=True)

    report: Mapped[TlsReport] = relationship(back_populates="rows")

    __table_args__ = (
        CheckConstraint(
            "success_count >= 0 AND failure_count >= 0",
            name="ck_tls_result_row_counts_non_negative",
        ),
        Index("ix_tls_result_row_domain_date", "policy_domain", "date"),
    )


# ─── Retention ───────────────────────────────────────────────────────────────


class DailyRollup(Base):
    """Post-retention daily aggregate, one row per domain per day.

    Raw ``report_row`` records are deleted after ``RETENTION_RAW_DAYS`` and survive
    here for ``RETENTION_ROLLUP_DAYS``. Rolling up drops the source IP, which is
    the field most likely to be personal data.
    """

    __tablename__ = "daily_rollup"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    domain_name: Mapped[str] = mapped_column(String(253), index=True)
    date: Mapped[dt.date] = mapped_column(Date, index=True)

    volume: Mapped[int] = mapped_column(BigInteger, default=0)
    pass_count: Mapped[int] = mapped_column(BigInteger, default=0)

    # The split the spec insists must survive rollup: volume failing because a
    # known sender is misconfigured is a fixable problem, volume failing from an
    # unclassified sender is the number that should stop someone tightening a
    # policy. Collapsing the two makes the readiness score misleading.
    fail_known: Mapped[int] = mapped_column(BigInteger, default=0)
    fail_unclassified: Mapped[int] = mapped_column(BigInteger, default=0)

    __table_args__ = (
        UniqueConstraint("domain_name", "date", name="uq_daily_rollup_domain_date"),
        CheckConstraint(
            "volume >= 0 AND pass_count >= 0 AND fail_known >= 0 AND fail_unclassified >= 0",
            name="ck_daily_rollup_counts_non_negative",
        ),
    )


# ─── Sender classification ───────────────────────────────────────────────────


class Source(Base):
    """A sending source, and whether it is recognised.

    "Unclassified" is not a synonym for "malicious": it means nobody has said what
    this is yet. That ambiguity is the point — it is what should stop an operator
    tightening a policy before investigating.
    """

    __tablename__ = "source"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    classification: Mapped[SourceClass] = mapped_column(
        _enum(SourceClass, "source_class"), default=SourceClass.UNCLASSIFIED, index=True
    )

    # CIDR blocks attributed to this org. PostgreSQL validates each entry and
    # supports containment operators, so classifying a report row is an index-
    # assisted lookup rather than a string prefix match.
    ip_ranges: Mapped[list[str]] = mapped_column(ARRAY(INET), default=list)

    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ─── Operational ─────────────────────────────────────────────────────────────


class Setting(Base):
    """Key/value configuration held in the database rather than the environment.

    Holds the encrypted Graph client secret, the configured report mailbox, and
    the wizard's per-step completion flags — the last of these so that setup
    survives a container restart mid-run.

    Values marked ``encrypted`` are Fernet tokens derived from ``SECRET_KEY``.
    Rotating that key makes them undecryptable by design. Nothing here is ever
    logged or returned by an endpoint.
    """

    __tablename__ = "setting"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IngestRun(Base):
    """One execution of the mailbox poll, successful or not.

    Written on every run without exception. A failure that only reaches stdout is
    invisible to the operator; Settings reads this table, and the stale banner and
    the day-zero "last poll" fact are both derived from it.
    """

    __tablename__ = "ingest_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome: Mapped[IngestOutcome] = mapped_column(_enum(IngestOutcome, "ingest_outcome"))

    messages_seen: Mapped[int] = mapped_column(Integer, default=0)
    reports_parsed: Mapped[int] = mapped_column(Integer, default=0)
    reports_failed: Mapped[int] = mapped_column(Integer, default=0)

    # Operator-facing text. Must never contain a credential or report contents.
    error_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "messages_seen >= 0 AND reports_parsed >= 0 AND reports_failed >= 0",
            name="ck_ingest_run_counts_non_negative",
        ),
    )
