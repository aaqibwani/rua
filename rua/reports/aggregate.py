"""DMARC aggregate report parsing (RFC 7489 Appendix C).

The document is small and its shape is fixed::

    feedback
      report_metadata   org_name, email, report_id, date_range{begin,end}
      policy_published  domain, p, sp, adkim, aspf, pct
      record*           row{source_ip, count, policy_evaluated{disposition,dkim,spf}}
                        identifiers{header_from}
                        auth_results{...}

What is not fixed is how faithfully receivers produce it, so this parser is
liberal: a missing optional element yields a default rather than an exception,
and a record it cannot make sense of is skipped with a count rather than
aborting the report. Only a document that is not a DMARC report at all, or one
missing the fields needed to store it, raises.

``policy_evaluated`` is the source for alignment, not ``auth_results``. The
former is the receiver's DMARC verdict — did SPF or DKIM pass *and* align — and
that is what the dashboard means by "SPF align" and "DKIM align". ``auth_results``
records the raw authentication outcome, which can pass while alignment fails.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element  # types only; parsing goes through defusedxml

from defusedxml.ElementTree import ParseError, fromstring

from rua.logging import get_logger

log = get_logger(__name__)

# A single report with more records than this is not something we will render,
# and holding it in memory is a denial-of-service vector.
MAX_RECORDS = 50_000

VALID_DISPOSITIONS = frozenset({"none", "quarantine", "reject"})


class ReportParseError(Exception):
    """A document is not a usable DMARC aggregate report."""


@dataclass(frozen=True, slots=True)
class AggregateRow:
    source_ip: str
    count: int
    disposition: str
    spf_aligned: bool
    dkim_aligned: bool
    header_from: str


@dataclass(slots=True)
class AggregateReport:
    org_name: str
    report_id: str
    date_begin: dt.datetime
    date_end: dt.datetime
    policy_domain: str
    org_email: str | None = None
    rows: list[AggregateRow] = field(default_factory=list)
    skipped_records: int = 0
    synthesised_id: bool = False

    @property
    def total_messages(self) -> int:
        return sum(row.count for row in self.rows)


def _text(parent: Element | None, path: str, default: str = "") -> str:
    if parent is None:
        return default
    found = parent.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _timestamp(raw: str, what: str) -> dt.datetime:
    """RFC 7489 date_range values are seconds since the epoch, UTC."""
    try:
        return dt.datetime.fromtimestamp(int(raw), tz=dt.UTC)
    except (ValueError, OverflowError, OSError):
        raise ReportParseError(f"{what} is not a usable unix timestamp: {raw!r}") from None


def _aligned(value: str) -> bool:
    """policy_evaluated/dkim and /spf carry "pass" or "fail".

    Anything else — an empty element, a receiver writing "none" — is treated as
    not aligned. Guessing generously here would inflate the readiness score,
    which is the one number someone acts on before tightening a live policy.
    """
    return value.strip().lower() == "pass"


def _normalise_ip(raw: str) -> str | None:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def parse_aggregate_report(content: bytes) -> AggregateReport:
    """Parse one aggregate report document.

    Raises :class:`ReportParseError` for anything unusable. The caller records
    that against the single report and continues with the rest of the batch.
    """
    try:
        # defusedxml, not ElementTree: reports are attacker-influenced and the
        # stdlib parser expands entities.
        root = fromstring(content)
    except ParseError as exc:
        raise ReportParseError(f"not well-formed XML: {exc}") from None
    except Exception as exc:
        # defusedxml raises EntitiesForbidden / DTDForbidden for hostile input.
        raise ReportParseError(f"rejected by the XML parser: {type(exc).__name__}") from None

    if root.tag != "feedback":
        raise ReportParseError(f"root element is <{root.tag}>, not <feedback>")

    metadata = root.find("report_metadata")
    policy = root.find("policy_published")

    org_name = _text(metadata, "org_name") or "unknown"
    org_email = _text(metadata, "email") or None
    policy_domain = _text(policy, "domain")

    date_range = metadata.find("date_range") if metadata is not None else None
    begin_raw = _text(date_range, "begin")
    end_raw = _text(date_range, "end")
    if not begin_raw or not end_raw:
        raise ReportParseError("report_metadata/date_range is missing begin or end")
    date_begin = _timestamp(begin_raw, "date_range/begin")
    date_end = _timestamp(end_raw, "date_range/end")

    report_id = _text(metadata, "report_id")
    synthesised = False
    if not report_id:
        # report_id is the idempotency key, so one has to exist. The conventional
        # aggregate filename is org!domain!begin!end, which is deterministic for
        # a given report — so a redelivery of the same report still collides and
        # is still deduplicated.
        basis = f"{org_name}!{policy_domain}!{begin_raw}!{end_raw}"
        report_id = "synthesised:" + hashlib.sha256(basis.encode()).hexdigest()[:32]
        synthesised = True
        log.info("aggregate_report_id_synthesised", org=org_name, domain=policy_domain)

    records = root.findall("record")
    if len(records) > MAX_RECORDS:
        raise ReportParseError(f"report holds {len(records)} records, over the {MAX_RECORDS} limit")

    rows: list[AggregateRow] = []
    skipped = 0
    for record in records:
        row = record.find("row")
        if row is None:
            skipped += 1
            continue

        source_ip = _normalise_ip(_text(row, "source_ip"))
        if source_ip is None:
            skipped += 1
            continue

        try:
            count = int(_text(row, "count", "0"))
        except ValueError:
            skipped += 1
            continue
        if count < 0:
            skipped += 1
            continue

        evaluated = row.find("policy_evaluated")
        disposition = _text(evaluated, "disposition", "none").lower()
        if disposition not in VALID_DISPOSITIONS:
            # Receivers do emit odd values here. The row's volume still counts;
            # only the disposition is unknown, and "none" is the safe reading
            # because it claims the least.
            disposition = "none"

        # header_from is what the dashboard groups by. Falling back to the
        # published policy domain keeps a row that would otherwise be dropped.
        header_from = (_text(record.find("identifiers"), "header_from") or policy_domain).lower()
        if not header_from:
            skipped += 1
            continue

        rows.append(
            AggregateRow(
                source_ip=source_ip,
                count=count,
                disposition=disposition,
                spf_aligned=_aligned(_text(evaluated, "spf")),
                dkim_aligned=_aligned(_text(evaluated, "dkim")),
                header_from=header_from,
            )
        )

    if not rows and not records:
        # A report with no records is legitimate — a domain that sent no mail in
        # the window — so this is not an error, just worth noticing.
        log.info("aggregate_report_empty", org=org_name, report_id=report_id)

    return AggregateReport(
        org_name=org_name,
        org_email=org_email,
        report_id=report_id,
        date_begin=date_begin,
        date_end=date_end,
        policy_domain=policy_domain.lower(),
        rows=rows,
        skipped_records=skipped,
        synthesised_id=synthesised,
    )
