"""Attachment extraction and report parsing.

Reports are attacker-influenced input — anyone can send mail that causes a third
party to generate a report about your domain — so roughly half of these are
adversarial rather than happy-path.
"""

from __future__ import annotations

import gzip
import io
import json
import zipfile
from pathlib import Path

import pytest

from rua.reports import extract_documents, parse_aggregate_report, parse_tls_report
from rua.reports.aggregate import ReportParseError
from rua.reports.extract import (
    MAX_ARCHIVE_MEMBERS,
    MAX_ATTACHMENT_BYTES,
    ExtractionError,
)
from rua.reports.tlsrpt import TlsReportParseError

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# ─── Extraction ──────────────────────────────────────────────────────────────


def test_bare_xml_passes_through() -> None:
    (doc,) = extract_documents("report.xml", fixture("aggregate_google.xml"))
    assert doc.kind == "xml"


def test_gzip_is_decompressed() -> None:
    packed = gzip.compress(fixture("aggregate_google.xml"))
    (doc,) = extract_documents("report.xml.gz", packed)

    assert doc.kind == "xml"
    assert doc.filename == "report.xml"
    assert b"<feedback>" in doc.content


def test_zip_is_unpacked() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.xml", fixture("aggregate_google.xml"))
    (doc,) = extract_documents("report.zip", buffer.getvalue())

    assert doc.kind == "xml"
    assert doc.filename == "report.xml"


def test_kind_is_decided_by_content_not_extension() -> None:
    # Receivers do mislabel. A JSON TLS report named .xml is still JSON.
    (doc,) = extract_documents("tls.xml", fixture("tlsrpt_google.json"))
    assert doc.kind == "json"


def test_gzip_bomb_is_refused() -> None:
    """A megabyte of zeroes compresses ~1000:1; a real report does not."""
    bomb = gzip.compress(b"<" + b"\0" * (8 * 1024 * 1024))

    with pytest.raises(ExtractionError, match=r"bomb|limit"):
        extract_documents("bomb.xml.gz", bomb)


def test_zip_bomb_is_refused() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("huge.xml", b"<" + b"\0" * (64 * 1024 * 1024))

    with pytest.raises(ExtractionError, match=r"bomb|limit"):
        extract_documents("bomb.zip", buffer.getvalue())


def test_archive_with_too_many_members_is_refused() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for i in range(MAX_ARCHIVE_MEMBERS + 5):
            archive.writestr(f"r{i}.xml", b"<feedback/>")

    with pytest.raises(ExtractionError, match="members"):
        extract_documents("many.zip", buffer.getvalue())


def test_oversized_attachment_is_refused_unread() -> None:
    with pytest.raises(ExtractionError, match="over the"):
        extract_documents("big.gz", b"\x1f\x8b" + b"\0" * MAX_ATTACHMENT_BYTES)


def test_empty_attachment_is_refused() -> None:
    with pytest.raises(ExtractionError, match="empty"):
        extract_documents("nothing.gz", b"")


def test_corrupt_gzip_is_refused_not_raised_raw() -> None:
    with pytest.raises(ExtractionError, match="gzip"):
        extract_documents("truncated.xml.gz", b"\x1f\x8b\x08\x00 truncated rubbish")


def test_unrecognised_attachment_is_refused() -> None:
    with pytest.raises(ExtractionError, match="neither gzip"):
        extract_documents("photo.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 64)


def test_zip_member_paths_are_reduced_to_basenames() -> None:
    """Nothing is written to disk, but a crafted name must not reach a log line."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../etc/passwd.xml", b"<feedback/>")
    (doc,) = extract_documents("evil.zip", buffer.getvalue())

    assert doc.filename == "passwd.xml"
    assert "/" not in doc.filename


# ─── Aggregate parsing ───────────────────────────────────────────────────────


def test_common_aggregate_report() -> None:
    report = parse_aggregate_report(fixture("aggregate_google.xml"))

    assert report.org_name == "google.com"
    assert report.report_id == "7038306147107031780"
    assert report.policy_domain == "fabrikam.com"
    assert len(report.rows) == 3
    assert report.total_messages == 1697
    assert report.skipped_records == 0


def test_alignment_comes_from_policy_evaluated() -> None:
    rows = {r.source_ip: r for r in parse_aggregate_report(fixture("aggregate_google.xml")).rows}

    assert rows["209.85.220.41"].spf_aligned is True
    assert rows["209.85.220.41"].dkim_aligned is True
    # This row's raw SPF was softfail and its alignment failed.
    assert rows["198.51.100.7"].spf_aligned is False
    assert rows["198.51.100.7"].disposition == "quarantine"


def test_ipv6_sources_are_normalised() -> None:
    ips = {r.source_ip for r in parse_aggregate_report(fixture("aggregate_google.xml")).rows}
    assert "2a00:1450:4864:20::42d" in ips


def test_header_from_is_lowercased() -> None:
    domains = {r.header_from for r in parse_aggregate_report(fixture("aggregate_google.xml")).rows}
    assert "mail.fabrikam.com" in domains, "MAIL.Fabrikam.COM must fold to lower case"


def test_alternate_element_ordering_parses() -> None:
    report = parse_aggregate_report(fixture("aggregate_microsoft.xml"))
    assert report.org_name == "Enterprise Outlook"
    assert len(report.rows) == 1


def test_missing_report_id_is_synthesised_deterministically() -> None:
    first = parse_aggregate_report(fixture("aggregate_no_report_id.xml"))
    second = parse_aggregate_report(fixture("aggregate_no_report_id.xml"))

    assert first.synthesised_id is True
    assert first.report_id.startswith("synthesised:")
    # Determinism is what preserves idempotency: a redelivery of the same report
    # must collide with the first ingest rather than insert a duplicate.
    assert first.report_id == second.report_id


def test_bad_records_are_skipped_individually_not_fatally() -> None:
    report = parse_aggregate_report(fixture("aggregate_odd_records.xml"))

    assert report.skipped_records == 3  # bad IP, bad count, no <row>
    assert len(report.rows) == 2
    # An unrecognised disposition keeps the row and reads as the safest value.
    dispositions = {r.disposition for r in report.rows}
    assert dispositions == {"none", "reject"}


def test_record_without_identifiers_falls_back_to_the_policy_domain() -> None:
    rows = {
        r.source_ip: r for r in parse_aggregate_report(fixture("aggregate_odd_records.xml")).rows
    }
    assert rows["192.0.2.66"].header_from == "tailspin.com"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("malformed_not_xml.xml", "not well-formed"),
        ("malformed_wrong_root.xml", "not <feedback>"),
        ("billion_laughs.xml", "rejected by the XML parser"),
    ],
)
def test_unusable_documents_are_refused(name: str, expected: str) -> None:
    with pytest.raises(ReportParseError, match=expected):
        parse_aggregate_report(fixture(name))


def test_entity_expansion_is_refused_rather_than_expanded() -> None:
    """The stdlib parser would expand this to gigabytes. defusedxml refuses it."""
    with pytest.raises(ReportParseError):
        parse_aggregate_report(fixture("billion_laughs.xml"))


def test_missing_date_range_is_fatal() -> None:
    # Without a window the rows cannot be placed on a timeline, so there is
    # nothing useful to store.
    document = b"<feedback><report_metadata><org_name>x</org_name></report_metadata></feedback>"
    with pytest.raises(ReportParseError, match="date_range"):
        parse_aggregate_report(document)


# ─── TLS-RPT parsing ─────────────────────────────────────────────────────────


def test_tls_report_success_and_failures() -> None:
    report = parse_tls_report(fixture("tlsrpt_google.json"))
    by_type = {r.result_type: r for r in report.results}

    assert report.org_name == "Google Inc."
    assert by_type["successful-session"].success_count == 5218
    assert by_type["certificate-expired"].failure_count == 9
    assert by_type["starttls-not-supported"].failure_count == 3
    assert all(r.policy_domain == "fabrikam.com" for r in report.results)


def test_tls_policy_mode_read_from_the_policy_string() -> None:
    report = parse_tls_report(fixture("tlsrpt_google.json"))
    assert {r.policy_mode for r in report.results} == {"enforce"}


def test_tls_failures_the_breakdown_does_not_explain_are_kept() -> None:
    """The summary is authoritative; dropping the remainder understates failure."""
    report = parse_tls_report(fixture("tlsrpt_unexplained_failures.json"))
    by_type = {r.result_type: r for r in report.results}

    assert by_type["validation-failure"].failure_count == 15
    assert by_type["unspecified-failure"].failure_count == 25  # 40 declared - 15 explained
    assert sum(r.failure_count for r in report.results) == 40


def test_unknown_result_types_are_recorded_not_dropped() -> None:
    """RFC 8460's registry is extensible; an unheard-of failure still matters."""
    document = json.dumps(
        {
            "organization-name": "future.example",
            "date-range": {
                "start-datetime": "2026-01-01T00:00:00Z",
                "end-datetime": "2026-01-01T23:59:59Z",
            },
            "report-id": "future-1",
            "policies": [
                {
                    "policy": {"policy-domain": "example.com"},
                    "summary": {"total-failure-session-count": 3},
                    "failure-details": [
                        {"result-type": "some-future-failure", "failed-session-count": 3}
                    ],
                }
            ],
        }
    ).encode()

    report = parse_tls_report(document)
    assert report.results[0].result_type == "some-future-failure"


@pytest.mark.parametrize(
    "document",
    [b"not json at all", b"[]", b'{"organization-name": "x"}', b'{"date-range": {}}'],
)
def test_unusable_tls_documents_are_refused(document: bytes) -> None:
    with pytest.raises(TlsReportParseError):
        parse_tls_report(document)
