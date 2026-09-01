"""TLS-RPT report parsing (RFC 8460 §4).

JSON, not XML, and simpler than the aggregate format::

    {
      "organization-name": "...",
      "date-range": {"start-datetime": "...", "end-datetime": "..."},
      "report-id": "...",
      "policies": [
        {
          "policy": {"policy-type": "sts", "policy-domain": "example.com", ...},
          "summary": {"total-successful-session-count": N,
                      "total-failure-session-count": M},
          "failure-details": [{"result-type": "...", "failed-session-count": N}]
        }
      ]
    }

``result-type`` is deliberately not an enum here. RFC 8460 §4.3 defines an
extensible registry, and a receiver reporting a type we have not heard of should
have it recorded, not dropped — that is precisely the kind of failure the TLS tab
exists to surface.

Note the shape of the counts. ``summary`` gives the totals for the policy;
``failure-details`` breaks the failures down by cause. Adding the two together
would double-count, so successes come from the summary and failures come from
the details, with a synthetic row carrying any remainder the details do not
explain.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field

from rua.logging import get_logger

log = get_logger(__name__)

MAX_POLICIES = 5_000
MAX_RESULTS_PER_POLICY = 1_000

VALID_POLICY_MODES = frozenset({"enforce", "testing", "none"})

# Result type used for failures the per-cause breakdown does not account for.
UNSPECIFIED_RESULT = "unspecified-failure"


class TlsReportParseError(Exception):
    """A document is not a usable TLS-RPT report."""


@dataclass(frozen=True, slots=True)
class TlsResult:
    policy_domain: str
    policy_mode: str
    result_type: str
    success_count: int
    failure_count: int


@dataclass(slots=True)
class TlsReportDocument:
    org_name: str
    report_id: str
    date_begin: dt.datetime
    date_end: dt.datetime
    results: list[TlsResult] = field(default_factory=list)
    synthesised_id: bool = False


def _datetime(raw: object, what: str) -> dt.datetime:
    """RFC 8460 uses RFC 3339 date-times, commonly with a trailing Z."""
    if not isinstance(raw, str) or not raw:
        raise TlsReportParseError(f"{what} is missing")
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise TlsReportParseError(f"{what} is not an RFC 3339 date-time: {raw!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _count(value: object) -> int:
    """Counts arrive as ints, and occasionally as numeric strings."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str):
        try:
            return max(0, int(value.strip()))
        except ValueError:
            return 0
    return 0


def parse_tls_report(content: bytes) -> TlsReportDocument:
    """Parse one TLS-RPT document.

    Raises :class:`TlsReportParseError` for anything unusable, so the caller can
    attribute the failure to this report and keep processing the batch.
    """
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TlsReportParseError(f"not valid JSON: {exc}") from None

    if not isinstance(document, dict):
        raise TlsReportParseError("top level is not a JSON object")

    org_name = str(document.get("organization-name") or "unknown")

    date_range = document.get("date-range")
    if not isinstance(date_range, dict):
        raise TlsReportParseError("date-range is missing")
    date_begin = _datetime(date_range.get("start-datetime"), "date-range/start-datetime")
    date_end = _datetime(date_range.get("end-datetime"), "date-range/end-datetime")

    report_id = str(document.get("report-id") or "").strip()
    synthesised = False
    if not report_id:
        # Same reasoning as the aggregate parser: report_id is the idempotency
        # key, and a deterministic synthetic one still collides on redelivery.
        basis = f"{org_name}!{date_begin.isoformat()}!{date_end.isoformat()}"
        report_id = "synthesised:" + hashlib.sha256(basis.encode()).hexdigest()[:32]
        synthesised = True
        log.info("tls_report_id_synthesised", org=org_name)

    policies = document.get("policies")
    if not isinstance(policies, list):
        raise TlsReportParseError("policies is missing or not an array")
    if len(policies) > MAX_POLICIES:
        raise TlsReportParseError(
            f"report holds {len(policies)} policies, over the {MAX_POLICIES} limit"
        )

    results: list[TlsResult] = []
    for entry in policies:
        if not isinstance(entry, dict):
            continue
        results.extend(_policy_results(entry))

    return TlsReportDocument(
        org_name=org_name,
        report_id=report_id,
        date_begin=date_begin,
        date_end=date_end,
        results=results,
        synthesised_id=synthesised,
    )


def _policy_results(entry: dict) -> list[TlsResult]:
    policy = entry.get("policy")
    policy = policy if isinstance(policy, dict) else {}

    domain = str(policy.get("policy-domain") or "").strip().lower()
    if not domain:
        return []

    # policy-type is "sts", "tlsa" or "no-policy-found"; the dashboard shows the
    # MTA-STS mode, which is carried in policy-string when present.
    mode = _policy_mode(policy)

    summary = entry.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    successes = _count(summary.get("total-successful-session-count"))
    declared_failures = _count(summary.get("total-failure-session-count"))

    details = entry.get("failure-details")
    details = details if isinstance(details, list) else []
    if len(details) > MAX_RESULTS_PER_POLICY:
        details = details[:MAX_RESULTS_PER_POLICY]
        log.info("tls_report_failure_details_truncated", domain=domain)

    results: list[TlsResult] = []
    if successes:
        results.append(
            TlsResult(
                policy_domain=domain,
                policy_mode=mode,
                result_type="successful-session",
                success_count=successes,
                failure_count=0,
            )
        )

    explained = 0
    for detail in details:
        if not isinstance(detail, dict):
            continue
        result_type = str(detail.get("result-type") or "").strip().lower()
        if not result_type:
            continue
        failures = _count(detail.get("failed-session-count"))
        explained += failures
        results.append(
            TlsResult(
                policy_domain=domain,
                policy_mode=mode,
                result_type=result_type,
                success_count=0,
                failure_count=failures,
            )
        )

    # The summary is authoritative for the total. If the breakdown accounts for
    # fewer failures than the summary claims, the difference is real and dropping
    # it would understate the failure rate on the TLS tab.
    remainder = declared_failures - explained
    if remainder > 0:
        results.append(
            TlsResult(
                policy_domain=domain,
                policy_mode=mode,
                result_type=UNSPECIFIED_RESULT,
                success_count=0,
                failure_count=remainder,
            )
        )

    return results


def _policy_mode(policy: dict) -> str:
    """Extract the MTA-STS mode, defaulting to "none" when it is not stated."""
    strings = policy.get("policy-string")
    if isinstance(strings, list):
        for line in strings:
            if isinstance(line, str) and line.strip().lower().startswith("mode:"):
                mode = line.split(":", 1)[1].strip().lower()
                if mode in VALID_POLICY_MODES:
                    return mode
    mode = str(policy.get("policy-mode") or "").strip().lower()
    return mode if mode in VALID_POLICY_MODES else "none"
