"""Report parsing: DMARC aggregate (RFC 7489) and TLS-RPT (RFC 8460).

Why this is hand-written rather than delegated to ``parsedmarc``
================================================================
``parsedmarc`` is the obvious library for this and the original plan named it.
Three things ruled it out:

1. **It makes outbound calls the operator did not configure.** Its parser takes
   ``offline: bool = False``, so by default it performs a reverse-DNS lookup for
   every source IP in every report, and it can fetch a reverse-DNS map over
   HTTP. The README promises "Nothing leaves your deployment and there is no
   telemetry". Reverse DNS is genuinely useful for the Sources screen, so Rua
   does it too — but as an explicit, configurable step, not a side effect of
   parsing.

2. **Its dependency tree is mostly output backends.** boto3/botocore,
   elasticsearch, kafka-python, opensearch-py, azure-identity and
   azure-monitor-ingestion are declared as mandatory dependencies rather than
   extras: roughly 28 MB of artefacts, before their own transitive deps, for
   destinations this project will never write to. SECURITY.md puts report
   parsing in scope for disclosure, and that surface is not worth carrying.

3. **The formats are small and fixed.** An aggregate report is
   ``feedback > report_metadata | policy_published | record*``. A TLS report is
   a JSON object with a ``policies`` array. What is genuinely hard is real-world
   deviation from the schema, and the answer to that is a fixture corpus —
   which CONTRIBUTING.md already names as the single most valuable contribution,
   and which we would need regardless of who wrote the parser.

The trade is real: parsedmarc has absorbed years of quirks that this parser has
not. That is why every parser here is written to be liberal in what it accepts,
to attribute a failure to a single report rather than a batch, and to record
what it could not read instead of discarding it silently.
"""

from rua.reports.aggregate import AggregateReport, AggregateRow, parse_aggregate_report
from rua.reports.extract import (
    ExtractedDocument,
    ExtractionError,
    extract_documents,
)
from rua.reports.tlsrpt import TlsReportDocument, TlsResult, parse_tls_report

__all__ = [
    "AggregateReport",
    "AggregateRow",
    "ExtractedDocument",
    "ExtractionError",
    "TlsReportDocument",
    "TlsResult",
    "extract_documents",
    "parse_aggregate_report",
    "parse_tls_report",
]
