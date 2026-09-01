"""Getting report documents out of mail attachments, safely.

Aggregate reports arrive gzipped or zipped. Anyone can send mail that causes a
third party to generate a report about your domain, so an attachment is
attacker-influenced input and everything here is written on that assumption:

* every read is bounded, so a decompression bomb exhausts a limit rather than
  the container's memory;
* the compression ratio is capped, because a 1 KB file that expands to 10 GB is
  the whole trick;
* archives are not recursed into, so a zip inside a zip is reported rather than
  followed;
* nothing is written to disk, so nothing can escape a directory via a crafted
  member name — the classic zip-slip does not apply because members are never
  extracted to a path.

Limits are deliberately generous compared to real reports (the largest ones from
big receivers run to a few megabytes uncompressed) and deliberately far below
anything that would trouble a container.
"""

from __future__ import annotations

import gzip
import io
import zipfile
import zlib
from dataclasses import dataclass
from typing import Literal

from rua.logging import get_logger

log = get_logger(__name__)

# A compressed attachment larger than this is refused unread.
MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024

# Ceiling on what any single attachment may expand to, across all its members.
MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024

# Expansion beyond this is treated as hostile regardless of absolute size. Real
# report XML compresses at roughly 10:1 to 30:1; 500:1 is not a real report.
MAX_COMPRESSION_RATIO = 500

# A report archive holds one document. A handful is tolerable; hundreds is not.
MAX_ARCHIVE_MEMBERS = 16

_READ_CHUNK = 64 * 1024

DocumentKind = Literal["xml", "json", "unknown"]


class ExtractionError(Exception):
    """An attachment could not be turned into documents, safely or at all.

    Always attributable to one attachment. The caller records it against that
    report and carries on with the rest of the batch.
    """


@dataclass(frozen=True, slots=True)
class ExtractedDocument:
    filename: str
    content: bytes
    kind: DocumentKind


def _classify(filename: str, content: bytes) -> DocumentKind:
    """Decide what a document is, preferring content over the file name."""
    head = content.lstrip()[:1]
    if head == b"<":
        return "xml"
    if head in (b"{", b"["):
        return "json"
    lowered = filename.lower()
    if lowered.endswith(".xml"):
        return "xml"
    if lowered.endswith(".json"):
        return "json"
    return "unknown"


def _bounded_read(stream: io.BufferedIOBase, limit: int, what: str) -> bytes:
    """Read at most ``limit`` bytes, raising if the stream has more to give.

    Reading ``limit + 1`` is what makes this a guard rather than a truncation:
    stopping at exactly ``limit`` would silently hand back a half-parsed document.
    """
    buffer = bytearray()
    while True:
        chunk = stream.read(_READ_CHUNK)
        if not chunk:
            return bytes(buffer)
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise ExtractionError(
                f"{what} expands beyond the {limit} byte limit; refusing to continue."
            )


def _check_ratio(compressed: int, decompressed: int, what: str) -> None:
    if compressed > 0 and decompressed / compressed > MAX_COMPRESSION_RATIO:
        raise ExtractionError(
            f"{what} expands {decompressed // max(compressed, 1)}:1, beyond the "
            f"{MAX_COMPRESSION_RATIO}:1 limit; treating it as a decompression bomb."
        )


def extract_documents(filename: str, data: bytes) -> list[ExtractedDocument]:
    """Turn one mail attachment into the report documents it carries.

    Handles gzip, zip, and bare XML or JSON. Raises :class:`ExtractionError` for
    anything oversized, hostile or unrecognisable.
    """
    if not data:
        raise ExtractionError("Attachment is empty.")
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise ExtractionError(
            f"Attachment is {len(data)} bytes, over the {MAX_ATTACHMENT_BYTES} byte limit."
        )

    lowered = filename.lower()

    if data[:2] == b"\x1f\x8b" or lowered.endswith(".gz"):
        return [_from_gzip(filename, data)]
    if data[:2] == b"PK" or lowered.endswith(".zip"):
        return _from_zip(filename, data)

    kind = _classify(filename, data)
    if kind == "unknown":
        raise ExtractionError(f"{filename!r} is neither gzip, zip, XML nor JSON; nothing to parse.")
    return [ExtractedDocument(filename=filename, content=data, kind=kind)]


def _from_gzip(filename: str, data: bytes) -> ExtractedDocument:
    inner_name = filename[:-3] if filename.lower().endswith(".gz") else filename
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            content = _bounded_read(stream, MAX_DECOMPRESSED_BYTES, f"{filename!r}")
    except ExtractionError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise ExtractionError(f"{filename!r} is not readable gzip: {type(exc).__name__}.") from None

    _check_ratio(len(data), len(content), f"{filename!r}")
    kind = _classify(inner_name, content)
    if kind == "unknown":
        raise ExtractionError(f"{filename!r} decompressed to something that is not XML or JSON.")
    return ExtractedDocument(filename=inner_name, content=content, kind=kind)


def _from_zip(filename: str, data: bytes) -> list[ExtractedDocument]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ExtractionError(f"{filename!r} is not a readable zip: {exc}.") from None

    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if not members:
            raise ExtractionError(f"{filename!r} contains no files.")
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ExtractionError(
                f"{filename!r} contains {len(members)} members, over the "
                f"{MAX_ARCHIVE_MEMBERS} limit."
            )

        # Trust the header only as an early reject; it is attacker-controlled, so
        # the real enforcement is the bounded read below.
        declared = sum(m.file_size for m in members)
        if declared > MAX_DECOMPRESSED_BYTES:
            raise ExtractionError(
                f"{filename!r} declares {declared} bytes of content, over the "
                f"{MAX_DECOMPRESSED_BYTES} byte limit."
            )

        documents: list[ExtractedDocument] = []
        budget = MAX_DECOMPRESSED_BYTES
        for member in members:
            # Members are read into memory and never written out, so a crafted
            # name like ../../etc/passwd has nowhere to go. Keep the basename
            # anyway so it cannot mislead a log line.
            name = member.filename.rsplit("/", 1)[-1] or "member"
            with archive.open(member) as stream:
                content = _bounded_read(stream, budget, f"{filename!r}::{name}")
            budget -= len(content)
            _check_ratio(member.compress_size, len(content), f"{filename!r}::{name}")

            kind = _classify(name, content)
            if kind == "unknown":
                log.info("report_archive_member_skipped", archive=filename, member=name)
                continue
            documents.append(ExtractedDocument(filename=name, content=content, kind=kind))

    if not documents:
        raise ExtractionError(f"{filename!r} contains no XML or JSON members.")
    return documents
