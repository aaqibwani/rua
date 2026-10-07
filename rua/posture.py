"""Deriving email-authentication posture from public DNS.

This is the half of the product that works with no reports at all. Within
seconds of setup every verified domain has five posture values and a ``rua=``
verdict, and that is what makes the tool useful before the first report lands.

The five vocabularies are PINNED by the spec — every value has a word rendered
beside it in the UI — so the derivation here is written to land on exactly those
values and nothing else:

    dmarc   reject | quarantine | none | missing
    spf     pass | softfail | missing
    dkim    pass | partial | missing
    mtasts  enforce | testing | missing
    tlsrpt  present | missing

plus ``na`` for a domain that cannot carry DNS at all (the tenant's
``.onmicrosoft.com`` name, whose zone Microsoft controls).

Everything talks to DNS and HTTPS through :class:`Resolver`, so the tests drive
the whole derivation from fixture records and the network is never touched.

Two return conventions matter throughout:

* A resolver returning ``[]`` means "looked, definitely no such record".
* A resolver returning ``None`` means "could not look" — timeout, SERVFAIL, no
  nameservers. The caller keeps the domain's previous posture rather than
  flipping it to ``missing`` on a transient failure, because a false "gap" is
  both an alert (M9) and a lie in the table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from rua.logging import get_logger

log = get_logger(__name__)

# Microsoft 365 publishes exactly these two selectors, as CNAMEs into the tenant's
# onmicrosoft.com zone, and rotates between them. The design's "1 of 2 selectors"
# is this pair. Other providers' selectors are unguessable without enumerating
# the zone, which DNS does not allow, so they are not attempted.
DKIM_SELECTORS: tuple[str, ...] = ("selector1", "selector2")

# RFC 8461 §3.3: the policy lives on a dedicated host, and redirects are not
# followed.
MTA_STS_POLICY_HOST = "mta-sts.{domain}"
MTA_STS_POLICY_PATH = "/.well-known/mta-sts.txt"
MTA_STS_MAX_POLICY_BYTES = 64 * 1024

_DMARC_TAG = re.compile(r"\s*([a-zA-Z]+)\s*=\s*([^;]*)")
_MAILTO = re.compile(r"^mailto:([^!]+)", re.IGNORECASE)


class Resolver(Protocol):
    """What the posture checker needs from the network."""

    def txt(self, name: str) -> list[str] | None:
        """TXT records at ``name``, each with its character-strings joined.

        ``[]`` when the name has no TXT records (NXDOMAIN or NoAnswer); ``None``
        when the lookup itself failed and nothing can be concluded.
        """
        ...

    def https_text(self, url: str, max_bytes: int) -> str | None:
        """Body of a GET, or ``None`` on any failure. Redirects are not followed."""
        ...


@dataclass(frozen=True, slots=True)
class Posture:
    dmarc: str
    spf: str
    dkim: str
    mtasts: str
    tlsrpt: str
    # Tri-state, see Domain.rua_matches. None when there is no DMARC record.
    rua_matches: bool | None
    # The rua= fragment as found, or the absence sentence the design renders.
    rua_value: str | None
    # Signals whose lookup failed outright; the caller keeps old values for these.
    unresolved: frozenset[str] = frozenset()

    @property
    def complete(self) -> bool:
        return not self.unresolved


NOT_APPLICABLE = Posture(
    dmarc="na", spf="na", dkim="na", mtasts="na", tlsrpt="na", rua_matches=None, rua_value=None
)


def is_tenant_default(domain: str) -> bool:
    """The ``<tenant>.onmicrosoft.com`` name. Its DNS is Microsoft's, not yours."""
    return domain.lower().endswith(".onmicrosoft.com")


# ─── DMARC ───────────────────────────────────────────────────────────────────


def parse_dmarc(record: str) -> dict[str, str]:
    """``v=DMARC1; p=reject; rua=mailto:a@x``  ->  {"v": "DMARC1", "p": "reject", ...}

    Tag names are case-insensitive per RFC 7489 §6.3; values are kept as written
    because ``rua`` addresses are compared elsewhere.
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        match = _DMARC_TAG.match(part)
        if match:
            tags[match.group(1).lower()] = match.group(2).strip()
    return tags


def dmarc_posture(records: list[str]) -> tuple[str, dict[str, str] | None]:
    """The policy, and the parsed record for the rua= check.

    RFC 7489 §6.6.3: more than one DMARC record means DMARC processing is
    abandoned — receivers treat the domain as having none. So does this.
    """
    dmarc = [r for r in records if r.strip().lower().startswith("v=dmarc1")]
    if len(dmarc) != 1:
        if len(dmarc) > 1:
            log.info("dmarc_multiple_records_treated_as_missing", count=len(dmarc))
        return "missing", None

    tags = parse_dmarc(dmarc[0])
    policy = tags.get("p", "").lower()
    if policy in ("reject", "quarantine", "none"):
        return policy, tags
    # A record with no valid p= is not a DMARC record a receiver will act on.
    return "missing", tags


def rua_addresses(tags: dict[str, str]) -> list[str]:
    """Every mailbox in ``rua=``, lower-cased, with size suffixes stripped.

    ``rua=mailto:a@x.com!10m,mailto:b@y.com`` -> ["a@x.com", "b@y.com"].
    Multi-address values are the norm when a domain reports to a vendor as well
    as to itself, so this is not an edge case — it is why the diagnostic exists.
    """
    raw = tags.get("rua", "")
    addresses: list[str] = []
    for uri in raw.split(","):
        match = _MAILTO.match(uri.strip())
        if match:
            addresses.append(match.group(1).strip().lower())
    return addresses


def rua_verdict(tags: dict[str, str] | None, mailbox: str) -> tuple[bool | None, str | None]:
    """Does the record's ``rua=`` include the configured report mailbox?

    Returns ``(matches, display)``. ``matches`` is None when there is no DMARC
    record at all — a different problem from a misdirected tag, and one that
    must not be shown as a mismatch (see Domain.rua_matches).
    """
    if tags is None:
        return None, None
    addresses = rua_addresses(tags)
    if not addresses:
        # The design's second sub-shape for the mismatch panel.
        return False, "no rua= tag in the record"
    display = "rua=" + tags.get("rua", "")
    return mailbox.strip().lower() in addresses, display


# ─── SPF ─────────────────────────────────────────────────────────────────────


def spf_posture(records: list[str]) -> str:
    """Judged on the ``all`` mechanism, which is the only part DMARC cares about.

    ``-all`` is the strict form the design calls ``pass``; ``~all`` is
    ``softfail`` ("Ends in ~all — tighten to -all"). ``?all`` and ``+all``
    provide no protection, but the vocabulary has no worse word than softfail
    for a record that exists, so they land there and the actual qualifier is
    logged. RFC 7208 §3.2: two SPF records is a permerror, i.e. no SPF.
    """
    spf = [r for r in records if r.strip().lower().startswith("v=spf1")]
    if len(spf) != 1:
        if len(spf) > 1:
            log.info("spf_multiple_records_treated_as_missing", count=len(spf))
        return "missing"

    terms = spf[0].split()
    # A redirect= modifier with no all is a valid strict-ish record; treat the
    # redirect target's policy as unknown and call it softfail rather than pass.
    all_terms = [t for t in terms if t.lower().lstrip("+-~?") == "all"]
    if not all_terms:
        return "softfail"
    qualifier = all_terms[-1][0] if all_terms[-1][0] in "+-~?" else "+"
    if qualifier == "-":
        return "pass"
    if qualifier != "~":
        log.info("spf_weak_all_qualifier", qualifier=qualifier)
    return "softfail"


# ─── DKIM ────────────────────────────────────────────────────────────────────


def dkim_selector_present(records: list[str]) -> bool:
    """A usable key: a DKIM record with a non-empty ``p=``.

    An empty ``p=`` is the RFC 6376 §3.6.1 way to revoke a key, so it counts as
    absent — the selector exists but signs nothing.
    """
    for record in records:
        tags = parse_dmarc(record)  # same tag=value; tag=value grammar
        if tags.get("p"):
            return True
    return False


def dkim_posture(present: int, total: int) -> str:
    if present == 0:
        return "missing"
    if present < total:
        return "partial"
    return "pass"


# ─── MTA-STS ─────────────────────────────────────────────────────────────────


def parse_mta_sts_policy(body: str) -> dict[str, str]:
    """``key: value`` lines per RFC 8461 §3.2. Unknown keys are kept and ignored."""
    policy: dict[str, str] = {}
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        policy[key.strip().lower()] = value.strip()
    return policy


def mtasts_posture(txt_records: list[str], policy_body: str | None) -> str:
    """Needs both the ``_mta-sts`` TXT and a fetchable policy with a mode.

    ``mode: none`` publishes a policy that enforces nothing; the vocabulary has
    no word for that other than ``missing``, and for the purpose of "is TLS
    enforced to this domain" that is the honest answer.
    """
    sts = [r for r in txt_records if r.strip().lower().startswith("v=stsv1")]
    if not sts:
        return "missing"
    if policy_body is None:
        log.info("mta_sts_txt_present_but_policy_unfetchable")
        return "missing"
    policy = parse_mta_sts_policy(policy_body)
    if policy.get("version", "").upper() != "STSV1":
        return "missing"
    mode = policy.get("mode", "").lower()
    if mode in ("enforce", "testing"):
        return mode
    return "missing"


# ─── TLS-RPT ─────────────────────────────────────────────────────────────────


def tlsrpt_posture(records: list[str]) -> str:
    return (
        "present" if any(r.strip().lower().startswith("v=tlsrptv1") for r in records) else "missing"
    )


# ─── Putting it together ─────────────────────────────────────────────────────


def check_domain(domain: str, mailbox: str, resolver: Resolver) -> Posture:
    """Derive the full posture of one domain.

    Each signal's lookups are independent, so one unresolvable name does not
    prevent the others being assessed. Signals whose lookup failed are listed in
    ``unresolved`` and their returned value is a placeholder the caller must not
    persist.
    """
    domain = domain.strip().lower().rstrip(".")
    if is_tenant_default(domain):
        return NOT_APPLICABLE

    unresolved: set[str] = set()

    dmarc_records = resolver.txt(f"_dmarc.{domain}")
    if dmarc_records is None:
        unresolved.add("dmarc")
        dmarc, tags = "missing", None
    else:
        dmarc, tags = dmarc_posture(dmarc_records)
    rua_matches, rua_value = rua_verdict(tags, mailbox)

    spf_records = resolver.txt(domain)
    if spf_records is None:
        unresolved.add("spf")
        spf = "missing"
    else:
        spf = spf_posture(spf_records)

    present = 0
    dkim_unresolved = False
    for selector in DKIM_SELECTORS:
        records = resolver.txt(f"{selector}._domainkey.{domain}")
        if records is None:
            dkim_unresolved = True
        elif dkim_selector_present(records):
            present += 1
    if dkim_unresolved and present < len(DKIM_SELECTORS):
        # Cannot tell partial from missing if a selector lookup failed.
        unresolved.add("dkim")
    dkim = dkim_posture(present, len(DKIM_SELECTORS))

    sts_records = resolver.txt(f"_mta-sts.{domain}")
    if sts_records is None:
        unresolved.add("mtasts")
        mtasts = "missing"
    else:
        body = None
        if any(r.strip().lower().startswith("v=stsv1") for r in sts_records):
            url = f"https://{MTA_STS_POLICY_HOST.format(domain=domain)}{MTA_STS_POLICY_PATH}"
            body = resolver.https_text(url, MTA_STS_MAX_POLICY_BYTES)
        mtasts = mtasts_posture(sts_records, body)

    tls_records = resolver.txt(f"_smtp._tls.{domain}")
    if tls_records is None:
        unresolved.add("tlsrpt")
        tlsrpt = "missing"
    else:
        tlsrpt = tlsrpt_posture(tls_records)

    return Posture(
        dmarc=dmarc,
        spf=spf,
        dkim=dkim,
        mtasts=mtasts,
        tlsrpt=tlsrpt,
        rua_matches=rua_matches,
        rua_value=rua_value,
        unresolved=frozenset(unresolved),
    )


# ─── The real resolver ───────────────────────────────────────────────────────


class DnsResolver:
    """dnspython + httpx. The only place in the checker that touches the network.

    Every lookup here is one the operator configured by completing setup: the
    domains come from their tenant, and checking their own DNS is the product.
    """

    def __init__(self, timeout: float = 5.0) -> None:
        import dns.resolver

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout * 2
        self._http_timeout = timeout * 2

    def txt(self, name: str) -> list[str] | None:
        import dns.exception
        import dns.resolver

        try:
            answer = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.resolver.NoNameservers:
            # NoNameservers is also what SERVFAIL looks like; it can be a
            # transient upstream fault or a genuinely broken zone. Neither is
            # "no record", so nothing is concluded.
            log.warning("dns_no_nameservers", name=name)
            return None
        except (dns.exception.Timeout, dns.exception.DNSException) as exc:
            log.warning("dns_lookup_failed", name=name, error_type=type(exc).__name__)
            return None

        records: list[str] = []
        for rdata in answer:
            # A TXT RR is a sequence of <=255-byte character-strings that the
            # publisher split arbitrarily; the record is their concatenation.
            records.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
        return records

    def https_text(self, url: str, max_bytes: int) -> str | None:
        import httpx

        try:
            with (
                httpx.Client(timeout=self._http_timeout, follow_redirects=False) as client,
                client.stream("GET", url) as response,
            ):
                if response.status_code != 200:
                    return None
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        log.warning("mta_sts_policy_too_large", url=url)
                        return None
                return bytes(body).decode("utf-8", errors="replace")
        except httpx.HTTPError as exc:
            log.info("mta_sts_policy_fetch_failed", url=url, error_type=type(exc).__name__)
            return None
