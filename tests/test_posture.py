"""Posture derivation from fixture DNS records.

Milestone 5's definition of done:

* against a fixture resolver, each posture enum is produced from a realistic
  record;
* a domain whose ``rua=`` points elsewhere sets ``rua_matches`` false;
* a domain with multiple ``rua=`` addresses including the configured one sets it
  true.

The resolver is a dict. No test here touches the network.
"""

from __future__ import annotations

import pytest

from rua.posture import (
    DKIM_SELECTORS,
    NOT_APPLICABLE,
    check_domain,
    dmarc_posture,
    rua_addresses,
    spf_posture,
    tlsrpt_posture,
)

MAILBOX = "dmarc-reports@example.com"

STS_POLICY = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"


class FakeResolver:
    """``txt`` returns [] for unknown names; ``None`` only when told to fail."""

    def __init__(
        self,
        txt: dict[str, list[str]] | None = None,
        https: dict[str, str] | None = None,
        fail: set[str] | None = None,
    ):
        self._txt = txt or {}
        self._https = https or {}
        self._fail = fail or set()
        self.lookups: list[str] = []

    def txt(self, name: str):
        self.lookups.append(name)
        if name in self._fail:
            return None
        return self._txt.get(name, [])

    def https_text(self, url: str, max_bytes: int):
        return self._https.get(url)


def fully_protected(domain: str = "example.com") -> FakeResolver:
    return FakeResolver(
        txt={
            f"_dmarc.{domain}": [f"v=DMARC1; p=reject; rua=mailto:{MAILBOX}"],
            domain: ["v=spf1 include:spf.protection.outlook.com -all"],
            f"selector1._domainkey.{domain}": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
            f"selector2._domainkey.{domain}": ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
            f"_mta-sts.{domain}": ["v=STSv1; id=20260101"],
            f"_smtp._tls.{domain}": [f"v=TLSRPTv1; rua=mailto:{MAILBOX}"],
        },
        https={f"https://mta-sts.{domain}/.well-known/mta-sts.txt": STS_POLICY},
    )


# ── acceptance: every enum from a realistic record ──


def test_fully_protected_domain() -> None:
    p = check_domain("example.com", MAILBOX, fully_protected())
    assert (p.dmarc, p.spf, p.dkim, p.mtasts, p.tlsrpt) == (
        "reject",
        "pass",
        "pass",
        "enforce",
        "present",
    )
    assert p.rua_matches is True
    assert p.complete


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=DMARC1; p=reject; rua=mailto:x@y", "reject"),
        ("v=DMARC1; p=quarantine; pct=100", "quarantine"),
        ("v=DMARC1; p=none; rua=mailto:x@y", "none"),
        ("V=DMARC1; P=Reject", "reject"),  # tags are case-insensitive
        ("v=DMARC1; sp=reject", "missing"),  # no p= at all
        ("v=spf1 -all", "missing"),  # not a DMARC record
    ],
)
def test_dmarc_enum(record: str, expected: str) -> None:
    assert dmarc_posture([record])[0] == expected


def test_two_dmarc_records_is_missing() -> None:
    """RFC 7489 §6.6.3: receivers abandon DMARC when more than one record exists."""
    posture, _ = dmarc_posture(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert posture == "missing"


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 include:spf.protection.outlook.com -all", "pass"),
        ("v=spf1 ip4:203.0.113.0/24 ~all", "softfail"),
        ("v=spf1 a mx ?all", "softfail"),  # no word worse than softfail exists
        ("v=spf1 +all", "softfail"),
        ("v=spf1 redirect=_spf.example.net", "softfail"),  # no all mechanism
        ("v=spf1 -ALL", "pass"),
    ],
)
def test_spf_enum(record: str, expected: str) -> None:
    assert spf_posture([record]) == expected


def test_spf_two_records_is_missing() -> None:
    assert spf_posture(["v=spf1 -all", "v=spf1 ~all"]) == "missing"


def test_dkim_partial_is_one_of_two_selectors() -> None:
    r = fully_protected()
    r._txt.pop(f"{DKIM_SELECTORS[1]}._domainkey.example.com")
    assert check_domain("example.com", MAILBOX, r).dkim == "partial"


def test_dkim_revoked_key_counts_as_absent() -> None:
    """An empty p= is how RFC 6376 revokes a key; the selector signs nothing."""
    r = fully_protected()
    r._txt[f"{DKIM_SELECTORS[1]}._domainkey.example.com"] = ["v=DKIM1; p="]
    assert check_domain("example.com", MAILBOX, r).dkim == "partial"


def test_dkim_missing() -> None:
    r = fully_protected()
    for s in DKIM_SELECTORS:
        r._txt.pop(f"{s}._domainkey.example.com")
    assert check_domain("example.com", MAILBOX, r).dkim == "missing"


def test_mtasts_testing() -> None:
    r = fully_protected()
    r._https["https://mta-sts.example.com/.well-known/mta-sts.txt"] = STS_POLICY.replace(
        "enforce", "testing"
    )
    assert check_domain("example.com", MAILBOX, r).mtasts == "testing"


def test_mtasts_txt_without_policy_is_missing() -> None:
    """The TXT says a policy exists; if it cannot be fetched, nothing is enforced."""
    r = fully_protected()
    r._https.clear()
    assert check_domain("example.com", MAILBOX, r).mtasts == "missing"


def test_mtasts_mode_none_is_missing() -> None:
    r = fully_protected()
    r._https["https://mta-sts.example.com/.well-known/mta-sts.txt"] = STS_POLICY.replace(
        "enforce", "none"
    )
    assert check_domain("example.com", MAILBOX, r).mtasts == "missing"


def test_mtasts_policy_not_fetched_when_no_txt() -> None:
    r = fully_protected()
    r._txt.pop("_mta-sts.example.com")
    calls: list[str] = []
    r.https_text = lambda url, max_bytes: calls.append(url)  # type: ignore[method-assign]
    assert check_domain("example.com", MAILBOX, r).mtasts == "missing"
    assert calls == [], "no TXT record means no HTTPS fetch is attempted"


def test_tlsrpt_enum() -> None:
    assert tlsrpt_posture(["v=TLSRPTv1; rua=mailto:a@b"]) == "present"
    assert tlsrpt_posture(["v=spf1 -all"]) == "missing"
    assert tlsrpt_posture([]) == "missing"


def test_entirely_unconfigured_domain() -> None:
    p = check_domain("parked.example", MAILBOX, FakeResolver())
    assert (p.dmarc, p.spf, p.dkim, p.mtasts, p.tlsrpt) == (
        "missing",
        "missing",
        "missing",
        "missing",
        "missing",
    )
    assert p.rua_matches is None, "no DMARC record means no rua= to judge"
    assert p.complete


def test_onmicrosoft_domain_is_not_applicable() -> None:
    r = FakeResolver()
    assert check_domain("contoso.onmicrosoft.com", MAILBOX, r) == NOT_APPLICABLE
    assert r.lookups == [], "Microsoft's zone is not ours to check"


# ── acceptance: rua= verdicts ──


def test_rua_pointing_elsewhere_is_false() -> None:
    r = fully_protected()
    r._txt["_dmarc.example.com"] = ["v=DMARC1; p=reject; rua=mailto:dmarc@tailspin-mktg.example"]
    p = check_domain("example.com", MAILBOX, r)
    assert p.rua_matches is False
    assert p.rua_value == "rua=mailto:dmarc@tailspin-mktg.example"


def test_rua_with_multiple_addresses_including_ours_is_true() -> None:
    """The highest-value diagnostic in the product, so multi-address must work."""
    r = fully_protected()
    r._txt["_dmarc.example.com"] = [
        f"v=DMARC1; p=reject; rua=mailto:reports@dmarcian.example!10m, mailto:{MAILBOX}"
    ]
    assert check_domain("example.com", MAILBOX, r).rua_matches is True


def test_rua_match_is_case_insensitive() -> None:
    r = fully_protected()
    r._txt["_dmarc.example.com"] = [f"v=DMARC1; p=reject; rua=mailto:{MAILBOX.upper()}"]
    assert check_domain("example.com", "DMARC-Reports@Example.com", r).rua_matches is True


def test_dmarc_without_rua_tag() -> None:
    r = fully_protected()
    r._txt["_dmarc.example.com"] = ["v=DMARC1; p=quarantine"]
    p = check_domain("example.com", MAILBOX, r)
    assert p.rua_matches is False
    assert p.rua_value == "no rua= tag in the record"  # the design's second sub-shape


def test_rua_addresses_strip_size_suffix_and_non_mailto() -> None:
    assert rua_addresses(
        {"rua": "mailto:A@x.com!10m, https://ignored.example, mailto:b@y.com"}
    ) == [
        "a@x.com",
        "b@y.com",
    ]


# ── transient failures keep old values ──


def test_failed_lookup_is_reported_as_unresolved_not_missing() -> None:
    r = fully_protected()
    r._fail.add("_dmarc.example.com")
    p = check_domain("example.com", MAILBOX, r)
    assert "dmarc" in p.unresolved
    assert not p.complete
    assert p.spf == "pass", "one failed lookup does not block the others"


def test_failed_selector_lookup_cannot_claim_partial() -> None:
    r = fully_protected()
    r._fail.add(f"{DKIM_SELECTORS[1]}._domainkey.example.com")
    assert "dkim" in check_domain("example.com", MAILBOX, r).unresolved


def test_domain_names_are_normalised() -> None:
    r = fully_protected()
    p = check_domain("  EXAMPLE.com. ", MAILBOX, r)
    assert p.dmarc == "reject"
