"""
tests/test_tld_verifier.py
Unit tests for the multi-source TLD restriction verifier.

The verifier requires consensus (≥2/3 agreeing sources, with at least 2
sources reachable) before declaring a TLD RESTRICTED. The 3 sources are
injectable so we never touch the network in unit tests.

Two integration tests at the bottom run against the real IANA / WhoisFreaks
/ DNS endpoints — opt-in via `pytest -m integration` only.
"""
from __future__ import annotations

import pytest

from tools._tld_verifier import TLDVerifier, _consensus


def _make(iana, whoisfreaks, dns_soa) -> TLDVerifier:
    """Build a verifier with the three sources stubbed to fixed return values."""
    return TLDVerifier(
        iana=lambda tld: iana,
        whoisfreaks=lambda tld: whoisfreaks,
        dns_soa=lambda tld: dns_soa,
    )


# ── Vote-tally rules (weighted: IANA=2, others=1) ────────────────────


def test_restricted_when_iana_and_whoisfreaks_confirm():
    """iana=True (w2) + whoisfreaks=True (w1) + dns_soa=False (w1) →
    score 3 vs 1 = 0.75 → RESTRICTED."""
    v = _make(iana=True, whoisfreaks=True, dns_soa=False)
    r = v.check("gov.gn")
    assert r["verdict"] == "RESTRICTED"
    assert r["votes_restricted"] == 2
    assert r["votes_available"] == 3
    assert r["confidence"] >= 0.60


def test_free_when_all_deny():
    """All three sources say False → FREE, confidence 0.0."""
    v = _make(iana=False, whoisfreaks=False, dns_soa=False)
    r = v.check("gn")
    assert r["verdict"] == "FREE"
    assert r["votes_restricted"] == 0
    assert r["votes_available"] == 3
    assert r["confidence"] == 0.0


def test_iana_alone_against_two_negatives_yields_unknown():
    """iana=True (w2) + whoisfreaks=False (w1) + dns_soa=False (w1) →
    score 2 vs 2 = 0.5 → UNKNOWN. Even with IANA's weight, two negatives
    must produce caution rather than flip the verdict."""
    v = _make(iana=True, whoisfreaks=False, dns_soa=False)
    r = v.check("ambiguous.tld")
    assert r["verdict"] == "UNKNOWN"
    assert r["votes_restricted"] == 1
    assert r["votes_available"] == 3


def test_iana_with_one_unknown_still_restricted_when_other_neutral():
    """Live shape for gov.gn: iana=True (w2) + whoisfreaks=False (w1) +
    dns_soa=None → 2 sources reachable, score 2 vs 1 = 0.67 → RESTRICTED.
    This is the regression fix for the original WhoisFreaks-only failure."""
    v = _make(iana=True, whoisfreaks=False, dns_soa=None)
    r = v.check("gov.gn")
    assert r["verdict"] == "RESTRICTED"
    assert r["votes_restricted"] == 1
    assert r["votes_available"] == 2


def test_unknown_when_all_sources_fail():
    """All three sources return None (network errors) → UNKNOWN, no votes."""
    v = _make(iana=None, whoisfreaks=None, dns_soa=None)
    r = v.check("offline.tld")
    assert r["verdict"] == "UNKNOWN"
    assert r["votes_available"] == 0
    assert r["votes_restricted"] == 0


def test_unknown_when_two_fail_one_confirms():
    """Single source says True but the other two are None → UNKNOWN.

    Single-source consensus was the original WhoisFreaks bug — the verifier
    refuses to declare RESTRICTED on votes_available < 2 no matter what
    the lone source says, even if it's the high-weight IANA source.
    """
    v = _make(iana=True, whoisfreaks=None, dns_soa=None)
    r = v.check("flaky.tld")
    assert r["verdict"] == "UNKNOWN"
    assert r["votes_restricted"] == 1
    assert r["votes_available"] == 1


# ── Edge cases on _consensus directly ────────────────────────────────


@pytest.mark.parametrize(
    "sources,expected_verdict",
    [
        # 0 sources → UNKNOWN
        ({"iana": None, "whoisfreaks": None, "dns_soa": None}, "UNKNOWN"),
        # 1 source available — single-source guard
        ({"iana": True, "whoisfreaks": None, "dns_soa": None}, "UNKNOWN"),
        ({"iana": False, "whoisfreaks": None, "dns_soa": None}, "UNKNOWN"),
        # 2 sources, both deny → FREE
        ({"iana": False, "whoisfreaks": False, "dns_soa": None}, "FREE"),
        # IANA + 1 neutral with True vs False heuristic
        ({"iana": True, "whoisfreaks": False, "dns_soa": None}, "RESTRICTED"),  # 2 vs 1 = 0.67
        ({"iana": False, "whoisfreaks": True, "dns_soa": None}, "UNKNOWN"),     # 1 vs 2 = 0.33
        # Three sources: all True
        ({"iana": True, "whoisfreaks": True, "dns_soa": True}, "RESTRICTED"),
        # Mixed — 1 weak True against 2 strong contradicts
        ({"iana": False, "whoisfreaks": True, "dns_soa": False}, "FREE"),       # 1 vs 3 = 0.25
    ],
)
def test_consensus_thresholds(sources, expected_verdict):
    verdict, _, _, _ = _consensus(sources)
    assert verdict == expected_verdict


# ── Cache + exception safety ─────────────────────────────────────────


def test_verifier_caches_results():
    """A second check() call must not re-trigger source calls."""
    calls = {"iana": 0, "wf": 0, "dns": 0}

    def iana(tld):
        calls["iana"] += 1
        return True

    def wf(tld):
        calls["wf"] += 1
        return True

    def dns(tld):
        calls["dns"] += 1
        return False

    v = TLDVerifier(iana=iana, whoisfreaks=wf, dns_soa=dns)
    v.check("gov.gn")
    v.check("gov.gn")
    v.check("GOV.gn")  # case-insensitive cache key
    assert calls == {"iana": 1, "wf": 1, "dns": 1}


def test_verifier_swallows_source_exceptions(recwarn):
    """A buggy source must not crash the run — it should be treated as None."""
    def boom(tld):
        raise RuntimeError("network melt")

    v = TLDVerifier(iana=boom, whoisfreaks=lambda t: True, dns_soa=lambda t: True)
    r = v.check("gov.gn")
    assert r["sources"]["iana"] is None
    # 2 surviving sources both say True → RESTRICTED.
    assert r["verdict"] == "RESTRICTED"
    assert any("indeterminate" in str(w.message) for w in recwarn.list)


# ── IANA second-level governmental rule ──────────────────────────────


def test_iana_recognises_known_gov_second_level_label_without_network():
    """The IANA check returns True for gov.<cc> / gouv.<cc> via the hardcoded
    KNOWN_GOV_LABELS rule, with no HTTP call. Net failures elsewhere are
    therefore irrelevant to this branch."""
    from tools._tld_verifier import _check_iana

    # We can't hit the network in unit tests, but the 2nd-level rule is
    # purely string-based, so this is a real exercise of the function.
    assert _check_iana("gov.gn") is True
    assert _check_iana("gouv.gn") is True
    assert _check_iana("mil.us") is True
    # Non-governmental 2nd-level → indeterminate (None) for this source.
    assert _check_iana("blog.gn") is None


def test_dns_soa_returns_none_for_top_level_tld():
    """Live observation regression: the SOA mname of a ccTLD root may be
    hosted on a national NIC under a .gov subdomain — that does NOT mean
    the TLD itself is restricted. The DNS SOA source must therefore stay
    silent (None) for any single-label TLD, whatever dig returns."""
    from tools._tld_verifier import _check_dns_soa

    assert _check_dns_soa("gn") is None
    assert _check_dns_soa(".gn") is None
    assert _check_dns_soa("us") is None


# ── Integration tests (opt-in) ───────────────────────────────────────


@pytest.mark.integration
def test_gov_gn_is_restricted_by_consensus():
    """Real network: gov.gn must end up RESTRICTED via the multi-source vote."""
    v = TLDVerifier()
    r = v.check("gov.gn")
    assert r["verdict"] == "RESTRICTED", (
        f"expected RESTRICTED, got {r['verdict']} "
        f"(sources={r['sources']}, votes={r['votes_restricted']}/{r['votes_available']})"
    )


@pytest.mark.integration
def test_gn_root_tld_is_not_restricted():
    """Real network: .gn root TLD must NOT be classified RESTRICTED."""
    v = TLDVerifier()
    r = v.check("gn")
    assert r["verdict"] != "RESTRICTED", (
        f"expected FREE/UNKNOWN, got RESTRICTED "
        f"(sources={r['sources']}, votes={r['votes_restricted']}/{r['votes_available']})"
    )
