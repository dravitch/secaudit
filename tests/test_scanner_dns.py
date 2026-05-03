"""
tests/test_scanner_dns.py
Mocke subprocess.run (dig). Chaque check testé en isolation.
"""
from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from tools import _dns

TARGET = "127.0.0.1"


def _fake_dig(stdout: str, returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["dig"], returncode=returncode, stdout=stdout, stderr=""
    )


def _patch_dig(monkeypatch, mapping: dict, reverse_mapping: dict | None = None):
    """Patch tools._dns._dig and _dig_reverse with canned responses."""
    monkeypatch.setattr(_dns, "_resolve_dig", lambda: "/usr/bin/dig")

    def fake_dig(rrtype: str, name: str, timeout: int = _dns.DIG_TIMEOUT_SEC):
        return mapping.get((rrtype, name), [])

    def fake_dig_reverse(ip: str, timeout: int = _dns.DIG_TIMEOUT_SEC):
        return (reverse_mapping or {}).get(ip, [])

    monkeypatch.setattr(_dns, "_dig", fake_dig)
    monkeypatch.setattr(_dns, "_dig_reverse", fake_dig_reverse)


# ── DNSSEC ────────────────────────────────────────────────────────────


def test_dnssec_absent_yields_critical(monkeypatch):
    _patch_dig(monkeypatch, {("DNSKEY", TARGET): []})
    findings = _dns.check_dnssec(TARGET)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "DNSSEC" in findings[0].title


def test_dnssec_present_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, {("DNSKEY", TARGET): ["256 3 13 abcdef..."]})
    assert _dns.check_dnssec(TARGET) == []


# ── SPF ───────────────────────────────────────────────────────────────


def test_spf_absent_yields_critical(monkeypatch):
    _patch_dig(monkeypatch, {("TXT", TARGET): ['"some other txt record"']})
    findings = _dns.check_spf(TARGET)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "SPF" in findings[0].title


def test_spf_present_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, {("TXT", TARGET): ['"v=spf1 include:_spf.example.com -all"']})
    assert _dns.check_spf(TARGET) == []


# ── DMARC ─────────────────────────────────────────────────────────────


def test_dmarc_absent_yields_critical(monkeypatch):
    _patch_dig(monkeypatch, {("TXT", f"_dmarc.{TARGET}"): []})
    findings = _dns.check_dmarc(TARGET)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "DMARC" in findings[0].title


def test_dmarc_p_none_yields_high(monkeypatch):
    _patch_dig(monkeypatch, {
        ("TXT", f"_dmarc.{TARGET}"): ['"v=DMARC1; p=none; rua=mailto:reports@example.com"']
    })
    findings = _dns.check_dmarc(TARGET)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "p=none" in findings[0].title


def test_dmarc_p_reject_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, {
        ("TXT", f"_dmarc.{TARGET}"): ['"v=DMARC1; p=reject; rua=mailto:reports@example.com"']
    })
    assert _dns.check_dmarc(TARGET) == []


def test_dmarc_p_quarantine_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, {
        ("TXT", f"_dmarc.{TARGET}"): ['"v=DMARC1; p=quarantine; sp=reject"']
    })
    assert _dns.check_dmarc(TARGET) == []


# ── DKIM ──────────────────────────────────────────────────────────────


def test_dkim_absent_yields_high(monkeypatch):
    _patch_dig(monkeypatch, {("TXT", f"default._domainkey.{TARGET}"): []})
    findings = _dns.check_dkim(TARGET)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "DKIM" in findings[0].title


def test_dkim_present_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, {
        ("TXT", f"default._domainkey.{TARGET}"): [
            '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ..."'
        ]
    })
    assert _dns.check_dkim(TARGET) == []


# ── MX ────────────────────────────────────────────────────────────────


def test_mx_absent_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, {("MX", TARGET): []})
    assert _dns.check_mx(TARGET) == []


def test_mx_present_yields_info_with_chain_dependency(monkeypatch):
    _patch_dig(monkeypatch, {
        ("MX", TARGET): ["10 mail1.example.com.", "20 mail2.example.com."]
    })
    findings = _dns.check_mx(TARGET)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "INFO"
    assert "CHAIN_DEPENDENCY" in f.flags
    assert any("mail1" in e for e in f.evidence)


# ── rDNS ──────────────────────────────────────────────────────────────


def test_rdns_mismatch_yields_info(monkeypatch):
    """A → 95.111.253.212 → PTR vmi3228287.contaboserver.net → INFO mismatch."""
    _patch_dig(
        monkeypatch,
        mapping={("A", TARGET): ["95.111.253.212"]},
        reverse_mapping={"95.111.253.212": ["vmi3228287.contaboserver.net."]},
    )
    findings = _dns.check_rdns(TARGET)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "INFO"
    assert "rDNS mismatch" in f.title
    assert "vmi3228287.contaboserver.net" in f.title
    assert any("vmi3228287" in e for e in f.evidence)


def test_rdns_aligned_yields_no_finding(monkeypatch):
    """PTR contains the original host → no mismatch finding."""
    _patch_dig(
        monkeypatch,
        mapping={("A", TARGET): ["95.111.253.212"]},
        reverse_mapping={"95.111.253.212": [f"www.{TARGET}."]},
    )
    assert _dns.check_rdns(TARGET) == []


def test_rdns_no_a_record_yields_no_finding(monkeypatch):
    _patch_dig(monkeypatch, mapping={("A", TARGET): []})
    assert _dns.check_rdns(TARGET) == []


def test_rdns_no_ptr_yields_info_missing(monkeypatch):
    """A resolved but no PTR → 'rDNS missing' INFO."""
    _patch_dig(
        monkeypatch,
        mapping={("A", TARGET): ["95.111.253.212"]},
        reverse_mapping={"95.111.253.212": []},
    )
    findings = _dns.check_rdns(TARGET)
    assert len(findings) == 1
    assert findings[0].title == "rDNS missing"


# ── Full scan_dns + scope ─────────────────────────────────────────────


def test_scan_dns_full_pipeline_no_records(monkeypatch):
    """Empty DNS for everything → 4 CRITICAL/HIGH findings, no MX finding."""
    _patch_dig(monkeypatch, {})
    findings = _dns.scan_dns(TARGET)
    titles = [f.title for f in findings]
    assert any("DNSSEC missing" in t for t in titles)
    assert any("SPF record missing" in t for t in titles)
    assert any("DMARC record missing" in t for t in titles)
    assert any("DKIM record missing" in t for t in titles)
    assert not any("MX records published" in t for t in titles)
    assert all(f.tool == "scanner-dns" for f in findings)
    assert all(f.sprint == 2 for f in findings)


def test_scan_dns_full_pipeline_strict_records(monkeypatch):
    """Fully-configured zone → only the INFO MX finding remains."""
    _patch_dig(monkeypatch, {
        ("DNSKEY", TARGET): ["256 3 13 abcd"],
        ("TXT", TARGET): ['"v=spf1 include:_spf.example.com -all"'],
        ("TXT", f"_dmarc.{TARGET}"): ['"v=DMARC1; p=reject; rua=mailto:r@x.com"'],
        ("TXT", f"default._domainkey.{TARGET}"): ['"v=DKIM1; k=rsa; p=ABC"'],
        ("MX", TARGET): ["10 mail.example.com."],
    })
    findings = _dns.scan_dns(TARGET)
    assert len(findings) == 1
    assert findings[0].title == "MX records published"
    assert findings[0].severity == "INFO"
    assert "CHAIN_DEPENDENCY" in findings[0].flags


def test_scan_dns_out_of_scope_raises(monkeypatch):
    with pytest.raises(ValueError, match="not in authorized scope"):
        _dns.scan_dns("evil.example.com")


def test_scan_dns_fails_when_dig_missing(monkeypatch):
    def boom():
        raise RuntimeError("dig not found on PATH")
    monkeypatch.setattr(_dns, "_resolve_dig", boom)
    with pytest.raises(RuntimeError, match="dig not found"):
        _dns.scan_dns(TARGET)
