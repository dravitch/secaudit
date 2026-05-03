"""
tests/test_scanner_tls.py
Mocke subprocess.run (testssl.sh) avec des sorties texte représentatives.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from schemas.finding import Finding
from tools import _tls

TARGET = "127.0.0.1"

# Strict modern config: TLS 1.3 only, FS, valid cert, HSTS preload.
TESTSSL_OK = """
 SSLv2                      not offered (OK)
 SSLv3                      not offered (OK)
 TLS 1                      not offered (OK)
 TLS 1.1                    not offered (OK)
 TLS 1.2                    not offered
 TLS 1.3                    offered (OK): final
 Forward Secrecy            offered (OK)
 PFS (RFC 7919)             ok
 Certificate Validity (UTC) 84 >= 60 days (2026-12-15 12:34 --> 2027-03-15 12:34)
 HSTS                       offered, 31536000 s = 1 year, includeSubDomains, preload
"""

# Multiple deprecated protocols + FS missing + cert expiring soon + HSTS not advertised.
TESTSSL_BAD = """
 SSLv2                      not offered (OK)
 SSLv3                      offered (NOT ok)
 TLS 1                      offered (deprecated)
 TLS 1.1                    offered (deprecated)
 TLS 1.2                    offered
 TLS 1.3                    offered (OK): final
 Forward Secrecy            no -- weak ciphers
 Certificate Validity (UTC) 5 days remaining
 HSTS                       not offered
"""

# TLS 1.2 active without TLS 1.3 (acceptable but worth a LOW Finding).
TESTSSL_TLS12_ONLY = """
 SSLv3                      not offered (OK)
 TLS 1                      not offered (OK)
 TLS 1.1                    not offered (OK)
 TLS 1.2                    offered
 TLS 1.3                    not offered
 Forward Secrecy            offered (OK)
 Certificate Validity (UTC) 200 >= 60 days
 HSTS                       offered, max-age=15552000
"""

# Cert window between 7 and 30 days remaining.
TESTSSL_CERT_25_DAYS = """
 TLS 1.3                    offered (OK): final
 Forward Secrecy            offered (OK)
 Certificate Validity (UTC) 25 days remaining
 HSTS                       offered, max-age=63072000, includeSubDomains, preload
"""

# Real-world `testssl -S` shape: cert remaining count is in parentheses.
# Strict-Transport-Security shows under the "Strict Transport Security" label.
TESTSSL_LIVE_SHAPE = """
 Trust (hostname)             Ok via CN wildcard and SAN (SNI mandatory)
 Chain of trust               NOT ok (self signed CA in chain)
 Certificate Validity (UTC)   expires < 30 days (29) (2026-05-03 08:23 --> 2026-06-02 08:23)
 Strict Transport Security    not offered
"""


def _fake_proc(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["testssl.sh"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ── Pure parser tests (no subprocess at all) ────────────────────────────


def test_strict_tls_yields_no_findings():
    findings = _tls.parse_testssl_text(TESTSSL_OK, target=TARGET)
    assert findings == [], (
        "Strict TLS 1.3 + valid cert + HSTS preload should yield 0 findings; "
        "got: " + ", ".join(f.title for f in findings)
    )


def test_sslv3_offered_yields_critical():
    findings = _tls.parse_testssl_text(TESTSSL_BAD, target=TARGET)
    sslv3 = [f for f in findings if f.title == "SSLv3 offered (POODLE)"]
    assert len(sslv3) == 1
    assert sslv3[0].severity == "CRITICAL"
    assert "SSLv3" in sslv3[0].evidence[0]


def test_tls10_and_tls11_offered_yield_high():
    findings = _tls.parse_testssl_text(TESTSSL_BAD, target=TARGET)
    titles = [f.title for f in findings]
    assert "TLSv1.0 offered" in titles
    assert "TLSv1.1 offered" in titles
    for f in findings:
        if f.title in {"TLSv1.0 offered", "TLSv1.1 offered"}:
            assert f.severity == "HIGH"


def test_tls12_only_yields_low_acceptable_finding():
    findings = _tls.parse_testssl_text(TESTSSL_TLS12_ONLY, target=TARGET)
    tls12 = [f for f in findings if f.title.startswith("TLSv1.2")]
    assert len(tls12) == 1
    assert tls12[0].severity == "LOW"


def test_forward_secrecy_absent_yields_high():
    findings = _tls.parse_testssl_text(TESTSSL_BAD, target=TARGET)
    fs = [f for f in findings if "Forward Secrecy" in f.title]
    assert len(fs) >= 1
    assert all(f.severity == "HIGH" for f in fs)


def test_cert_expiring_in_5_days_yields_high():
    findings = _tls.parse_testssl_text(TESTSSL_BAD, target=TARGET)
    cert = [f for f in findings if "<7 days" in f.title]
    assert len(cert) == 1
    assert cert[0].severity == "HIGH"
    assert "5" in cert[0].finding


def test_cert_expiring_in_25_days_yields_medium():
    findings = _tls.parse_testssl_text(TESTSSL_CERT_25_DAYS, target=TARGET)
    cert = [f for f in findings if "<30 days" in f.title]
    assert len(cert) == 1
    assert cert[0].severity == "MEDIUM"
    # Must NOT also flag <7 days.
    assert not any("<7 days" in f.title for f in findings)


def test_hsts_not_advertised_yields_high():
    findings = _tls.parse_testssl_text(TESTSSL_BAD, target=TARGET)
    hsts = [f for f in findings if "HSTS not advertised" in f.title]
    assert len(hsts) == 1
    assert hsts[0].severity == "HIGH"


def test_hsts_offered_without_preload_yields_low():
    # TESTSSL_TLS12_ONLY's HSTS line lacks 'preload'.
    findings = _tls.parse_testssl_text(TESTSSL_TLS12_ONLY, target=TARGET)
    hsts = [f for f in findings if "preload" in f.title]
    assert len(hsts) == 1
    assert hsts[0].severity == "LOW"


def test_cert_remaining_in_parentheses_form_yields_medium():
    """Regression: testssl `-S` outputs `expires < 30 days (29)` — the actual
    remaining count lives in the parens, NOT in the leading `< 30`."""
    findings = _tls.parse_testssl_text(TESTSSL_LIVE_SHAPE, target=TARGET)
    cert = [f for f in findings if "<30 days" in f.title]
    assert len(cert) == 1
    assert cert[0].severity == "MEDIUM"
    assert "29" in cert[0].finding, (
        f"expected 29 days remaining, got: {cert[0].finding}"
    )


def test_strict_transport_security_label_recognised():
    """Regression: testssl labels HSTS as 'Strict Transport Security' under -h."""
    findings = _tls.parse_testssl_text(TESTSSL_LIVE_SHAPE, target=TARGET)
    hsts = [f for f in findings if "HSTS not advertised" in f.title]
    assert len(hsts) == 1
    assert hsts[0].severity == "HIGH"


# ── End-to-end via mocked subprocess ────────────────────────────────────


def test_scan_tls_full_pipeline_mocked(monkeypatch):
    monkeypatch.setattr(_tls, "_resolve_testssl", lambda: "/usr/bin/testssl.sh")
    with patch("tools._tls.subprocess.run", return_value=_fake_proc(TESTSSL_BAD)) as mock_run:
        findings = _tls.scan_tls(TARGET)
    assert mock_run.called
    assert len(findings) >= 4  # SSLv3, TLS1.0, TLS1.1, FS, cert<7, HSTS missing
    assert all(f.tool == "scanner-tls" for f in findings)
    assert all(f.sprint == 2 for f in findings)


def test_scan_tls_out_of_scope_raises():
    with pytest.raises(ValueError, match="not in authorized scope"):
        _tls.scan_tls("evil.example.com")


def test_scan_tls_fails_when_binary_missing(monkeypatch):
    def boom():
        raise RuntimeError("testssl.sh not found on PATH")
    monkeypatch.setattr(_tls, "_resolve_testssl", boom)
    with pytest.raises(RuntimeError, match="testssl.sh not found"):
        _tls.scan_tls(TARGET)


def test_tls_findings_json_roundtrip(tmp_path: Path):
    findings = _tls.parse_testssl_text(TESTSSL_BAD, target=TARGET)
    assert findings
    out = tmp_path / "tls.json"
    out.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings], indent=2)
    )
    raw = json.loads(out.read_text())
    restored = [Finding.model_validate(item) for item in raw]
    assert {f.severity for f in restored} >= {"CRITICAL", "HIGH"}
    assert all(f.tool == "scanner-tls" for f in restored)
