"""
tests/test_scanner.py
Mocke httpx via respx + subprocess.run pour la fallback curl.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from schemas.finding import Finding
from tools import scanner

URL = "https://127.0.0.1"

# A response that satisfies ALL "required" headers and contains NO forbidden ones.
STRICT_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "NEL": '{"report_to":"default"}',
    "Reporting-Endpoints": 'default="https://example.com/r"',
    "Report-To": '{"group":"default"}',
    "Cache-Control": "no-store",
    "Content-Type": "text/html; charset=utf-8",
}


def test_csp_missing_yields_high_finding():
    headers = dict(STRICT_HEADERS)
    headers.pop("Content-Security-Policy")
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    csp = [f for f in findings if "Content-Security-Policy" in f.title]
    assert len(csp) == 1
    assert csp[0].severity == "HIGH"
    assert csp[0].sprint == 1
    assert csp[0].tool == "scanner"
    assert "header absent" in csp[0].evidence[0]
    assert "method=httpx" in csp[0].evidence[0]


def test_xframe_missing_yields_medium_finding():
    headers = dict(STRICT_HEADERS)
    headers.pop("X-Frame-Options")
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    xfo = [f for f in findings if f.title == "X-Frame-Options missing"]
    assert len(xfo) == 1
    assert xfo[0].severity == "MEDIUM"


def test_strict_response_produces_no_findings():
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(STRICT_HEADERS.items()),
        target=URL, method="httpx",
    )
    # All required headers present, no forbidden ones, no bad values → 0 findings.
    assert findings == [], (
        "Strict response should yield 0 findings; got: "
        + ", ".join(f.title for f in findings)
    )


def test_server_header_present_is_low():
    headers = dict(STRICT_HEADERS)
    headers["Server"] = "nginx/1.25.3"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    server = [f for f in findings if f.title == "Server header exposes software"]
    assert len(server) == 1
    assert server[0].severity == "LOW"
    assert "nginx/1.25.3" in server[0].evidence[0]


def test_acao_wildcard_flagged_medium():
    headers = dict(STRICT_HEADERS)
    headers["Access-Control-Allow-Origin"] = "*"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    acao = [f for f in findings if f.title == "ACAO wildcard"]
    assert len(acao) == 1
    assert acao[0].severity == "MEDIUM"


def test_set_cookie_missing_attrs_yields_three_findings():
    headers = dict(STRICT_HEADERS)
    headers["Set-Cookie"] = "sessionid=abc; Path=/"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    titles = {f.title for f in findings}
    assert "Set-Cookie missing Secure" in titles
    assert "Set-Cookie missing HttpOnly" in titles
    assert "Set-Cookie missing SameSite" in titles


def test_set_cookie_absent_does_not_yield_attribute_findings():
    # Set-Cookie absent → must_match with requires_present=True must NOT trigger.
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(STRICT_HEADERS.items()),
        target=URL, method="httpx",
    )
    assert not any("Set-Cookie" in f.title for f in findings)


def test_hsts_max_age_too_short():
    headers = dict(STRICT_HEADERS)
    headers["Strict-Transport-Security"] = "max-age=3600"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    short = [f for f in findings if f.title == "HSTS max-age too short"]
    assert len(short) == 1
    assert short[0].severity == "MEDIUM"


@respx.mock
def test_fetch_headers_httpx_path():
    respx.get(URL).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Security-Policy": "default-src 'self'", "Server": "nginx"},
        )
    )
    headers, method = scanner.fetch_headers(URL)
    assert method == "httpx"
    assert headers["server"] == "nginx"
    assert headers["content-security-policy"] == "default-src 'self'"


def test_fetch_headers_falls_back_to_curl_on_timeout(monkeypatch):
    def boom(url, timeout=scanner.HTTPX_TIMEOUT_SEC):
        raise httpx.ReadTimeout("simulated timeout", request=None)

    monkeypatch.setattr(scanner, "fetch_headers_httpx", boom)

    curl_output = (
        "HTTP/2 200\r\n"
        "server: cloudfront\r\n"
        "x-powered-by: Express\r\n"
        "content-type: text/html\r\n"
        "\r\n"
    )
    fake_proc = subprocess.CompletedProcess(
        args=["curl"], returncode=0, stdout=curl_output, stderr=""
    )

    with patch("tools.scanner.subprocess.run", return_value=fake_proc) as mock_run:
        headers, method = scanner.fetch_headers(URL)

    assert method == "curl"
    assert headers["server"] == "cloudfront"
    assert headers["x-powered-by"] == "Express"
    mock_run.assert_called_once()
    cmd = mock_run.call_args.args[0]
    assert cmd[0] == "curl"
    assert URL in cmd


def test_out_of_scope_target_raises():
    with pytest.raises(ValueError, match="not in authorized scope"):
        scanner.scan("https://evil.example.com")


def test_write_findings_json_roundtrip(tmp_path: Path):
    headers = dict(STRICT_HEADERS)
    headers.pop("Content-Security-Policy")
    headers["Server"] = "nginx/1.25"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    assert findings  # at least 2

    out = tmp_path / "scanner.json"
    scanner.write_findings(findings, out)
    raw = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(raw, list) and len(raw) == len(findings)
    restored = [Finding.model_validate(item) for item in raw]
    assert all(f.tool == "scanner" for f in restored)
    assert "HIGH" in {f.severity for f in restored}


def test_headers_checks_count_at_least_60():
    # Spec: au moins 60 checks. Ground truth, no flexibility.
    assert len(scanner.HEADERS_CHECKS) >= 60, (
        f"Expected >=60 checks, got {len(scanner.HEADERS_CHECKS)}"
    )


# ── Sprint 1 corrections (Session 3 §1-3) ──────────────────────────────


def test_hsts_completely_missing_yields_high_finding():
    """Regression test for the audit observation #1: confirm HSTS missing
    is emitted as a HIGH finding and serialized correctly."""
    headers = dict(STRICT_HEADERS)
    headers.pop("Strict-Transport-Security")
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    hsts = [f for f in findings if f.title == "HSTS header missing"]
    assert len(hsts) == 1
    f = hsts[0]
    assert f.severity == "HIGH"
    assert f.sprint == 1
    assert f.tool == "scanner"
    assert "Strict-Transport-Security" in f.evidence[0]
    assert "header absent" in f.evidence[0]
    # Must survive JSON round-trip via the schema.
    restored = Finding.model_validate_json(f.model_dump_json())
    assert restored.title == "HSTS header missing"
    assert restored.severity == "HIGH"


def test_chain_dependency_flag_set_for_csp_unsafe_inline_and_eval():
    """Two findings derived from the same CSP header value must share
    the CHAIN_DEPENDENCY flag (they have the same root cause)."""
    headers = dict(STRICT_HEADERS)
    headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    csp_findings = [f for f in findings if f.title.startswith("CSP allows")]
    assert len(csp_findings) == 2
    titles = {f.title for f in csp_findings}
    assert titles == {"CSP allows unsafe-inline", "CSP allows unsafe-eval"}
    for f in csp_findings:
        assert "CHAIN_DEPENDENCY" in f.flags, (
            f"missing CHAIN_DEPENDENCY on {f.title}; flags={f.flags}"
        )
    # The two findings must point at the same evidence string.
    assert csp_findings[0].evidence == csp_findings[1].evidence


def test_chain_dependency_not_set_for_unrelated_findings():
    """Findings from distinct headers must NOT receive CHAIN_DEPENDENCY."""
    headers = dict(STRICT_HEADERS)
    headers.pop("Content-Security-Policy")  # 1 CSP finding
    headers["Server"] = "nginx/1.25"        # 1 Server finding
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    relevant = [f for f in findings if f.title in {
        "Content-Security-Policy missing", "Server header exposes software"
    }]
    assert len(relevant) == 2
    for f in relevant:
        assert "CHAIN_DEPENDENCY" not in f.flags, (
            f"unexpected CHAIN_DEPENDENCY on {f.title}; evidence={f.evidence}"
        )


def test_imperva_signature_detected_with_context_dependent_flag():
    """Set-Cookie containing 'ipmsperf_uuid' → INFO finding, CONTEXT_DEPENDENT flag."""
    headers = dict(STRICT_HEADERS)
    headers["Set-Cookie"] = (
        "ipmsperf_uuid=abc-123; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    waf = [f for f in findings if "Imperva" in f.title or "Incapsula" in f.title]
    assert len(waf) == 1
    f = waf[0]
    assert f.severity == "INFO"
    assert "CONTEXT_DEPENDENT" in f.flags
    assert "ipmsperf_uuid" in f.evidence[0]


def test_imperva_signature_not_emitted_when_cookie_clean():
    """Without ipmsperf_uuid, the Imperva check must NOT fire."""
    headers = dict(STRICT_HEADERS)
    headers["Set-Cookie"] = "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    findings = scanner.evaluate_headers(
        scanner._normalize_headers(headers.items()), target=URL, method="httpx"
    )
    assert not any("Imperva" in f.title or "Incapsula" in f.title for f in findings)
