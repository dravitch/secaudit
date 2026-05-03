"""
tools/scanner.py
Sprint 1 — analyse HTTP headers via httpx (primary) avec fallback curl
si httpx timeout > HTTPX_TIMEOUT_SEC.

61 checks définis dans HEADERS_CHECKS (security headers, info disclosure,
deprecated, dangerous values).

Rejette toute cible absente de config/scope.yaml.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

# Allow running as a script (`python tools/scanner.py ...`) per CLAUDE.md §12.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import typer
from rich.console import Console
from rich.table import Table

from schemas.finding import Finding
from tools._scope import assert_in_scope, normalize_host

HTTPX_TIMEOUT_SEC = 10.0
CURL_TIMEOUT_SEC = 15
USER_AGENT = "secaudit/0.1 (+passive)"

# Each check is a dict with:
#   header           : header name (case-insensitive matching)
#   rule             : "required" | "forbidden" | "must_match" | "must_not_match"
#   severity         : finding severity if rule violated
#   title            : short title
#   description      : description for the Finding `finding` field
#   pattern          : regex (only for must_match / must_not_match)
#   requires_present : skip must_match if header absent (avoids duplicate findings)
HEADERS_CHECKS: list[dict] = [
    # --- Group A: security headers required ---
    {"header": "Strict-Transport-Security", "rule": "required", "severity": "HIGH",
     "title": "HSTS header missing",
     "description": "Strict-Transport-Security absent — sessions HTTPS dégradables (downgrade)."},
    {"header": "Strict-Transport-Security", "rule": "must_match",
     "pattern": r"max-age\s*=\s*(\d{8,})", "requires_present": True,
     "severity": "MEDIUM",
     "title": "HSTS max-age too short",
     "description": "max-age inférieur à ~6 mois — HSTS insuffisamment durable."},
    {"header": "Content-Security-Policy", "rule": "required", "severity": "HIGH",
     "title": "Content-Security-Policy missing",
     "description": "Aucune CSP — risque XSS et exfiltration accru."},
    {"header": "Content-Security-Policy", "rule": "must_not_match",
     "pattern": r"unsafe-inline", "severity": "MEDIUM",
     "title": "CSP allows unsafe-inline",
     "description": "CSP autorise unsafe-inline — protection XSS dégradée."},
    {"header": "Content-Security-Policy", "rule": "must_not_match",
     "pattern": r"unsafe-eval", "severity": "MEDIUM",
     "title": "CSP allows unsafe-eval",
     "description": "CSP autorise unsafe-eval — surface d'injection JS."},
    {"header": "X-Frame-Options", "rule": "required", "severity": "MEDIUM",
     "title": "X-Frame-Options missing",
     "description": "X-Frame-Options absent — clickjacking si CSP frame-ancestors absent."},
    {"header": "X-Frame-Options", "rule": "must_match",
     "pattern": r"(?i)^(DENY|SAMEORIGIN)\s*$", "requires_present": True,
     "severity": "MEDIUM",
     "title": "X-Frame-Options weak value",
     "description": "X-Frame-Options doit être DENY ou SAMEORIGIN."},
    {"header": "X-Content-Type-Options", "rule": "required", "severity": "MEDIUM",
     "title": "X-Content-Type-Options missing",
     "description": "X-Content-Type-Options absent — sniffing MIME possible."},
    {"header": "X-Content-Type-Options", "rule": "must_match",
     "pattern": r"(?i)^nosniff\s*$", "requires_present": True,
     "severity": "LOW",
     "title": "X-Content-Type-Options weak value",
     "description": "X-Content-Type-Options doit valoir 'nosniff'."},
    {"header": "Referrer-Policy", "rule": "required", "severity": "MEDIUM",
     "title": "Referrer-Policy missing",
     "description": "Aucune politique referrer — fuite d'URL vers tiers."},
    {"header": "Permissions-Policy", "rule": "required", "severity": "MEDIUM",
     "title": "Permissions-Policy missing",
     "description": "Permissions-Policy absent — APIs navigateur non durcies."},
    {"header": "Cross-Origin-Opener-Policy", "rule": "required", "severity": "LOW",
     "title": "COOP missing",
     "description": "Cross-Origin-Opener-Policy absent — pas d'isolation cross-origin."},
    {"header": "Cross-Origin-Embedder-Policy", "rule": "required", "severity": "LOW",
     "title": "COEP missing",
     "description": "Cross-Origin-Embedder-Policy absent — pas de require-corp."},
    {"header": "Cross-Origin-Resource-Policy", "rule": "required", "severity": "LOW",
     "title": "CORP missing",
     "description": "Cross-Origin-Resource-Policy absent."},
    {"header": "Origin-Agent-Cluster", "rule": "required", "severity": "INFO",
     "title": "Origin-Agent-Cluster missing",
     "description": "Origin-Agent-Cluster absent — pas d'isolation par origine."},
    {"header": "NEL", "rule": "required", "severity": "INFO",
     "title": "NEL missing",
     "description": "Network Error Logging non configuré."},
    {"header": "Reporting-Endpoints", "rule": "required", "severity": "INFO",
     "title": "Reporting-Endpoints missing",
     "description": "Reporting-Endpoints absent — pas de remontée d'incidents navigateur."},
    {"header": "Report-To", "rule": "required", "severity": "INFO",
     "title": "Report-To missing",
     "description": "Report-To absent (déprécié — voir Reporting-Endpoints)."},
    {"header": "Cache-Control", "rule": "required", "severity": "LOW",
     "title": "Cache-Control missing",
     "description": "Cache-Control absent — caching indéterminé."},

    # --- Group B: information disclosure (forbidden) ---
    {"header": "Server", "rule": "forbidden", "severity": "LOW",
     "title": "Server header exposes software",
     "description": "Header Server révèle le logiciel/version."},
    {"header": "X-Powered-By", "rule": "forbidden", "severity": "LOW",
     "title": "X-Powered-By disclosure",
     "description": "Header X-Powered-By révèle la stack applicative."},
    {"header": "X-AspNet-Version", "rule": "forbidden", "severity": "LOW",
     "title": "X-AspNet-Version disclosure",
     "description": "Version ASP.NET exposée."},
    {"header": "X-AspNetMvc-Version", "rule": "forbidden", "severity": "LOW",
     "title": "X-AspNetMvc-Version disclosure",
     "description": "Version ASP.NET MVC exposée."},
    {"header": "X-Runtime", "rule": "forbidden", "severity": "LOW",
     "title": "X-Runtime disclosure",
     "description": "Runtime applicatif exposé (Rails)."},
    {"header": "X-Generator", "rule": "forbidden", "severity": "LOW",
     "title": "X-Generator disclosure",
     "description": "Outil de génération exposé."},
    {"header": "X-Drupal-Cache", "rule": "forbidden", "severity": "LOW",
     "title": "X-Drupal-Cache disclosure",
     "description": "Drupal détecté via header de cache."},
    {"header": "X-Drupal-Dynamic-Cache", "rule": "forbidden", "severity": "LOW",
     "title": "X-Drupal-Dynamic-Cache disclosure",
     "description": "Drupal cache dynamique exposé."},
    {"header": "X-Generated-By", "rule": "forbidden", "severity": "LOW",
     "title": "X-Generated-By disclosure",
     "description": "Outil de génération exposé."},
    {"header": "X-Backend-Server", "rule": "forbidden", "severity": "LOW",
     "title": "X-Backend-Server disclosure",
     "description": "Backend interne exposé."},
    {"header": "X-Pingback", "rule": "forbidden", "severity": "LOW",
     "title": "X-Pingback exposed (WordPress)",
     "description": "WordPress XML-RPC pingback exposé."},
    {"header": "X-Wix-Request-Id", "rule": "forbidden", "severity": "INFO",
     "title": "X-Wix-Request-Id disclosure",
     "description": "Plateforme Wix identifiée."},
    {"header": "X-Hubspot-Correlation-Id", "rule": "forbidden", "severity": "INFO",
     "title": "X-Hubspot-Correlation-Id disclosure",
     "description": "Plateforme HubSpot identifiée."},
    {"header": "X-Powered-CMS", "rule": "forbidden", "severity": "LOW",
     "title": "X-Powered-CMS disclosure",
     "description": "CMS exposé."},
    {"header": "X-Backend", "rule": "forbidden", "severity": "LOW",
     "title": "X-Backend disclosure",
     "description": "Backend exposé."},
    {"header": "X-Application-Context", "rule": "forbidden", "severity": "LOW",
     "title": "X-Application-Context disclosure (Spring)",
     "description": "Contexte Spring Boot exposé."},
    {"header": "X-Cache", "rule": "forbidden", "severity": "INFO",
     "title": "X-Cache disclosure",
     "description": "Couche de cache révélée."},
    {"header": "X-Served-By", "rule": "forbidden", "severity": "INFO",
     "title": "X-Served-By disclosure",
     "description": "Identité du serveur applicatif révélée."},
    {"header": "X-Varnish", "rule": "forbidden", "severity": "INFO",
     "title": "X-Varnish disclosure",
     "description": "Varnish identifié."},
    {"header": "Via", "rule": "forbidden", "severity": "INFO",
     "title": "Via disclosure",
     "description": "Proxy intermédiaire révélé."},
    {"header": "X-Cf-Pop", "rule": "forbidden", "severity": "INFO",
     "title": "X-Cf-Pop disclosure",
     "description": "Cloudflare PoP révélé."},
    {"header": "X-Sucuri-ID", "rule": "forbidden", "severity": "INFO",
     "title": "X-Sucuri-ID disclosure",
     "description": "Sucuri WAF révélé."},
    {"header": "X-Sucuri-Cache", "rule": "forbidden", "severity": "INFO",
     "title": "X-Sucuri-Cache disclosure",
     "description": "Sucuri cache révélé."},
    {"header": "X-Mod-Pagespeed", "rule": "forbidden", "severity": "INFO",
     "title": "X-Mod-Pagespeed disclosure",
     "description": "Module Pagespeed exposé."},
    {"header": "X-Page-Speed", "rule": "forbidden", "severity": "INFO",
     "title": "X-Page-Speed disclosure",
     "description": "Pagespeed exposé."},
    {"header": "X-Server", "rule": "forbidden", "severity": "LOW",
     "title": "X-Server disclosure",
     "description": "Serveur interne exposé."},
    {"header": "X-Host", "rule": "forbidden", "severity": "LOW",
     "title": "X-Host disclosure",
     "description": "Hôte interne exposé."},
    {"header": "X-CDN", "rule": "forbidden", "severity": "INFO",
     "title": "X-CDN disclosure",
     "description": "CDN révélé."},
    {"header": "X-Hudson", "rule": "forbidden", "severity": "LOW",
     "title": "X-Hudson disclosure",
     "description": "Jenkins/Hudson exposé."},
    {"header": "X-Jenkins", "rule": "forbidden", "severity": "LOW",
     "title": "X-Jenkins disclosure",
     "description": "Jenkins exposé."},
    {"header": "X-Iinfo", "rule": "forbidden", "severity": "INFO",
     "title": "X-Iinfo disclosure (Incapsula)",
     "description": "Incapsula WAF révélé."},
    {"header": "X-Litespeed-Cache", "rule": "forbidden", "severity": "INFO",
     "title": "X-Litespeed-Cache disclosure",
     "description": "Litespeed cache révélé."},
    {"header": "X-CF-Powered-By", "rule": "forbidden", "severity": "INFO",
     "title": "X-CF-Powered-By disclosure",
     "description": "Cloudflare module exposé."},

    # --- Group C: deprecated / advisory ---
    {"header": "Expect-CT", "rule": "forbidden", "severity": "INFO",
     "title": "Expect-CT present (deprecated)",
     "description": "Expect-CT déprécié — supprimer."},
    {"header": "Public-Key-Pins", "rule": "forbidden", "severity": "INFO",
     "title": "Public-Key-Pins present (deprecated)",
     "description": "HPKP déprécié — supprimer."},
    {"header": "Feature-Policy", "rule": "forbidden", "severity": "INFO",
     "title": "Feature-Policy present (deprecated)",
     "description": "Feature-Policy déprécié — utiliser Permissions-Policy."},
    {"header": "X-XSS-Protection", "rule": "must_not_match",
     "pattern": r"^[1-9]", "severity": "INFO",
     "title": "X-XSS-Protection enabled (legacy)",
     "description": "Recommandation moderne : X-XSS-Protection: 0."},

    # --- Group D: dangerous values ---
    {"header": "Access-Control-Allow-Origin", "rule": "must_not_match",
     "pattern": r"^\*\s*$", "severity": "MEDIUM",
     "title": "ACAO wildcard",
     "description": "Access-Control-Allow-Origin = * — CORS trop permissif."},
    {"header": "Access-Control-Allow-Credentials", "rule": "must_not_match",
     "pattern": r"(?i)^true\s*$", "severity": "MEDIUM",
     "title": "ACAC=true (verify ACAO)",
     "description": "Access-Control-Allow-Credentials=true — vérifier que ACAO != *."},
    {"header": "Set-Cookie", "rule": "must_match",
     "pattern": r"(?i)Secure", "requires_present": True,
     "severity": "MEDIUM",
     "title": "Set-Cookie missing Secure",
     "description": "Cookie sans attribut Secure — transmissible en HTTP clair."},
    {"header": "Set-Cookie", "rule": "must_match",
     "pattern": r"(?i)HttpOnly", "requires_present": True,
     "severity": "MEDIUM",
     "title": "Set-Cookie missing HttpOnly",
     "description": "Cookie accessible via JavaScript (XSS exfiltration)."},
    {"header": "Set-Cookie", "rule": "must_match",
     "pattern": r"(?i)SameSite\s*=", "requires_present": True,
     "severity": "LOW",
     "title": "Set-Cookie missing SameSite",
     "description": "Cookie sans SameSite — risque CSRF."},

    # --- Group E: WAF/CDN signatures (informational) ---
    {"header": "Set-Cookie", "rule": "must_not_match",
     "pattern": r"ipmsperf_uuid", "severity": "INFO",
     "title": "WAF/CDN detected (Imperva/Incapsula signature)",
     "description": "Set-Cookie contient une signature Imperva/Incapsula (ipmsperf_uuid) — Sprint 3 phishing surface devra tenir compte du WAF.",
     "flags": ["CONTEXT_DEPENDENT"]},
]

app = typer.Typer(add_completion=False)


def _normalize_headers(items) -> dict[str, str]:
    """Lowercase keys for case-insensitive lookup."""
    return {str(k).lower(): str(v) for k, v in items}


def _parse_curl_headers(text: str) -> dict[str, str]:
    """Parse curl -I output. Keep the LAST header block (after redirects)."""
    blocks = re.split(r"\r?\n\r?\n", text.strip())
    last_block = blocks[-1] if blocks else ""
    out: dict[str, str] = {}
    for line in last_block.splitlines():
        if ":" in line and not line.upper().startswith("HTTP/"):
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip()
    return out


def fetch_headers_httpx(
    url: str, timeout: float = HTTPX_TIMEOUT_SEC
) -> dict[str, str]:
    """Fetch via httpx.GET. Returns lowercased-key dict."""
    with httpx.Client(verify=True, follow_redirects=True, timeout=timeout) as c:
        r = c.get(url, headers={"User-Agent": USER_AGENT})
    return _normalize_headers(r.headers.items())


def fetch_headers_curl(
    url: str, timeout: int = CURL_TIMEOUT_SEC
) -> dict[str, str]:
    """Fetch headers via subprocess curl -I. Used as httpx fallback."""
    cmd = [
        "curl", "-sI", "-L", "--max-time", str(timeout),
        "-A", USER_AGENT, url,
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False, timeout=timeout + 5
    )
    if proc.returncode != 0:
        raise RuntimeError(f"curl failed (rc={proc.returncode}): {proc.stderr.strip()}")
    return _parse_curl_headers(proc.stdout)


def fetch_headers(url: str) -> tuple[dict[str, str], str]:
    """Try httpx first; on timeout, fall back to curl. Returns (headers, method)."""
    try:
        return fetch_headers_httpx(url), "httpx"
    except (httpx.TimeoutException, httpx.ReadTimeout, httpx.ConnectTimeout):
        return fetch_headers_curl(url), "curl"


def _evaluate(check: dict, headers: dict[str, str]) -> Optional[tuple[str, str]]:
    """Return (raw_value, evidence_label) if the check is triggered, else None."""
    name = check["header"]
    rule = check["rule"]
    val = headers.get(name.lower())
    pattern = check.get("pattern")
    requires_present = check.get("requires_present", False)

    triggered = False
    if rule == "required":
        triggered = val is None
    elif rule == "forbidden":
        triggered = val is not None
    elif rule == "must_match":
        if val is None:
            triggered = not requires_present
        else:
            triggered = re.search(pattern, val) is None
    elif rule == "must_not_match":
        triggered = (val is not None) and (re.search(pattern, val) is not None)
    else:
        raise ValueError(f"Unknown rule: {rule}")

    if not triggered:
        return None
    raw = val if val is not None else "header absent"
    return raw, f"{name}: {raw}"


def _apply_chain_dependency(findings: list[Finding]) -> None:
    """Tag findings sharing the same evidence source with CHAIN_DEPENDENCY.

    Two or more findings derived from the same raw header value (same
    evidence[0] string) are downstream of one root cause. We mark them so
    the AnalystAgent / report can deduplicate or group them.
    """
    from collections import Counter

    counts = Counter(f.evidence[0] for f in findings if f.evidence)
    for f in findings:
        if not f.evidence:
            continue
        if counts[f.evidence[0]] >= 2 and "CHAIN_DEPENDENCY" not in f.flags:
            f.flags.append("CHAIN_DEPENDENCY")


def evaluate_headers(
    headers: dict[str, str], target: str, method: str
) -> list[Finding]:
    """Run all HEADERS_CHECKS against the response headers. One Finding per trigger."""
    findings: list[Finding] = []
    for check in HEADERS_CHECKS:
        result = _evaluate(check, headers)
        if result is None:
            continue
        _, evidence_label = result
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                sprint=1,
                tool="scanner",
                target=target,
                timestamp=datetime.utcnow(),
                title=check["title"],
                finding=check["description"],
                evidence=[f"{evidence_label} (method={method})"],
                analyst_conclusion=check["description"],
                severity=check["severity"],
                flags=list(check.get("flags", [])),
            )
        )
    _apply_chain_dependency(findings)
    return findings


def scan(target: str) -> list[Finding]:
    """HTTP-headers scan (mode=http). Scope check → fetch → evaluate."""
    assert_in_scope(target, sprint=1)
    headers, method = fetch_headers(target)
    return evaluate_headers(headers, target=target, method=method)


def scan_tls(target: str) -> list[Finding]:
    """TLS scan (mode=tls). Delegates to tools._tls.scan_tls."""
    from tools import _tls

    return _tls.scan_tls(target)


def scan_dns(target: str) -> list[Finding]:
    """DNS scan (mode=dns). Delegates to tools._dns.scan_dns."""
    from tools import _dns

    return _dns.scan_dns(target)


def write_findings(findings: list[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(f.model_dump_json()) for f in findings]
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def print_summary(findings: list[Finding], tool: str) -> None:
    console = Console()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    table = Table(title=f"{tool} — {len(findings)} finding(s)")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev, 0):
            table.add_row(sev, str(counts[sev]))
    console.print(table)


@app.command()
def main(
    target: str = typer.Option(..., "--target", help="URL (http mode) or hostname (tls/dns mode)"),
    output: Path = typer.Option(..., "--output", help="JSON output file"),
    mode: str = typer.Option("http", "--mode", help="http | tls | dns"),
):
    """Scanner CLI — dispatches on --mode."""
    if mode == "http":
        findings = scan(target)
        label = "scanner-http"
    elif mode == "tls":
        findings = scan_tls(target)
        label = "scanner-tls"
    elif mode == "dns":
        findings = scan_dns(target)
        label = "scanner-dns"
    else:
        raise typer.BadParameter(f"unknown mode: {mode!r} (expected http|tls|dns)")
    write_findings(findings, output)
    typer.echo(f"[{label}] {len(findings)} finding(s) → {output}")
    print_summary(findings, tool=label)


if __name__ == "__main__":
    app()
