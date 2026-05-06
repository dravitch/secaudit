"""
tools/phishing_surface.py
Sprints 3 + 4 — surface phishing passive.

Sprint 3 (passive HTTP) :
  - Login page parser (BeautifulSoup) : trouve le 1er formulaire login
    sur /, /connexion, /login, /auth.
  - Assets externes + SRI checker : <script>, <link rel=stylesheet>, <img>.
  - WAF/CDN signature (Imperva ipmsperf_uuid) — enrichissement Sprint 1.
  - Favicon fingerprinting : SHA256 du contenu pour détection clones.

Sprint 4 (passif, génération + meta-WHOIS) :
  - generate_typosquats(domain) → ≤15 variantes, filtrées contre les
    Restricted TLDs (.gov.gn, .gouv.gn — WhoisFreaks). Aucun appel DNS
    sur les variantes elles-mêmes.
  - 1 Finding HIGH PHISHING_VECTOR par variante restante.
  - 1 Finding CRITICAL synthèse PHISHING_VECTOR + CHAIN_DEPENDENCY.

Mindset 13 — passif strict : aucun formulaire soumis, aucune authentification
tentée. Le seul appel réseau hors target est la lookup WhoisFreaks pour
classer le TLD (registrable ou restricted), pas le target lui-même.
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
import warnings
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

# Allow running as a script (`python tools/phishing_surface.py ...`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

from schemas.finding import Finding
from tools._scope import assert_in_scope, normalize_host

HTTPX_TIMEOUT_SEC = 10.0
USER_AGENT = "secaudit/0.1 (+passive)"
LOGIN_PATHS = ("/", "/connexion", "/login", "/auth")
FAVICON_PATHS = ("/favicon.ico", "/favicon.png")
MAX_TYPOSQUATS = 15
WAF_IMPERVA_COOKIES = ("ipmsperf_uuid",)

app = typer.Typer(add_completion=False)


# ── HTTP helpers ─────────────────────────────────────────────────────


def _http_get(client: httpx.Client, url: str) -> Optional[httpx.Response]:
    """GET an URL, swallow connection errors, return Response or None."""
    try:
        return client.get(url, headers={"User-Agent": USER_AGENT})
    except (httpx.RequestError, httpx.TimeoutException):
        return None


def _make(
    target: str,
    title: str,
    description: str,
    severity: str,
    evidence: list[str],
    flags: list[str] | None = None,
    sprint: int = 3,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        sprint=sprint,
        tool="phishing-surface",
        target=target,
        timestamp=datetime.utcnow(),
        title=title,
        finding=description,
        evidence=evidence or ["(no evidence)"],
        analyst_conclusion=description,
        severity=severity,
        flags=list(flags or []),
    )


# ── Sprint 3 §1 — login form parser ──────────────────────────────────


def find_login_page(
    client: httpx.Client, base_url: str
) -> Optional[tuple[str, BeautifulSoup, httpx.Response]]:
    """Try each LOGIN_PATHS in order, return the first 200 OK page."""
    for path in LOGIN_PATHS:
        url = urljoin(base_url, path)
        resp = _http_get(client, url)
        if resp is not None and resp.status_code == 200 and resp.text:
            return url, BeautifulSoup(resp.text, "lxml"), resp
    return None


def parse_login_form(
    page_url: str, soup: BeautifulSoup, target: str
) -> list[Finding]:
    """Find a login-shaped form and emit findings about it."""
    findings: list[Finding] = []
    for form in soup.find_all("form"):
        # Heuristic: form is a login form if it contains a password input.
        if not form.find("input", {"type": "password"}):
            continue

        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""
        action_abs = urljoin(page_url, action) if action else page_url
        host_self = normalize_host(target)
        host_action = urlparse(action_abs).hostname or host_self
        external_action = host_action != host_self

        inputs_summary = [
            f"<input name={(i.get('name') or '?')!r} type={(i.get('type') or 'text')!r} id={(i.get('id') or '')!r}>"
            for i in form.find_all("input")
        ]

        findings.append(_make(
            target,
            "Login form identified",
            f"Formulaire de connexion détecté sur {page_url} (method={method}, "
            f"action={action_abs}).",
            "MEDIUM",
            evidence=[str(form)[:1000], *inputs_summary],
        ))

        if method == "GET":
            findings.append(_make(
                target,
                "Login form uses GET (credentials in URL)",
                "Le formulaire login utilise method=GET — les identifiants apparaîtront "
                "dans l'URL, les logs et le Referer.",
                "HIGH",
                evidence=[f"<form method=GET action={action_abs}>"],
            ))

        if external_action:
            findings.append(_make(
                target,
                "Login form action targets external domain",
                f"L'action du formulaire pointe sur {host_action} — domaine externe à {host_self}.",
                "INFO",
                evidence=[f"action={action_abs}", f"page={page_url}"],
            ))

        # One login form is enough for Sprint 3 scope.
        return findings
    return findings


# ── Sprint 3 §2 — external assets + SRI ──────────────────────────────


def parse_external_assets(
    page_url: str, soup: BeautifulSoup, target: str
) -> list[Finding]:
    """For each external <script>/<link>/<img>, check SRI integrity attribute."""
    findings: list[Finding] = []
    self_host = normalize_host(target)
    external_count = 0
    sri_protected = 0

    triplets = (
        ("script", "src", "HIGH",
         "External script without SRI",
         "Script chargé depuis un tiers sans attribut integrity — injection JS possible si l'origine est compromise."),
        ("link", "href", "MEDIUM",
         "External stylesheet without SRI",
         "Feuille de style externe sans integrity — ré-écriture CSS possible si l'origine est compromise."),
        ("img", "src", "INFO",
         "External image without SRI (not enforceable)",
         "Image distante référencée — note pour fingerprinting / suivi tiers."),
    )

    for tag_name, url_attr, severity, title, description in triplets:
        for tag in soup.find_all(tag_name):
            url = tag.get(url_attr)
            if not url:
                continue
            abs_url = urljoin(page_url, url)
            host = urlparse(abs_url).hostname
            if not host or host == self_host:
                continue
            external_count += 1
            integrity = tag.get("integrity")
            if integrity:
                sri_protected += 1
                continue
            # img is informational only — SRI doesn't apply to <img>.
            if tag_name == "img":
                findings.append(_make(
                    target, title, description, severity,
                    evidence=[str(tag)[:300]],
                ))
                continue
            findings.append(_make(
                target, title, description, severity,
                evidence=[str(tag)[:300]],
            ))

    if external_count > 0:
        findings.append(_make(
            target,
            f"{external_count} external assets, {sri_protected} SRI-protected",
            f"Page login charge {external_count} ressources externes ; {sri_protected} sont protégées par integrity.",
            "MEDIUM" if sri_protected < external_count else "INFO",
            evidence=[f"external_count={external_count}", f"sri_protected={sri_protected}"],
            flags=["CHAIN_DEPENDENCY"],
        ))
    return findings


# ── Sprint 3 §3 — WAF/CDN enrichment ─────────────────────────────────


def detect_waf(page_response: httpx.Response, target: str) -> list[Finding]:
    """Look for WAF/CDN cookie signatures in the response."""
    findings: list[Finding] = []
    cookies = page_response.headers.get_list("set-cookie") if hasattr(
        page_response.headers, "get_list"
    ) else [page_response.headers.get("set-cookie", "")]
    cookies_text = " ; ".join(c for c in cookies if c)
    matched = [name for name in WAF_IMPERVA_COOKIES if name in cookies_text]
    if matched:
        findings.append(_make(
            target,
            "WAF Imperva/Incapsula detected",
            "Présence d'un WAF Imperva/Incapsula — peut masquer certains headers "
            "et modifier la surface clonable réelle (à corréler avec Sprint 1).",
            "INFO",
            evidence=[f"cookies={', '.join(matched)}"],
            flags=["CONTEXT_DEPENDENT"],
        ))
    return findings


# ── Sprint 3 §4 — favicon fingerprinting ─────────────────────────────


def fingerprint_favicon(client: httpx.Client, base_url: str, target: str) -> list[Finding]:
    """Fetch /favicon.{ico,png}, hash content (SHA256). Emit one Finding."""
    for path in FAVICON_PATHS:
        url = urljoin(base_url, path)
        resp = _http_get(client, url)
        if resp is None or resp.status_code != 200 or not resp.content:
            continue
        sha = hashlib.sha256(resp.content).hexdigest()
        return [_make(
            target,
            "Favicon accessible (fingerprint)",
            f"Favicon récupéré depuis {url} — son empreinte SHA256 sert d'indicateur "
            "de clone visuel.",
            "INFO",
            evidence=[f"url={url}", f"sha256={sha}", f"bytes={len(resp.content)}"],
        )]
    return [_make(
        target,
        "Favicon absent",
        "Aucun favicon accessible sur /favicon.ico ni /favicon.png — clonage "
        "visuel partiel plus difficile mais site moins reconnaissable.",
        "INFO",
        evidence=["/favicon.ico → not 200", "/favicon.png → not 200"],
    )]


# ── Sprint 4 — typosquat generator + multi-source TLD filter ───────


# Lazy module-level singleton — instantiated on first use so importing
# phishing_surface from a unit test that monkey-patches _is_restricted
# never touches the real network.
_TLD_VERIFIER = None


def _get_verifier():
    """Return a process-wide TLDVerifier (lazy init)."""
    global _TLD_VERIFIER
    if _TLD_VERIFIER is None:
        from tools._tld_verifier import TLDVerifier

        _TLD_VERIFIER = TLDVerifier()
    return _TLD_VERIFIER


def _is_restricted(tld: str) -> bool:
    """True iff the multi-source verifier says RESTRICTED.

    UNKNOWN is treated as NOT restricted: for a phishing-surface audit we
    prefer the false-negative (slightly noisier report) over the false-
    positive (silently dropping a real attack vector).
    """
    result = _get_verifier().check(tld)
    verdict = result["verdict"]
    if verdict == "RESTRICTED":
        warnings.warn(
            f"TLD {tld!r} excluded from typosquat list: RESTRICTED "
            f"({result['votes_restricted']}/{result['votes_available']} sources).",
            RuntimeWarning, stacklevel=2,
        )
        return True
    if verdict == "UNKNOWN":
        warnings.warn(
            f"TLD {tld!r} restriction status UNKNOWN "
            f"({result['votes_restricted']}/{result['votes_available']} sources) "
            f"— variants kept by precaution.",
            RuntimeWarning, stacklevel=2,
        )
    return False


def _split_domain(domain: str) -> tuple[str, str, str]:
    """Split 'foo.gov.gn' → ('foo', '.gov.gn', '.gn').

    Returns (label, full_suffix, base_tld) where base_tld is the last
    label only — used as the registrable-TLD anchor for free variants.
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        label = parts[0]
        full_suffix = "." + ".".join(parts[1:])
        base_tld = "." + parts[-1]
        return label, full_suffix, base_tld
    return domain, "", ""


HOMOGLYPH_MAP = {"l": "1", "o": "0", "e": "3", "a": "@"}


def _homoglyph_variants(label: str) -> list[tuple[str, str]]:
    """Single-char homoglyph substitutions. Returns (variant, rule)."""
    out: list[tuple[str, str]] = []
    for i, ch in enumerate(label):
        sub = HOMOGLYPH_MAP.get(ch.lower())
        if sub is None:
            continue
        variant = label[:i] + sub + label[i + 1:]
        out.append((variant, f"homoglyph {ch}->{sub} at index {i}"))
    return out


def _hyphen_variants(label: str) -> list[tuple[str, str]]:
    """Insert a hyphen at each interior position."""
    out: list[tuple[str, str]] = []
    for i in range(1, len(label)):
        variant = label[:i] + "-" + label[i:]
        out.append((variant, f"hyphen inserted at index {i}"))
    return out


def generate_typosquats(domain: str) -> list[tuple[str, str]]:
    """Generate up to MAX_TYPOSQUATS typosquat variants for a given domain.

    Filters out variants on Restricted TLDs (e.g. .gov.gn, .gouv.gn) using
    the multi-source TLDVerifier (IANA + WhoisFreaks + DNS SOA, ≥ 2/3
    consensus). Variants on the free base TLD (e.g. .gn) are always kept.
    """
    label, full_suffix, base_tld = _split_domain(domain)
    candidates: list[tuple[str, str]] = []

    # ── Free base TLD (.gn) — always safe ───────────────────────────
    for variant_label, rule in _homoglyph_variants(label):
        candidates.append((variant_label + base_tld, f"{rule} on free TLD"))

    if ".gov." in full_suffix or full_suffix == ".gov":
        candidates.append(
            (f"{label}-gov{base_tld}", "merge .gov as hyphen suffix on free TLD")
        )
        candidates.append(
            (f"{label}-gouv{base_tld}", "merge .gouv as hyphen suffix on free TLD")
        )

    if full_suffix != base_tld and full_suffix:
        candidates.append((label + base_tld, "drop intermediate subdomain levels"))

    # ── Other intermediate TLDs (.gov.gn, .gouv.gn) — gated on consensus ──
    intermediate_tlds: list[str] = []
    if full_suffix and full_suffix != base_tld:
        intermediate_tlds.append(full_suffix)
        if ".gov." in full_suffix:
            intermediate_tlds.append(full_suffix.replace(".gov.", ".gouv.", 1))

    for suffix in intermediate_tlds:
        if _is_restricted(suffix):
            continue
        for variant_label, rule in _homoglyph_variants(label):
            candidates.append((variant_label + suffix, f"{rule} on {suffix}"))
        for variant_label, rule in _hyphen_variants(label):
            candidates.append((variant_label + suffix, f"{rule} on {suffix}"))
        for tpl, rule in [
            (f"www-{label}{suffix}", f"prefix 'www-' on {suffix}"),
            (f"{label}-portail{suffix}", f"suffix '-portail' on {suffix}"),
            (f"{label}-connect{suffix}", f"suffix '-connect' on {suffix}"),
        ]:
            candidates.append((tpl, rule))

    # Dedupe while preserving order, cap at MAX_TYPOSQUATS.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for c, rule in candidates:
        if c == domain or c in seen:
            continue
        seen.add(c)
        unique.append((c, rule))
        if len(unique) >= MAX_TYPOSQUATS:
            break
    return unique


def _collect_excluded_restricted_tlds(domain: str) -> list[str]:
    """List intermediate TLDs that were excluded for being RESTRICTED.

    Used in the synthesis finding evidence so the auditor sees the filter
    decision at a glance.
    """
    _, full_suffix, base_tld = _split_domain(domain)
    excluded: list[str] = []
    if full_suffix and full_suffix != base_tld:
        if _is_restricted(full_suffix):
            excluded.append(full_suffix)
        if ".gov." in full_suffix:
            gouv = full_suffix.replace(".gov.", ".gouv.", 1)
            if _is_restricted(gouv):
                excluded.append(gouv)
    return excluded


def typosquat_findings(target: str) -> list[Finding]:
    """Build one HIGH finding per typosquat + a CRITICAL synthesis finding."""
    findings: list[Finding] = []
    host = normalize_host(target)
    variants = generate_typosquats(host)
    excluded_tlds = _collect_excluded_restricted_tlds(host)
    for variant, rule in variants:
        findings.append(_make(
            target,
            f"Typosquat domain variant: {variant}",
            f"Variante typosquat plausible '{variant}' (règle: {rule}) — "
            "vecteur phishing direct si enregistrée par un attaquant.",
            "HIGH",
            evidence=[f"variant={variant}", f"rule={rule}"],
            flags=["PHISHING_VECTOR"],
            sprint=4,
        ))
    if variants:
        if excluded_tlds:
            excluded_text = (
                f" {', '.join(excluded_tlds)} sont des Restricted Domains "
                f"(WhoisFreaks) — variantes sur ces TLDs exclues car non "
                f"enregistrables par des tiers."
            )
        else:
            excluded_text = ""
        findings.append(_make(
            target,
            f"{len(variants)} typosquat variants — TLD libre d'enregistrement",
            f"{len(variants)} variantes typosquat sur TLD libre identifiées "
            f"pour {host}.{excluded_text} À corréler avec DMARC p=none + "
            f"DNSSEC absent du Sprint 2.",
            "CRITICAL",
            evidence=[
                f"variants={[v for v, _ in variants]}",
                f"excluded_restricted_tlds={excluded_tlds}",
            ],
            flags=["PHISHING_VECTOR", "CHAIN_DEPENDENCY"],
            sprint=4,
        ))
    return findings


# ── Orchestration ────────────────────────────────────────────────────


def scan(target: str) -> list[Finding]:
    """Full passive phishing-surface scan."""
    assert_in_scope(target, sprint=4)
    findings: list[Finding] = []
    with httpx.Client(
        verify=True, follow_redirects=True, timeout=HTTPX_TIMEOUT_SEC
    ) as client:
        located = find_login_page(client, target)
        if located is None:
            findings.append(_make(
                target,
                "No login page reachable",
                "Aucune page sur '/', '/connexion', '/login', '/auth' n'a renvoyé HTTP 200 — "
                "scan limité aux artefacts globaux (favicon, typosquats).",
                "INFO",
                evidence=[f"paths_tried={list(LOGIN_PATHS)}"],
            ))
        else:
            page_url, soup, response = located
            findings.extend(parse_login_form(page_url, soup, target))
            findings.extend(parse_external_assets(page_url, soup, target))
            findings.extend(detect_waf(response, target))
        findings.extend(fingerprint_favicon(client, target, target))
    findings.extend(typosquat_findings(target))
    return findings


def write_findings(findings: list[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(f.model_dump_json()) for f in findings]
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def print_summary(findings: list[Finding]) -> None:
    console = Console()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    table = Table(title=f"phishing-surface — {len(findings)} finding(s)")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev, 0):
            table.add_row(sev, str(counts[sev]))
    console.print(table)


@app.command()
def main(
    target: str = typer.Option(..., "--target", help="Full URL (https://host)"),
    output: Path = typer.Option(..., "--output", help="JSON output file"),
):
    """Sprints 3 + 4 — passive phishing surface."""
    findings = scan(target)
    write_findings(findings, output)
    typer.echo(f"[phishing-surface] {len(findings)} finding(s) → {output}")
    print_summary(findings)


if __name__ == "__main__":
    app()
