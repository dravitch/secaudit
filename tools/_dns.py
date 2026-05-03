"""
tools/_dns.py
Sprint 2 — checks DNS via subprocess dig (DNSSEC, SPF, DMARC, DKIM, MX).

Mappings de severité (CLAUDE.md Session 3 §6) :
  DNSSEC absent       → CRITICAL
  SPF absent          → CRITICAL
  DMARC absent        → CRITICAL
  DMARC p=none        → HIGH
  DKIM absent         → HIGH
  MX present          → INFO + flag CHAIN_DEPENDENCY (vecteur phishing)
"""
from __future__ import annotations

import re
import subprocess
import uuid
from datetime import datetime
from typing import Iterable

from schemas.finding import Finding
from tools._scope import assert_in_scope, normalize_host

DIG_TIMEOUT_SEC = 15
DIG_BINARY = "dig"
DKIM_DEFAULT_SELECTOR = "default"


def _resolve_dig() -> str:
    import shutil

    path = shutil.which(DIG_BINARY)
    if path:
        return path
    raise RuntimeError(
        "dig not found on PATH — run from `nix-shell` (see shell.nix) "
        "or install dnsutils manually."
    )


def _dig(rrtype: str, name: str, timeout: int = DIG_TIMEOUT_SEC) -> list[str]:
    """Run `dig +short <rrtype> <name>` and return non-empty stripped lines."""
    binary = _resolve_dig()
    cmd = [binary, "+short", rrtype, name]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False, timeout=timeout
    )
    if proc.returncode != 0 and not proc.stdout:
        # dig returns rc=0 even for NXDOMAIN+empty; rc!=0 here is a real error.
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _make_dns_finding(
    target: str,
    title: str,
    description: str,
    severity: str,
    evidence_lines: Iterable[str],
    flags: list[str] | None = None,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        sprint=2,
        tool="scanner-dns",
        target=target,
        timestamp=datetime.utcnow(),
        title=title,
        finding=description,
        evidence=list(evidence_lines) or ["(no records)"],
        analyst_conclusion=description,
        severity=severity,
        flags=list(flags or []),
    )


def check_dnssec(host: str) -> list[Finding]:
    """DNSKEY absent → CRITICAL."""
    keys = _dig("DNSKEY", host)
    if not keys:
        return [_make_dns_finding(
            host,
            "DNSSEC missing (no DNSKEY)",
            "Aucun DNSKEY publié — DNSSEC non activé, spoofing DNS facilité.",
            "CRITICAL",
            [f"dig +short DNSKEY {host} → empty"],
        )]
    return []


def check_spf(host: str) -> list[Finding]:
    """SPF absent → CRITICAL."""
    txts = _dig("TXT", host)
    spf_records = [r for r in txts if "v=spf1" in r.lower()]
    if not spf_records:
        return [_make_dns_finding(
            host,
            "SPF record missing",
            "Aucun enregistrement v=spf1 — usurpation d'expéditeur facilitée.",
            "CRITICAL",
            [f"dig +short TXT {host} → no v=spf1 record"],
        )]
    return []


def check_dmarc(host: str) -> list[Finding]:
    """DMARC absent → CRITICAL ; DMARC p=none → HIGH."""
    name = f"_dmarc.{host}"
    txts = _dig("TXT", name)
    dmarc_records = [r for r in txts if "v=dmarc1" in r.lower()]
    if not dmarc_records:
        return [_make_dns_finding(
            host,
            "DMARC record missing",
            "Aucun DMARC sur _dmarc — phishing par e-mail facilité.",
            "CRITICAL",
            [f"dig +short TXT {name} → empty"],
        )]
    findings: list[Finding] = []
    for line in dmarc_records:
        if re.search(r"\bp\s*=\s*none\b", line, re.IGNORECASE):
            findings.append(_make_dns_finding(
                host,
                "DMARC policy is p=none",
                "DMARC publié mais politique 'none' — observation seulement, aucun blocage.",
                "HIGH",
                [line],
            ))
            break
    return findings


def check_dkim(host: str, selector: str = DKIM_DEFAULT_SELECTOR) -> list[Finding]:
    """DKIM absent (sélecteur 'default') → HIGH."""
    name = f"{selector}._domainkey.{host}"
    txts = _dig("TXT", name)
    dkim_records = [r for r in txts if re.search(r"\b(v=dkim|p=|k=)", r, re.IGNORECASE)]
    if not dkim_records:
        return [_make_dns_finding(
            host,
            f"DKIM record missing (selector={selector})",
            f"Aucun DKIM sur le sélecteur '{selector}' — signature e-mail absente.",
            "HIGH",
            [f"dig +short TXT {name} → empty"],
        )]
    return []


def check_mx(host: str) -> list[Finding]:
    """MX present → INFO + CHAIN_DEPENDENCY (phishing vector context)."""
    mx_records = _dig("MX", host)
    if not mx_records:
        return []
    return [_make_dns_finding(
        host,
        "MX records published",
        "Serveurs mail identifiés — vecteur phishing à corréler avec SPF/DMARC.",
        "INFO",
        mx_records,
        flags=["CHAIN_DEPENDENCY"],
    )]


def scan_dns(target: str) -> list[Finding]:
    """Full DNS scan: scope check → all checks. Order: DNSSEC, SPF, DMARC, DKIM, MX."""
    assert_in_scope(target, sprint=2)
    host = normalize_host(target)
    findings: list[Finding] = []
    findings.extend(check_dnssec(host))
    findings.extend(check_spf(host))
    findings.extend(check_dmarc(host))
    findings.extend(check_dkim(host))
    findings.extend(check_mx(host))
    return findings
