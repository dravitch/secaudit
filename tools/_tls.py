"""
tools/_tls.py
Sprint 2 — wrapper subprocess autour de testssl.sh (text mode), parsing
ligne par ligne. 1 Finding par anomalie, evidence = ligne brute.

Disponibilité : testssl.sh est fourni par shell.nix / flake.nix. En dehors
de l'environnement Nix, l'appel échoue (RuntimeError clair).

Mindset 1 — Ground Truth or Silence : aucune affirmation sans preuve dans
la ligne testssl.sh.
"""
from __future__ import annotations

import re
import subprocess
import uuid
from datetime import datetime

from schemas.finding import Finding
from tools._scope import assert_in_scope, normalize_host

TESTSSL_TIMEOUT_SEC = 600
TESTSSL_BINARIES = ("testssl.sh", "testssl")

# (regex, severity, title, description)
# Each pattern is searched on every output line. A line that matches yields
# exactly one Finding using that line (stripped) as evidence.
TLS_PATTERNS: list[tuple[str, str, str, str]] = [
    # ── Obsolete protocols ────────────────────────────────────────────────
    (r"\bSSLv2\b\s+offered\b",
     "CRITICAL", "SSLv2 offered",
     "Protocole SSLv2 obsolète actif — déchiffrement trivial."),
    (r"\bSSLv3\b\s+offered\b",
     "CRITICAL", "SSLv3 offered (POODLE)",
     "Protocole SSLv3 obsolète actif — vulnérable à POODLE."),
    (r"\bTLS\s+1(?!\.)\s+offered\b|\bTLS\s+1\.0\b\s+offered\b",
     "HIGH", "TLSv1.0 offered",
     "TLSv1.0 actif — protocole déprécié."),
    (r"\bTLS\s+1\.1\b\s+offered\b",
     "HIGH", "TLSv1.1 offered",
     "TLSv1.1 actif — protocole déprécié."),
    (r"\bTLS\s+1\.2\b\s+offered\b",
     "LOW", "TLSv1.2 offered (acceptable)",
     "TLSv1.2 actif — préférer TLSv1.3 exclusivement."),

    # ── Forward Secrecy ───────────────────────────────────────────────────
    (r"^\s*Forward Secrecy\b.*\b(?:no|not offered|not supported)\b",
     "HIGH", "Forward Secrecy not supported",
     "Forward Secrecy absent — capture TLS rejouable si la clé fuite."),
    (r"^\s*PFS\s+\(.*\)\s*:\s*(?:no|not offered)",
     "HIGH", "Forward Secrecy not supported",
     "PFS absent — confidentialité compromise rétroactivement."),
]

def _parse_cert_days_remaining(line: str) -> int | None:
    """Extract real days-remaining from a testssl cert validity line.

    testssl emits four common shapes:
      "Certificate Validity (UTC)   expires < 30 days (29) (date --> date)"
      "Certificate Validity (UTC)   84 >= 60 days (date --> date)"
      "Certificate Validity (UTC)   45 days remaining"
      "Cert. expiration             certificate expires in 5 days"

    The "< 30 days (29)" form is tricky: the remaining count is in parens,
    not the leading integer. Try the parenthesised form first.
    """
    m = re.search(
        r"expires?\s*<\s*\d+\s*days?\s*\((\d+)\)", line, re.IGNORECASE
    )
    if m:
        return int(m.group(1))
    m = re.search(
        r"Validity[^\d\n]+(\d+)\s*>=\s*\d+\s*days?", line, re.IGNORECASE
    )
    if m:
        return int(m.group(1))
    m = re.search(r"(\d+)\s+days?\s+remaining", line, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"expires?\s+in\s+(\d+)\s+days?", line, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


CERT_LINE_RE = re.compile(
    r"(?:Certificate Validity|Cert\.?\s*expiration)", re.IGNORECASE
)

# Strip ANSI SGR escape sequences so detection doesn't depend on whether
# testssl was invoked with --color 0 (NixOS shells / piped runs may leak codes).
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(line: str) -> str:
    return ANSI_ESCAPE_RE.sub("", line)


# HSTS line shapes (after ANSI strip + lstrip):
#   "Strict Transport Security    not offered"
#   "HSTS                          offered, max-age=..., preload"
#   "Grade capped to A. HSTS is not offered"   (synthesis line, dedupe target)
HSTS_LINE_RE = re.compile(r"\b(?:HSTS|Strict[- ]Transport[- ]Security)\b", re.IGNORECASE)


def _make_tls_finding(
    target: str,
    line: str,
    severity: str,
    title: str,
    description: str,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        sprint=2,
        tool="scanner-tls",
        target=target,
        timestamp=datetime.utcnow(),
        title=title,
        finding=description,
        evidence=[line.strip()],
        analyst_conclusion=description,
        severity=severity,
    )


def _resolve_testssl() -> str:
    """Find testssl.sh binary on PATH. Raise RuntimeError if absent."""
    import shutil

    for name in TESTSSL_BINARIES:
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError(
        "testssl.sh not found on PATH — run from `nix-shell` "
        "(see shell.nix) or install testssl.sh manually."
    )


def run_testssl(target: str, timeout: int = TESTSSL_TIMEOUT_SEC) -> str:
    """Run testssl.sh in plain-text mode against target. Return stdout.

    Flags chosen for Sprint 2 scope (protocols + cert + FS + HSTS):
      -p  protocols
      -S  server defaults (incl. certificate validity, SAN)
      -f  forward secrecy
      -h  HTTP headers (HSTS preload visibility)
    """
    binary = _resolve_testssl()
    cmd = [
        binary,
        "--quiet",
        "--color", "0",
        "-p", "-S", "-f", "-h",
        target,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    # testssl.sh exits non-zero on findings — that's normal. Only fatal if no stdout.
    if not proc.stdout:
        raise RuntimeError(
            f"testssl.sh produced no output (rc={proc.returncode}): "
            f"{proc.stderr.strip()[:200]}"
        )
    return proc.stdout


def parse_testssl_text(text: str, target: str) -> list[Finding]:
    """Parse testssl.sh text output into Findings. One Finding per anomalous line.

    ANSI escape codes (SGR) are stripped before matching so the parser works
    whether testssl was invoked with --color 0 or with default colorisation
    (e.g. when redirected to a file from a fully-coloured shell). HSTS is
    deduped because testssl emits both a 'Strict Transport Security' line
    and a final 'Grade capped ... HSTS is not offered' synthesis line.
    """
    findings: list[Finding] = []
    seen_hsts_kind: set[str] = set()

    for raw_line in text.splitlines():
        line = _strip_ansi(raw_line).rstrip()
        if not line.strip():
            continue

        # Protocol / FS pattern checks.
        for pattern, severity, title, description in TLS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(
                    _make_tls_finding(target, line, severity, title, description)
                )

        # Certificate expiration window.
        if CERT_LINE_RE.search(line):
            days = _parse_cert_days_remaining(line)
            if days is not None:
                if days < 7:
                    findings.append(_make_tls_finding(
                        target, line, "HIGH",
                        "Certificate expires in <7 days",
                        f"Le certificat expire dans {days} jour(s) — renouvellement urgent.",
                    ))
                elif days < 30:
                    findings.append(_make_tls_finding(
                        target, line, "MEDIUM",
                        "Certificate expires in <30 days",
                        f"Le certificat expire dans {days} jours — planifier le renouvellement.",
                    ))

        # HSTS detection (deduped — testssl prints both an HTTP-headers line
        # and a Grade-capped synthesis line). Note: "offered" is a substring
        # of "not offered", so classify the missing case FIRST.
        if HSTS_LINE_RE.search(line):
            lower = line.lower()
            is_missing = ("not offered" in lower) or ("no hsts" in lower)
            is_offered_no_preload = (
                ("offered" in lower) and (not is_missing) and ("preload" not in lower)
            )
            if is_missing and "missing" not in seen_hsts_kind:
                findings.append(_make_tls_finding(
                    target, line, "HIGH",
                    "HSTS not advertised at TLS layer",
                    "testssl.sh signale HSTS absent — durcir le serveur.",
                ))
                seen_hsts_kind.add("missing")
            elif is_offered_no_preload and "no_preload" not in seen_hsts_kind:
                findings.append(_make_tls_finding(
                    target, line, "LOW",
                    "HSTS without preload",
                    "HSTS sans directive preload — non éligible à la liste Chromium preload.",
                ))
                seen_hsts_kind.add("no_preload")

    return findings


def scan_tls(target: str) -> list[Finding]:
    """Full TLS scan: scope check → testssl.sh → parse."""
    assert_in_scope(target, sprint=2)
    host = normalize_host(target)
    text = run_testssl(host)
    return parse_testssl_text(text, target=host)
