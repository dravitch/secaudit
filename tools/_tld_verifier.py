"""
tools/_tld_verifier.py
Multi-source TLD restriction verifier — adversarial cross-check.

Une seule source (WhoisFreaks scrape HTML) s'est révélée non fiable :
gov.gn → False alors que gouv.gn → True dans le même run, alors que
les deux sont restreints. Ce module corrige en interrogeant trois
sources indépendantes et en exigeant un consensus ≥ 2/3 avant de
considérer un TLD comme RESTRICTED.

Sources :
  1. IANA — https://www.iana.org/domains/root/db/<tld>.html
     Pour les ccTLD (1 label) : scrape "restricted" / "sponsored TLD".
     Pour les 2nd-level (gov.<cc>, gouv.<cc>, mil.<cc>, edu.<cc>, ac.<cc>,
     police.<cc>, army.<cc>) : règle ICANN/IANA standard — ces labels sont
     universellement réservés par les registres ccTLD.
  2. WhoisFreaks — https://whoisfreaks.com/tools/whois/lookup/<tld>
     Scrape "Restricted Domain" dans le HTML.
  3. DNS SOA — `dig +short SOA <tld>`
     Heuristique : le SOA mname d'un TLD restreint contient des tokens
     gouvernementaux (gov., gouv., mil., ministry, …).

Verdict :
  - votes_available < 2          → UNKNOWN  (une source seule n'est pas fiable)
  - votes_restricted/avail ≥ 2/3 → RESTRICTED
  - votes_restricted/avail ≥ 1/3 → UNKNOWN
  - sinon                        → FREE

UNKNOWN signifie "on ne sait pas" — l'appelant choisit la politique :
phishing_surface.py inclut les variantes (false negative préféré au
false positive pour un audit).

Cache mémoire par TLD : un même TLD ne déclenche les 3 sources qu'une
seule fois par process.
"""
from __future__ import annotations

import logging
import subprocess
import warnings
from typing import Callable, Optional

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "secaudit/0.1 (+passive)"
SOURCE_TIMEOUT_SEC = 5.0
DNS_TIMEOUT_SEC = 3.0

# Universally reserved 2nd-level labels under ccTLDs (ICANN registry policy).
KNOWN_GOV_LABELS: frozenset[str] = frozenset({
    "gov", "gouv", "mil", "edu", "ac", "police", "army",
})

# Heuristic markers that a SOA mname is run by a government registry.
GOV_SOA_TOKENS: tuple[str, ...] = (
    "gov.", "gouv.", "mil.", "ministry", "ministr", "presidence",
    "minfra", "minfin", "minister",
)


# ── Source 1 — IANA ──────────────────────────────────────────────────


def _check_iana(tld: str) -> Optional[bool]:
    """Source 1: IANA root zone DB.

    For ccTLDs (single label, e.g. 'gn'): GET the IANA root zone HTML
    page and look for "restricted" or "sponsored TLD" markers.

    For 2nd-level TLDs (e.g. 'gov.gn'): apply the universal ICANN-policy
    rule that governmental labels (gov/gouv/mil/edu/ac/...) are reserved
    across all ccTLDs that follow standard registry policy. This is
    deterministic and doesn't require IANA to maintain per-country
    second-level reservation lists.
    """
    parts = tld.lstrip(".").split(".")
    if not parts or not parts[0]:
        return None

    # 2nd-level: governmental label rule.
    if len(parts) >= 2:
        if parts[0].lower() in KNOWN_GOV_LABELS:
            return True
        return None  # IANA cannot speak for non-governmental 2nd-levels.

    # 1st-level: scrape IANA root zone DB.
    base_tld = parts[0].lower()
    url = f"https://www.iana.org/domains/root/db/{base_tld}.html"
    try:
        with httpx.Client(timeout=SOURCE_TIMEOUT_SEC, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": USER_AGENT})
    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.debug("IANA lookup failed for %s: %s", tld, exc)
        return None
    if resp.status_code != 200:
        return None
    body = (resp.text or "").lower()
    if "page not found" in body or "not found" in body[:500]:
        return None
    if "this tld is sponsored" in body or "sponsored tld" in body:
        return True
    if "restricted" in body or "this domain is reserved" in body:
        return True
    return False


# ── Source 2 — WhoisFreaks ───────────────────────────────────────────


def _check_whoisfreaks(tld: str) -> Optional[bool]:
    """Source 2: WhoisFreaks HTML scrape.

    Returns None on network/timeout errors (NOT False) so that a flaky
    network doesn't poison the consensus tally.
    """
    key = tld.lstrip(".")
    url = f"https://whoisfreaks.com/tools/whois/lookup/{key}"
    try:
        with httpx.Client(timeout=SOURCE_TIMEOUT_SEC, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": USER_AGENT})
    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.debug("WhoisFreaks lookup failed for %s: %s", tld, exc)
        return None
    if resp.status_code != 200:
        return None
    body = (resp.text or "").lower()
    if "restricted domain" in body or "restricted tld" in body:
        return True
    return False


# ── Source 3 — DNS SOA heuristic ─────────────────────────────────────


def _check_dns_soa(tld: str) -> Optional[bool]:
    """Source 3: dig SOA <tld> and inspect the mname for governmental tokens.

    Restricted 2nd-level TLDs (gov.<cc>) typically have their SOA hosted on
    a government registry whose mname contains 'gov.', 'ministry', etc.

    Top-level TLDs (single label like 'gn') are excluded from this check :
    a ccTLD's root SOA may be hosted by ANY operator (often a national NIC
    that itself sits under a .gov subdomain) without implying the TLD is
    restricted. Live observation: dig SOA gn returns nameservers under
    nic.gov.* → matched 'gov.' → false positive RESTRICTED on .gn.
    """
    key = tld.lstrip(".")
    if "." not in key:
        # Top-level TLD — SOA mname is not a reliable restriction signal.
        return None
    try:
        result = subprocess.run(
            ["dig", "+short", "SOA", key],
            capture_output=True, text=True, timeout=DNS_TIMEOUT_SEC,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.debug("dig SOA lookup failed for %s: %s", tld, exc)
        return None
    if result.returncode != 0:
        return None
    out = (result.stdout or "").strip().lower()
    if not out:
        return None  # no SOA record — indeterminate
    if any(tok in out for tok in GOV_SOA_TOKENS):
        return True
    return False


# ── Verdict logic — weighted consensus ───────────────────────────────


# IANA carries weight 2 because for known governmental 2nd-level labels
# (gov/gouv/mil/edu/...) it returns True via a deterministic ICANN-policy
# rule, not a scrape. WhoisFreaks and DNS SOA each scrape/heuristic-check
# a single endpoint, so they get weight 1.
SOURCE_WEIGHTS: dict[str, int] = {"iana": 2, "whoisfreaks": 1, "dns_soa": 1}

# Confidence thresholds (weighted score_for / score_total).
THRESHOLD_RESTRICTED = 0.60
THRESHOLD_UNKNOWN = 0.30


def _consensus(sources: dict[str, Optional[bool]]) -> tuple[str, float, int, int]:
    """Compute (verdict, confidence, votes_restricted, votes_available).

    Voting is weighted by SOURCE_WEIGHTS — IANA's deterministic ICANN-policy
    rule for known governmental 2nd-levels carries weight 2; the other
    heuristic sources carry weight 1 each. With at least 2 sources reachable
    (the single-source-bias guard), the rules are :

      - score_for / total ≥ 0.60 → RESTRICTED
      - score_for / total ≥ 0.30 → UNKNOWN
      - else                     → FREE

    `votes_restricted` and `votes_available` are unweighted counts kept for
    display in the verdict dict.
    """
    votes_restricted = sum(1 for v in sources.values() if v is True)
    votes_available = sum(1 for v in sources.values() if v is not None)
    if votes_available < 2:
        return "UNKNOWN", 0.0, votes_restricted, votes_available

    score_for = sum(
        SOURCE_WEIGHTS.get(name, 1) for name, v in sources.items() if v is True
    )
    score_against = sum(
        SOURCE_WEIGHTS.get(name, 1) for name, v in sources.items() if v is False
    )
    total = score_for + score_against
    if total == 0:
        return "UNKNOWN", 0.0, votes_restricted, votes_available

    confidence = score_for / total
    if confidence >= THRESHOLD_RESTRICTED:
        verdict = "RESTRICTED"
    elif confidence >= THRESHOLD_UNKNOWN:
        verdict = "UNKNOWN"
    else:
        verdict = "FREE"
    return verdict, confidence, votes_restricted, votes_available


# ── Public verifier ──────────────────────────────────────────────────


class TLDVerifier:
    """Adversarial multi-source TLD restriction verifier with caching.

    Tests can inject custom source callables via the constructor to bypass
    the network entirely.
    """

    def __init__(
        self,
        *,
        iana: Callable[[str], Optional[bool]] = _check_iana,
        whoisfreaks: Callable[[str], Optional[bool]] = _check_whoisfreaks,
        dns_soa: Callable[[str], Optional[bool]] = _check_dns_soa,
    ):
        self._iana = iana
        self._whoisfreaks = whoisfreaks
        self._dns_soa = dns_soa
        self._cache: dict[str, dict] = {}

    def check(self, tld: str) -> dict:
        """Return the full verdict dict for `tld` (cached)."""
        key = tld.lstrip(".").lower()
        if key in self._cache:
            return self._cache[key]

        sources = {
            "iana": _safe(self._iana, key),
            "whoisfreaks": _safe(self._whoisfreaks, key),
            "dns_soa": _safe(self._dns_soa, key),
        }
        verdict, confidence, votes_restricted, votes_available = _consensus(sources)

        result = {
            "tld": key,
            "sources": sources,
            "votes_restricted": votes_restricted,
            "votes_available": votes_available,
            "verdict": verdict,
            "confidence": round(confidence, 3),
        }
        self._cache[key] = result
        return result


def _safe(fn: Callable[[str], Optional[bool]], tld: str) -> Optional[bool]:
    """Wrap a source callable so any exception becomes None (indeterminate)."""
    try:
        return fn(tld)
    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"TLD source {fn.__name__!r} raised {type(exc).__name__}: {exc}; "
            f"treating as indeterminate.",
            RuntimeWarning, stacklevel=2,
        )
        return None
