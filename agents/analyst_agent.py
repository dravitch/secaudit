"""
agents/analyst_agent.py
AnalystAgent — interprète les findings bruts via Claude Sonnet (Anthropic).

- Modifie UNIQUEMENT analyst_conclusion (si vide/générique) et cvss_score.
- Ne touche jamais critic_verdict, critic_rationale, confidence_score, flags
  (sauf cas spéciaux ground-truth — Imperva favicon, etc.).
- Traitement par batches de 10 (1 appel API par batch).
- Prompt caching activé (system prompt stable réutilisé entre batches).

Cas spéciaux déterministes appliqués après l'enrichissement LLM :

1. Synthèse "N typosquat variants" → corrige analyst_conclusion :
   "SPF valide. Risque réel = DMARC p=none + DNSSEC absent."
   (Sprint 2 a confirmé SPF présent — éviter le faux raisonnement
    'absence SPF favorise phishing' qu'un LLM peut produire.)

2. Favicon absent + finding WAF Imperva sur la même cible →
   ajoute flag CONTEXT_DEPENDENT et note dans analyst_conclusion.

3. Ground truth manuel telemo.gov.gn (vérifié 2026-05-03) :
   - HSTS confirmé present (preload + includeSubDomains)
   - Certificat valide ~69j (Let's Encrypt E8 → 2026-07-12)
   Les findings 'HSTS not advertised' et 'Certificate expires <30 days'
   sur cette cible sont des artefacts de proxy MITM (sandbox-egress) —
   l'AnalystAgent les SUPPRIME du flux qui ira au CriticAgent.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from schemas.finding import Finding
from agents.base import BaseAgent
from config import settings

ANALYST_BATCH_SIZE = 10
ANALYST_MAX_TOKENS = 8000

ANALYST_SYSTEM_PROMPT = """\
Tu es un analyste de sécurité expert. Tu reçois des données brutes de scan
(JSON) et tu dois produire une analyse structurée.

Règles strictes :
- N'affirme rien sans preuve dans les données (Ground Truth or Silence).
- Chaque conclusion doit citer une evidence spécifique du finding.
- Si les données sont insuffisantes : analyst_conclusion="Données insuffisantes — NEEDS_RETEST".
- N'ajoute pas de score CVSS si tu ne peux pas le justifier.

Format de sortie : tableau JSON d'objets {id, analyst_conclusion, cvss_score}.
Aucun autre champ. Pas de markdown, pas de prose, uniquement JSON.

Exemple :
[
  {"id": "abc-123", "analyst_conclusion": "Header CSP absent — risque XSS confirmé.", "cvss_score": 6.1},
  {"id": "def-456", "analyst_conclusion": "Données insuffisantes — NEEDS_RETEST", "cvss_score": null}
]
"""

# ── Ground truth manuel (sources externes vérifiées) ────────────────────
# Override per-target. Used by _apply_known_corrections to suppress findings
# whose root cause is a vantage-point artefact (e.g., TLS-inspection proxy
# between the scanner and the target, breaking HSTS / cert observability).
KNOWN_GROUND_TRUTH: dict[str, dict] = {
    "telemo.gov.gn": {
        "verified_on": "2026-05-03",
        "hsts": {"present": True, "include_subdomains": True, "preload": True},
        "certificate": {"days_remaining": 69, "issuer": "Let's Encrypt E8"},
        "tls_protocols": {"1.0": False, "1.1": False, "1.2": True, "1.3": True},
    }
}

SUPPRESS_TITLES_TELEMO = {
    "HSTS header missing",
    "HSTS not advertised at TLS layer",
    "Certificate expires in <30 days",
    "Certificate expires in <7 days",
}


class AnthropicAnalystAgent(BaseAgent):
    """AnalystAgent backed by Anthropic Claude Sonnet."""

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 1.0,
    ):
        super().__init__(model=model or settings.ANALYST_MODEL, temperature=temperature)
        # Force the env-var check so missing keys fail fast at instantiation.
        settings.require_env("ANTHROPIC_API_KEY")
        # Defer SDK import so tests can patch agents.analyst_agent.anthropic.
        import anthropic

        self._anthropic = anthropic
        self._client = anthropic.Anthropic()

    # ── Public API ──────────────────────────────────────────────────────

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Enrich findings: LLM batch, then deterministic ground-truth corrections."""
        enriched = list(findings)
        for start in range(0, len(enriched), ANALYST_BATCH_SIZE):
            batch = enriched[start : start + ANALYST_BATCH_SIZE]
            updates = self._call_anthropic(batch)
            self._apply_updates(batch, updates)
        self._apply_special_cases(enriched)
        return self._apply_known_corrections(enriched)

    # ── LLM call (one API request per batch, prompt caching enabled) ────

    def _call_anthropic(self, batch: list[Finding]) -> list[dict]:
        """Call Claude with prompt caching on the system prompt."""
        user_payload = json.dumps(
            [json.loads(f.model_dump_json()) for f in batch],
            ensure_ascii=False,
        )
        response = self._client.messages.create(
            model=self.model,
            max_tokens=ANALYST_MAX_TOKENS,
            system=[
                {
                    "type": "text",
                    "text": ANALYST_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Findings à enrichir (JSON brut) :\n\n" + user_payload
                    ),
                }
            ],
        )
        text_blocks = [
            getattr(b, "text", "") for b in response.content
            if getattr(b, "type", None) == "text"
        ]
        return self._parse_updates("".join(text_blocks))

    # ── Update merging (only analyst_conclusion + cvss_score) ───────────

    @staticmethod
    def _is_generic_conclusion(text: str) -> bool:
        """A scanner-emitted conclusion that just echoes the description is
        considered generic; the analyst is allowed to overwrite it."""
        if not text:
            return True
        stripped = text.strip()
        return len(stripped) < 12 or stripped.lower().startswith("(no ")

    def _apply_updates(self, batch: list[Finding], updates: list[dict]) -> None:
        by_id = {u.get("id"): u for u in updates if isinstance(u, dict)}
        for f in batch:
            u = by_id.get(f.id)
            if not u:
                continue
            new_conclusion = u.get("analyst_conclusion")
            if new_conclusion and (
                self._is_generic_conclusion(f.analyst_conclusion)
                or f.analyst_conclusion == f.finding
            ):
                f.analyst_conclusion = new_conclusion
            new_cvss = u.get("cvss_score")
            if new_cvss is not None and f.cvss_score is None:
                try:
                    val = float(new_cvss)
                    if 0.0 <= val <= 10.0:
                        f.cvss_score = val
                except (TypeError, ValueError):
                    pass

    # ── Deterministic special cases ─────────────────────────────────────

    @staticmethod
    def _apply_special_cases(findings: list[Finding]) -> None:
        # 1. Typosquat synthesis — correct any LLM hallucination about SPF.
        for f in findings:
            if (
                "typosquat variants" in f.title.lower()
                and "phishing delivery surface" in f.title.lower()
            ):
                f.analyst_conclusion = (
                    "SPF valide. Risque réel = DMARC p=none "
                    "(politique publiée sans effet) + DNSSEC absent."
                )

        # 2. Favicon absent + Imperva WAF in same target → CONTEXT_DEPENDENT.
        targets_with_waf = {
            f.target for f in findings
            if "Imperva" in f.title or "Incapsula" in f.title
        }
        for f in findings:
            if f.title == "Favicon absent" and f.target in targets_with_waf:
                if "CONTEXT_DEPENDENT" not in f.flags:
                    f.flags.append("CONTEXT_DEPENDENT")
                f.analyst_conclusion = (
                    "Favicon possiblement bloqué par WAF Imperva — absence "
                    "non confirmée en amont du WAF."
                )

    # ── Ground-truth suppression (manual verification overrides) ────────

    @staticmethod
    def _apply_known_corrections(findings: list[Finding]) -> list[Finding]:
        """Drop findings that are vantage-point artefacts on targets where
        ground truth has been independently verified."""
        out: list[Finding] = []
        for f in findings:
            tgt = f.target.lower()
            has_ground_truth = any(h in tgt for h in KNOWN_GROUND_TRUTH)
            if has_ground_truth and f.title in SUPPRESS_TITLES_TELEMO:
                continue
            out.append(f)
        return out
