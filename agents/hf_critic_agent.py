"""
agents/hf_critic_agent.py
CriticAgent contradictoire — DeepSeek V4 Pro via le router HuggingFace
(API OpenAI-compatible).

Architecture multi-fournisseurs : éviter la chambre d'écho en utilisant
un modèle entraîné par un fournisseur indépendant de l'analyste Anthropic.

⚠ DeepSeek V4 Pro est un modèle à raisonnement. Le provider Novita ne
supporte pas extra_body={"reasoning_effort": "disabled"} (BadRequest
400 sur le router HF). Stratégie de mitigation effective :
- BATCH_SIZE = 1 (un seul finding par appel → marge maximale de tokens)
- max_tokens = 2048
- FallbackCriticAgent enveloppe l'agent : bascule sur Gemma 4 31B
  (modèle non-raisonnement) si DeepSeek tronque ou laisse trop de PENDING.

Contraintes :
- temperature=0 (déterministe, reproductible)
- PAS de response_format=json_object (certains providers HF Router le
  rejettent) — instruction textuelle dans le prompt à la place
- Traitement finding-par-finding (BATCH_SIZE=1)
- EnvironmentError si HF_TOKEN absent
"""
from __future__ import annotations

import json
import os
import warnings
from typing import Optional

from schemas.finding import Finding
from agents.base import BaseAgent
from config import settings

CRITIC_BATCH_SIZE = 1
CRITIC_MAX_TOKENS = 2048
HF_BASE_URL = "https://router.huggingface.co/v1"

CRITIC_SYSTEM_PROMPT = """\
Tu es un agent contradictoire. Tu reçois des findings produits par un
analyste de sécurité et tu dois les challenger avec rigueur.

Pour chaque finding :
1. Vérifie que l'evidence citée supporte réellement la conclusion.
2. Identifie les variables confondantes (VPN, CDN, WAF, contexte réseau).
3. Attribue un confidence_score entre 0.0 et 1.0.
4. Retourne un verdict : CONFIRMED / NUANCED / REJECTED.

Règles strictes :
- Ne jamais retourner CONFIRMED sans citer une vérification indépendante.
- Réfute ou nuance au minimum 20% des findings — un accord total est suspect.
- Signale tout contexte manquant avec le flag CONTEXT_DEPENDENT.
- Si une conclusion cite une preuve incorrecte, corrige dans critic_rationale.
- temperature=0 : sois déterministe et reproductible.

Verdicts attendus pour les cas connus :
- DMARC p=none → CONFIRMED 0.90 (vérifiable par dig indépendant)
- DNSSEC absent → CONFIRMED 0.88
- HSTS absent → NUANCED 0.70 si WAF Imperva détecté (peut être défini
  en amont du WAF)
- Favicon absent + WAF présent → NUANCED 0.55, CONTEXT_DEPENDENT
- Typosquat synthèse "14 variants" → NUANCED 0.65 si analyst_conclusion
  mentionnait "SPF absent" à tort (SPF est valide — corriger)
- Typosquat variants individuels → CONFIRMED 0.85
- CSP unsafe-inline → CONFIRMED 0.88
- Cookie SameSite absent → CONFIRMED 0.80

Retourne UNIQUEMENT un objet JSON {"findings": [<Finding>, ...]} où chaque
Finding inclut TOUS les champs originaux du schéma + critic_verdict,
critic_rationale, confidence_score, flags mis à jour.

Exemple de sortie attendue (format strict) :
{"findings": [
  {"id": "abc-123", "critic_verdict": "CONFIRMED",
   "critic_rationale": "Evidence dig TXT confirme l'absence de DMARC.",
   "confidence_score": 0.90, "flags": []}
]}

Pas de texte avant ou après le JSON. Pas de markdown. Pas de prose.
"""


class HFCriticAgent(BaseAgent):
    """CriticAgent backed by HF router → DeepSeek V4 Pro:novita."""

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.0,
    ):
        super().__init__(
            model=model or settings.CRITIC_MODEL,
            temperature=temperature,
        )
        # Force the env-var check.
        token = settings.require_env("HF_TOKEN")
        # Defer SDK import so tests can patch agents.hf_critic_agent.openai.
        import openai

        self._openai = openai
        self._client = openai.OpenAI(
            base_url=HF_BASE_URL,
            api_key=token,
        )
        self._total_usage = {"input_tokens": 0, "output_tokens": 0}

    # ── Public API ──────────────────────────────────────────────────────

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Send findings to the critic in batches; merge verdict updates back."""
        out: list[Finding] = []
        for start in range(0, len(findings), CRITIC_BATCH_SIZE):
            batch = findings[start : start + CRITIC_BATCH_SIZE]
            verdicts = self._call_critic(batch)
            out.extend(self._merge_verdicts(batch, verdicts))
        return out

    # ── LLM call ────────────────────────────────────────────────────────

    def _call_critic(self, batch: list[Finding]) -> list[Finding]:
        """Call DeepSeek via HF router and parse the response."""
        user_payload = json.dumps(
            [json.loads(f.model_dump_json()) for f in batch],
            ensure_ascii=False,
        )
        response = self._client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=CRITIC_MAX_TOKENS,
            messages=[
                {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Findings à challenger (JSON brut) :\n\n" + user_payload
                    ),
                },
            ],
        )
        choice = response.choices[0]
        text = choice.message.content or ""
        finish_reason = getattr(choice, "finish_reason", None)
        usage = getattr(response, "usage", None)
        if usage is not None:
            self._total_usage["input_tokens"] += int(
                getattr(usage, "prompt_tokens", 0) or 0
            )
            self._total_usage["output_tokens"] += int(
                getattr(usage, "completion_tokens", 0) or 0
            )
        if finish_reason == "length":
            warnings.warn(
                f"CriticAgent: finish_reason=length (batch={len(batch)}, "
                f"max_tokens={CRITIC_MAX_TOKENS}, output_tokens="
                f"{getattr(usage, 'completion_tokens', '?')}). "
                f"Réponse tronquée — réduire CRITIC_BATCH_SIZE si parsing échoue.",
                RuntimeWarning,
                stacklevel=2,
            )
            self._last_finish_reason = "length"
        else:
            self._last_finish_reason = finish_reason
        return self._parse_findings(text)

    # ── Verdict merging ─────────────────────────────────────────────────

    def _merge_verdicts(
        self, batch: list[Finding], verdicts: list[Finding]
    ) -> list[Finding]:
        """Merge critic verdict fields onto the original findings.

        We never trust the LLM to faithfully echo every original field, so
        we keep the input findings as the source of truth and copy ONLY the
        critic_* fields and additive flags from the LLM response.
        """
        verdict_by_id = {v.id: v for v in verdicts}
        out: list[Finding] = []
        for f in batch:
            v = verdict_by_id.get(f.id)
            if v is None:
                # Critic didn't return a verdict for this finding — leave PENDING.
                out.append(f)
                continue
            f.critic_verdict = v.critic_verdict
            f.critic_rationale = v.critic_rationale
            f.confidence_score = max(0.0, min(1.0, v.confidence_score))
            for flag in v.flags:
                if flag not in f.flags:
                    f.flags.append(flag)
            out.append(f)
        return out
