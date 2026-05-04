"""
agents/deepseek_critic_agent.py
CriticAgent contradictoire — DeepSeek V4 natif (API OpenAI-compatible).
"""
from __future__ import annotations

import json
import os
import warnings
from typing import Optional

import openai
from schemas.finding import Finding
from agents.base import BaseAgent
from config import settings

DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
CRITIC_BATCH_SIZE = int(os.getenv("CRITIC_BATCH_SIZE", "3"))
CRITIC_MAX_TOKENS = int(os.getenv("CRITIC_MAX_TOKENS", "2048"))

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

Verdicts attendus pour les cas connus :
- DMARC p=none → CONFIRMED 0.90
- DNSSEC absent → CONFIRMED 0.88
- HSTS absent → NUANCED 0.70 si WAF Imperva détecté
- Favicon absent + WAF présent → NUANCED 0.55, CONTEXT_DEPENDENT
- Typosquat synthèse "14 variants" → NUANCED 0.65 si l'analyste a mentionné "SPF absent" à tort
- CSP unsafe-inline → CONFIRMED 0.88

Retourne UNIQUEMENT un objet JSON :
{"findings": [{"id": "...", "critic_verdict": "...",
"critic_rationale": "...", "confidence_score": 0.XX, "flags": [...]}, ...]}

Pas de texte avant ou après le JSON. Pas de markdown. Pas de prose.
"""

class DeepSeekCriticAgent(BaseAgent):
    """CriticAgent backed by DeepSeek native API."""

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.0,
    ):
        super().__init__(
            model=model or settings.CRITIC_MODEL,
            temperature=temperature,
        )
        token = settings.require_env("DEEPSEEK_API_KEY")
        self._client = openai.OpenAI(
            base_url=DEEPSEEK_BASE_URL,
            api_key=token,
        )
        self._total_usage = {"input_tokens": 0, "output_tokens": 0}

    def run(self, findings: list[Finding]) -> list[Finding]:
        out = []
        for i in range(0, len(findings), CRITIC_BATCH_SIZE):
            batch = findings[i : i + CRITIC_BATCH_SIZE]
            verdicts = self._call_critic(batch)
            out.extend(self._merge_verdicts(batch, verdicts))
        return out

    def _call_critic(self, batch: list[Finding]) -> list[Finding]:
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
                {"role": "user", "content": "Findings à challenger (JSON brut) :\n\n" + user_payload},
            ],
        )
        choice = response.choices[0]
        text = choice.message.content or ""
        finish_reason = getattr(choice, "finish_reason", None)
        usage = getattr(response, "usage", None)
        if usage:
            self._total_usage["input_tokens"] += usage.prompt_tokens or 0
            self._total_usage["output_tokens"] += usage.completion_tokens or 0
        if finish_reason == "length":
            warnings.warn(
                f"CriticAgent: finish_reason=length (batch={len(batch)}, "
                f"max_tokens={CRITIC_MAX_TOKENS}). "
                f"Réduire CRITIC_BATCH_SIZE si parsing échoue.",
                RuntimeWarning,
            )
        return self._parse_findings(text)

    def _merge_verdicts(
        self, batch: list[Finding], verdicts: list[Finding]
    ) -> list[Finding]:
        verdict_by_id = {v.id: v for v in verdicts}
        out = []
        for f in batch:
            v = verdict_by_id.get(f.id)
            if v is None:
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
