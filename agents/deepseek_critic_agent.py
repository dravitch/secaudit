"""
agents/deepseek_critic_agent.py
CriticAgent contradictoire — DeepSeek V4 (deepseek-chat) via l'API native
api.deepseek.com (OpenAI-compatible).

Pourquoi l'API native plutôt que le router HF :
- Le router HF + Novita rejette extra_body={"reasoning_effort": "disabled"}
  (BadRequest 400). DeepSeek consomme alors ses tokens de sortie en
  raisonnement → finish_reason=length, content tronqué.
- L'API native gère reasoning_effort par défaut sur deepseek-chat ;
  finish_reason=stop fiable, pas de troncature sur batches ≤ 3.

Contraintes :
- temperature=0 (déterministe, reproductible)
- BATCH_SIZE / MAX_TOKENS pilotables via .env (CRITIC_BATCH_SIZE,
  CRITIC_MAX_TOKENS) — défauts : 3 et 2048.
- EnvironmentError si DEEPSEEK_API_KEY absent.
"""
from __future__ import annotations

import json
import warnings
from typing import Optional

from schemas.finding import Finding
from agents.base import BaseAgent
from config import settings

DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"

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

Retourne UNIQUEMENT un objet JSON :
{"findings": [{"id": "...", "critic_verdict": "...",
"critic_rationale": "...", "confidence_score": 0.XX, "flags": [...]}, ...]}

Pas de texte avant ou après le JSON. Pas de markdown. Pas de prose.
"""


class DeepSeekCriticAgent(BaseAgent):
    """CriticAgent backed by the native DeepSeek API (deepseek-chat)."""

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ):
        super().__init__(
            model=model or settings.CRITIC_MODEL,
            temperature=temperature if temperature is not None else settings.CRITIC_TEMPERATURE,
        )
        token = settings.require_env("DEEPSEEK_API_KEY")
        # Defer SDK import so tests can patch agents.deepseek_critic_agent.openai.
        import openai

        self._openai = openai
        self._client = openai.OpenAI(
            base_url=DEEPSEEK_BASE_URL,
            api_key=token,
        )
        self._total_usage = {"input_tokens": 0, "output_tokens": 0}
        self._last_finish_reason: Optional[str] = None

    # ── Public API ──────────────────────────────────────────────────────

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Send findings to the critic in batches; merge verdict updates back."""
        out: list[Finding] = []
        for start in range(0, len(findings), settings.CRITIC_BATCH_SIZE):
            batch = findings[start : start + settings.CRITIC_BATCH_SIZE]
            verdicts = self._call_critic(batch)
            out.extend(self._merge_verdicts(batch, verdicts))
        return out

    # ── LLM call ────────────────────────────────────────────────────────

    def _call_critic(self, batch: list[Finding]) -> list[Finding]:
        """Call DeepSeek native API and extract verdict-only Finding stubs.

        DeepSeek returns ONLY the verdict fields per the prompt
        ({id, critic_verdict, critic_rationale, confidence_score, flags}),
        so we cannot use Finding(**item) — Pydantic would reject it for
        missing required fields (sprint, tool, target, title, finding,
        severity). We use Finding.model_construct() to build verdict stubs
        that bypass validation; _merge_verdicts then copies the verdict
        fields onto the original (fully validated) input findings.
        """
        user_payload = json.dumps(
            [json.loads(f.model_dump_json()) for f in batch],
            ensure_ascii=False,
        )
        response = self._client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=settings.CRITIC_MAX_TOKENS,
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
                f"DeepSeekCriticAgent: finish_reason=length "
                f"(batch={len(batch)}, max_tokens={settings.CRITIC_MAX_TOKENS}, "
                f"output_tokens={getattr(usage, 'completion_tokens', '?')}). "
                f"Réponse tronquée — réduire CRITIC_BATCH_SIZE si parsing échoue.",
                RuntimeWarning,
                stacklevel=2,
            )
        self._last_finish_reason = finish_reason

        return self._parse_verdict_stubs(text)

    def _parse_verdict_stubs(self, text: str) -> list[Finding]:
        """Parse a verdict-only JSON payload into Finding stubs.

        Accepts either {"findings": [...]} or a bare list. Each item must
        carry at least an `id` — items missing the id are dropped. Truncated
        arrays are recovered by BaseAgent._recover_truncated_json so that a
        partially-streamed batch still updates the verdicts that did arrive.
        """
        cleaned = self._strip_code_fence(text)
        if not cleaned.strip():
            raise ValueError(
                "DeepSeekCriticAgent: empty content (likely max_tokens=0 or upstream filter)"
            )
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            recovered = self._recover_truncated_json(cleaned)
            if recovered is None:
                raise ValueError(
                    f"DeepSeekCriticAgent: réponse JSON invalide "
                    f"({exc.msg} at pos {exc.pos}). Texte brut : {cleaned[:200]!r}"
                ) from exc
            data = recovered

        if isinstance(data, dict):
            data = data.get("findings", [data])

        verdicts: list[Finding] = []
        for item in data:
            if not isinstance(item, dict) or "id" not in item:
                continue
            try:
                score = float(item.get("confidence_score", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            verdicts.append(
                Finding.model_construct(
                    id=item["id"],
                    critic_verdict=item.get("critic_verdict", "PENDING"),
                    critic_rationale=item.get("critic_rationale", ""),
                    confidence_score=score,
                    flags=list(item.get("flags") or []),
                )
            )
        return verdicts

    # ── Verdict merging ─────────────────────────────────────────────────

    def _merge_verdicts(
        self, batch: list[Finding], verdicts: list[Finding]
    ) -> list[Finding]:
        """Merge critic verdict fields onto the original findings.

        Source of truth for non-critic_* fields = the input batch (never
        trust the LLM to faithfully echo every original field).
        """
        verdict_by_id = {v.id: v for v in verdicts}
        out: list[Finding] = []
        for f in batch:
            v = verdict_by_id.get(f.id)
            if v is None:
                # Critic returned no verdict for this finding — leave PENDING.
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
