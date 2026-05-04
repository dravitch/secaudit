"""
agents/gemma_critic_agent.py
CriticAgent fallback — Google Gemma 3 27B via le router HuggingFace
(API OpenAI-compatible).

Utilisé automatiquement par agents.factory.FallbackCriticAgent quand
DeepSeek (primaire) échoue ou laisse trop de findings PENDING.

Différences vs HFCriticAgent (DeepSeek) :
- modèle non-raisonnement → pas de extra_body reasoning_effort
- response_format={"type": "json_object"} supporté → activé
- batch un peu plus grand (4) car réponses plus compactes
- max_tokens=1024 suffit
"""
from __future__ import annotations

import json
import os
import warnings
from typing import Optional

from schemas.finding import Finding
from agents.base import BaseAgent
from agents.hf_critic_agent import CRITIC_SYSTEM_PROMPT
from config import settings

GEMMA_BATCH_SIZE = int(os.getenv("FALLBACK_CRITIC_BATCH_SIZE", "4"))
GEMMA_MAX_TOKENS = 1024
HF_BASE_URL = "https://router.huggingface.co/v1"


class GemmaCriticAgent(BaseAgent):
    """Fallback CriticAgent — Gemma 3 27B (non-reasoning)."""

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.0,
    ):
        super().__init__(
            model=model
            or os.getenv("FALLBACK_CRITIC_MODEL", "google/gemma-4-31B-it:novita"),
            temperature=temperature,
        )
        token = settings.require_env("HF_TOKEN")
        import openai

        self._openai = openai
        self._client = openai.OpenAI(base_url=HF_BASE_URL, api_key=token)
        self._total_usage = {"input_tokens": 0, "output_tokens": 0}
        self._last_finish_reason: Optional[str] = None

    def run(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        for start in range(0, len(findings), GEMMA_BATCH_SIZE):
            batch = findings[start : start + GEMMA_BATCH_SIZE]
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
            max_tokens=GEMMA_MAX_TOKENS,
            response_format={"type": "json_object"},
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
                f"GemmaCriticAgent: finish_reason=length (batch={len(batch)}, "
                f"max_tokens={GEMMA_MAX_TOKENS}, output_tokens="
                f"{getattr(usage, 'completion_tokens', '?')}). "
                f"Réponse tronquée — réduire FALLBACK_CRITIC_BATCH_SIZE.",
                RuntimeWarning,
                stacklevel=2,
            )
        self._last_finish_reason = finish_reason
        return self._parse_findings(text)

    def _merge_verdicts(
        self, batch: list[Finding], verdicts: list[Finding]
    ) -> list[Finding]:
        verdict_by_id = {v.id: v for v in verdicts}
        out: list[Finding] = []
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
