"""
agents/factory.py
Provider dispatch — choisit l'implémentation concrète selon settings.

Pour le critic, on enveloppe DeepSeek (primaire) dans un FallbackCriticAgent
qui bascule automatiquement sur Gemma 3 27B si :
- DeepSeek lève une exception (souvent ValueError sur JSON tronqué quand
  reasoning_effort=disabled n'est pas honoré par le provider downstream)
- ou plus de 30 % des findings restent PENDING après le run primaire.
"""
from __future__ import annotations

import warnings

from agents.base import BaseAgent
from config import settings
from schemas.finding import Finding


PENDING_FALLBACK_RATIO = 0.30


def create_analyst() -> BaseAgent:
    if settings.AGENT_PROVIDER_ANALYST == "anthropic":
        from agents.analyst_agent import AnthropicAnalystAgent

        return AnthropicAnalystAgent()
    raise ValueError(
        f"Provider analyst inconnu : {settings.AGENT_PROVIDER_ANALYST!r}"
    )


def create_critic() -> BaseAgent:
    if settings.AGENT_PROVIDER_CRITIC == "huggingface":
        from agents.hf_critic_agent import HFCriticAgent
        from agents.gemma_critic_agent import GemmaCriticAgent

        primary = HFCriticAgent()
        return FallbackCriticAgent(primary=primary, fallback_factory=GemmaCriticAgent)
    raise ValueError(
        f"Provider critic inconnu : {settings.AGENT_PROVIDER_CRITIC!r}"
    )


class FallbackCriticAgent(BaseAgent):
    """Wrap a primary CriticAgent and fall back on a secondary one on failure.

    Failure modes that trigger fallback :
    - primary.run() raises any Exception (ValueError on truncated JSON,
      RateLimitError, transient network errors…)
    - primary returns OK but >30 % of findings are still PENDING (means
      the model returned an empty/partial verdict array)
    """

    def __init__(self, primary: BaseAgent, fallback_factory):
        # Skip BaseAgent.__init__ — we don't own the model/temperature directly.
        self._primary = primary
        self._fallback_factory = fallback_factory
        self._used_fallback = False
        self._total_usage = {"input_tokens": 0, "output_tokens": 0}

    @property
    def model(self) -> str:
        return self._primary.model

    @property
    def temperature(self) -> float:
        return getattr(self._primary, "temperature", 0.0)

    def run(self, findings: list[Finding]) -> list[Finding]:
        if not findings:
            return findings
        try:
            result = self._primary.run(findings)
            pending = sum(1 for f in result if f.critic_verdict == "PENDING")
            if pending / max(len(findings), 1) > PENDING_FALLBACK_RATIO:
                raise RuntimeError(
                    f"Primary critic left {pending}/{len(findings)} findings PENDING "
                    f"(> {PENDING_FALLBACK_RATIO * 100:.0f} %)"
                )
            self._merge_usage(self._primary)
            return result
        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"Primary CriticAgent ({getattr(self._primary, 'model', '?')}) "
                f"failed: {type(exc).__name__}: {exc}. "
                f"Falling back to secondary critic.",
                RuntimeWarning,
                stacklevel=2,
            )
            self._used_fallback = True
            self._merge_usage(self._primary)
            fallback = self._fallback_factory()
            result = fallback.run(findings)
            self._merge_usage(fallback)
            return result

    def _merge_usage(self, agent: BaseAgent) -> None:
        usage = getattr(agent, "_total_usage", None)
        if not usage:
            return
        for key in ("input_tokens", "output_tokens"):
            self._total_usage[key] += int(usage.get(key, 0) or 0)
