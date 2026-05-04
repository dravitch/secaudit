"""
agents/factory.py
Provider dispatch — choisit l'implémentation concrète selon settings.

Critic providers supportés :
- "deepseek"     → DeepSeekCriticAgent (API native deepseek.com, défaut)

Note historique :
- "huggingface"  → HFCriticAgent + Gemma fallback ont été retirés après
  des troncatures systématiques sur le router HF/Novita (DeepSeek est
  un modèle à raisonnement, et Novita rejette extra_body
  reasoning_effort=disabled). L'API DeepSeek native expose
  reasoning_effort par défaut sur deepseek-chat.
"""
from __future__ import annotations

from agents.base import BaseAgent
from config import settings


def create_analyst() -> BaseAgent:
    if settings.AGENT_PROVIDER_ANALYST == "anthropic":
        from agents.analyst_agent import AnthropicAnalystAgent

        return AnthropicAnalystAgent()
    raise ValueError(
        f"Provider analyst inconnu : {settings.AGENT_PROVIDER_ANALYST!r}"
    )


def create_critic() -> BaseAgent:
    if settings.AGENT_PROVIDER_CRITIC == "deepseek":
        from agents.deepseek_critic_agent import DeepSeekCriticAgent

        return DeepSeekCriticAgent()
    raise ValueError(
        f"Provider critic inconnu : {settings.AGENT_PROVIDER_CRITIC!r}. "
        f"Valeurs supportées : 'deepseek'."
    )
