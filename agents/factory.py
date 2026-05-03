"""
agents/factory.py
Provider dispatch — choisit l'implémentation concrète selon settings.
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
    if settings.AGENT_PROVIDER_CRITIC == "huggingface":
        from agents.hf_critic_agent import HFCriticAgent

        return HFCriticAgent()
    raise ValueError(
        f"Provider critic inconnu : {settings.AGENT_PROVIDER_CRITIC!r}"
    )
