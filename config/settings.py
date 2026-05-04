"""
config/settings.py
Lecture des variables d'environnement (.env via python-dotenv).

Mindset 8 — No Hidden State : aucune valeur par défaut silencieuse pour
les API keys. EnvironmentError explicite à l'instanciation de l'agent
correspondant si la clé est absente.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    # python-dotenv optional — env vars may already be in the environment.
    pass


# ── Provider selection ───────────────────────────────────────────────
AGENT_PROVIDER_ANALYST = os.getenv("AGENT_PROVIDER_ANALYST", "anthropic")
# `deepseek` (native API) by default. `huggingface` is no longer wired up
# (HF Router/Novita rejected reasoning_effort + truncated payloads in production).
AGENT_PROVIDER_CRITIC = os.getenv("AGENT_PROVIDER_CRITIC", "deepseek")

# ── Model identifiers ────────────────────────────────────────────────
ANALYST_MODEL = os.getenv("ANALYST_MODEL", "claude-sonnet-4-5")
CRITIC_MODEL = os.getenv("CRITIC_MODEL", "deepseek-chat")

# ── Critic determinism ───────────────────────────────────────────────
CRITIC_TEMPERATURE = float(os.getenv("CRITIC_TEMPERATURE", "0"))
CRITIC_BATCH_SIZE = int(os.getenv("CRITIC_BATCH_SIZE", "3"))
CRITIC_MAX_TOKENS = int(os.getenv("CRITIC_MAX_TOKENS", "2048"))

# ── Confidence thresholds (used by classify_finding) ─────────────────
CONFIDENCE_THRESHOLD_CONFIRM = float(os.getenv("CONFIDENCE_THRESHOLD_CONFIRM", "0.75"))
CONFIDENCE_THRESHOLD_INVESTIGATE = float(os.getenv("CONFIDENCE_THRESHOLD_INVESTIGATE", "0.50"))


def require_env(var: str) -> str:
    """Read an env var or raise EnvironmentError. No silent fallback."""
    value = os.getenv(var)
    if not value:
        raise EnvironmentError(
            f"Required environment variable {var!r} is not set. "
            f"Add it to .env (see .env.example)."
        )
    return value
