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
AGENT_PROVIDER_CRITIC = os.getenv("AGENT_PROVIDER_CRITIC", "huggingface")

# ── Model identifiers ────────────────────────────────────────────────
ANALYST_MODEL = os.getenv("ANALYST_MODEL", "claude-sonnet-4-5")
CRITIC_MODEL = os.getenv("CRITIC_MODEL", "deepseek-ai/DeepSeek-V4-Pro:novita")

# ── Critic determinism ───────────────────────────────────────────────
CRITIC_TEMPERATURE = float(os.getenv("CRITIC_TEMPERATURE", "0"))

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
