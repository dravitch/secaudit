"""
agents/classifier.py
Logique de barrière : classifie un Finding dans la section du rapport
finale (CLAUDE.md §11).
"""
from __future__ import annotations

from schemas.finding import Finding
from config import settings


def classify_finding(f: Finding) -> str:
    """Return the report section a finding belongs to.

    - REJECTED                                 → findings_rejected
    - PENDING                                  → findings_pending
    - CONFIRMED & confidence >= 0.75            → findings_confirmed
    - NUANCED, or 0.50 ≤ confidence < 0.75     → findings_investigate
    - everything else                          → findings_rejected
    """
    if f.critic_verdict == "REJECTED":
        return "findings_rejected"
    if f.critic_verdict == "PENDING":
        return "findings_pending"
    if (
        f.critic_verdict == "CONFIRMED"
        and f.confidence_score >= settings.CONFIDENCE_THRESHOLD_CONFIRM
    ):
        return "findings_confirmed"
    if (
        f.critic_verdict == "NUANCED"
        or f.confidence_score >= settings.CONFIDENCE_THRESHOLD_INVESTIGATE
    ):
        return "findings_investigate"
    return "findings_rejected"
