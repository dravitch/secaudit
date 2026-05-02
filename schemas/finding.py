"""
schemas/finding.py
Contrat API central — tout agent produit et consomme ce schéma.
"""
from pydantic import BaseModel, Field
from typing import Literal, Optional
from datetime import datetime


class Finding(BaseModel):
    # Identité
    id: str = Field(..., description="UUID du finding")
    sprint: int = Field(..., ge=1, le=5)
    tool: str
    target: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Description
    title: str
    finding: str = Field(..., description="Description brute du résultat")
    evidence: list[str] = Field(default_factory=list, description="Preuves objectives (logs, codes HTTP)")

    # Analyse AnalystAgent
    analyst_conclusion: str
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    # Verdict CriticAgent
    critic_verdict: Literal["CONFIRMED", "NUANCED", "REJECTED", "PENDING"] = "PENDING"
    critic_rationale: str = ""
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    flags: list[Literal[
        "CONTEXT_DEPENDENT",
        "NEEDS_RETEST",
        "FALSE_POSITIVE_RISK",
        "PHISHING_VECTOR",
        "CHAIN_DEPENDENCY"
    ]] = Field(default_factory=list)
