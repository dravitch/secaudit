"""
agents/base.py
Classe de base abstraite pour AnalystAgent et CriticAgent.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod

from schemas.finding import Finding


class BaseAgent(ABC):
    """Common base class for AnalystAgent and CriticAgent.

    Subclasses must implement `run(findings) -> list[Finding]` and call
    `_parse_findings()` on the LLM response text.
    """

    def __init__(self, model: str, temperature: float = 1.0):
        self.model = model
        self.temperature = temperature

    @abstractmethod
    def run(self, findings: list[Finding]) -> list[Finding]:
        ...

    @staticmethod
    def _strip_code_fence(raw: str) -> str:
        """Strip a ```...``` markdown fence if the model wrapped its JSON."""
        raw = raw.strip()
        if raw.startswith("```"):
            # Drop the opening fence (with optional language tag) and closing fence.
            lines = raw.splitlines()
            if lines:
                lines = lines[1:]
                if lines and lines[-1].strip().startswith("```"):
                    lines = lines[:-1]
            raw = "\n".join(lines).strip()
        return raw

    def _parse_findings(self, raw: str) -> list[Finding]:
        """Parse a JSON response into Finding objects. Accepts either a JSON
        array, or a JSON object with a `findings` array."""
        cleaned = self._strip_code_fence(raw)
        data = json.loads(cleaned)
        if isinstance(data, dict):
            data = data.get("findings", [data])
        return [Finding(**item) for item in data]

    def _parse_updates(self, raw: str) -> list[dict]:
        """Parse a JSON response into a list of partial-update dicts.
        Used by the Analyst, which only returns id/analyst_conclusion/cvss_score."""
        cleaned = self._strip_code_fence(raw)
        data = json.loads(cleaned)
        if isinstance(data, dict):
            data = data.get("findings", [data])
        return list(data)
