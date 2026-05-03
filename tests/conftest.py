"""
tests/conftest.py
Fixtures partagées pour la suite Session 5.
"""
from __future__ import annotations

import json
import pathlib
import uuid

import pytest

from schemas.finding import Finding


@pytest.fixture
def findings_37_sample():
    """Charge les findings réels depuis results/ (~37 sur le pipeline complet
    telemo) ; fallback sur 10 findings synthétiques représentatifs si results/
    est absent (CI / fresh checkout)."""
    files = sorted(
        pathlib.Path("results").glob("s[1-4]*telemo*.json")
    )
    findings: list[Finding] = []
    for f in files:
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, list):
                for item in data:
                    try:
                        findings.append(Finding(**item))
                    except Exception:
                        # Skip findings whose schema drifted between sprints.
                        continue
    if not findings:
        findings = [
            Finding(
                id=str(uuid.uuid4()),
                sprint=1,
                tool="scanner",
                target="t.gn",
                title=f"Synthetic finding {i}",
                finding=f"desc {i}",
                evidence=["ev"] if i % 3 != 0 else [],
                analyst_conclusion="conclusion",
                severity=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"][i % 5],
            )
            for i in range(10)
        ]
    return findings
