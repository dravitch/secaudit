"""
tests/test_reporter.py
Couverture du module reports/reporter.py.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from reports import reporter
from schemas.finding import Finding


def _mk(
    *,
    title: str = "Sample finding",
    severity: str = "HIGH",
    verdict: str = "CONFIRMED",
    confidence: float = 0.85,
    flags: list[str] | None = None,
    evidence: list[str] | None = None,
    target: str = "telemo.gov.gn",
    sprint: int = 1,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        sprint=sprint,
        tool="scanner",
        target=target,
        title=title,
        finding=title + " — desc",
        evidence=evidence if evidence is not None else ["ev1"],
        analyst_conclusion="analyst says " + title,
        severity=severity,
        critic_verdict=verdict,
        critic_rationale="critic says " + title,
        confidence_score=confidence,
        flags=flags or [],
    )


# ── Section classification routing ──────────────────────────────────


def test_render_routes_confirmed_high_into_confirmed_section():
    f = _mk(verdict="CONFIRMED", confidence=0.85)
    md = reporter.render_markdown([f], target="telemo.gov.gn")
    # The "Findings confirmés" section header includes the count.
    assert "Findings confirmés (1)" in md
    assert "À investiguer (0)" in md
    assert f.title in md


def test_render_routes_nuanced_into_investigate_section():
    f = _mk(verdict="NUANCED", confidence=0.6)
    md = reporter.render_markdown([f], target="telemo.gov.gn")
    assert "À investiguer (1)" in md
    assert "Findings confirmés (0)" in md


def test_render_routes_low_confidence_confirmed_into_investigate():
    """CONFIRMED but confidence < 0.75 → investigate (per classify_finding)."""
    f = _mk(verdict="CONFIRMED", confidence=0.60)
    md = reporter.render_markdown([f], target="telemo.gov.gn")
    assert "À investiguer (1)" in md
    assert "Findings confirmés (0)" in md


def test_render_routes_rejected_into_rejected_section():
    f = _mk(verdict="REJECTED", confidence=0.20)
    md = reporter.render_markdown([f], target="telemo.gov.gn")
    assert "Findings rejetés (1)" in md


# ── Counts in executive summary ─────────────────────────────────────


def test_severity_counts_appear_in_summary():
    findings = [
        _mk(severity="CRITICAL", verdict="CONFIRMED"),
        _mk(severity="HIGH", verdict="CONFIRMED"),
        _mk(severity="HIGH", verdict="NUANCED", confidence=0.6),
        _mk(severity="MEDIUM", verdict="CONFIRMED"),
    ]
    md = reporter.render_markdown(findings, target="telemo.gov.gn")
    assert "**CRITICAL** | 1" in md
    assert "**HIGH** | 2" in md
    assert "**MEDIUM** | 1" in md


def test_disagreement_rate_displayed_in_summary():
    findings = [
        _mk(verdict="CONFIRMED"),
        _mk(verdict="NUANCED", confidence=0.6),
        _mk(verdict="REJECTED", confidence=0.2),
        _mk(verdict="CONFIRMED"),
    ]
    md = reporter.render_markdown(findings, target="telemo.gov.gn")
    # 2 disagreements / 4 = 50%
    assert "Taux de désaccord critic :** 50.0 %" in md


# ── Cost annexe ─────────────────────────────────────────────────────


def test_reporter_cost_estimate_present_in_annexe(tmp_path):
    """When usage tokens are provided in metadata, cost section appears."""
    f = _mk(verdict="CONFIRMED")
    metadata = {
        "started_at": "2026-05-03T10:00:00Z",
        "duration_sec": 12.5,
        "sprints_requested": [1, 2, 3, 4, 5],
        "no_ai": False,
        "findings_pre_ai": 38,
        "counts": {
            "s5": {
                "before_analyst": 38,
                "after_analyst": 35,
                "after_critic": 35,
                "analyst_model": "claude-sonnet-4-5",
                "critic_model": "deepseek-ai/DeepSeek-V4-Pro:novita",
                "analyst_usage": {
                    "input_tokens": 12000,
                    "output_tokens": 3000,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 8000,
                },
                "critic_usage": {"input_tokens": 15000, "output_tokens": 4000},
            }
        },
    }
    md = reporter.render_markdown([f], target="telemo.gov.gn", metadata=metadata)
    assert "Coût total estimé" in md
    assert "claude-sonnet-4-5" in md
    assert "deepseek-ai/DeepSeek-V4-Pro" in md
    # 12000 input tokens shown.
    assert "12000" in md


def test_reporter_no_cost_section_when_no_ai_metadata():
    """Without S5 metadata, no cost section is rendered."""
    f = _mk(verdict="PENDING", confidence=0.0)
    md = reporter.render_markdown(
        [f], target="telemo.gov.gn",
        metadata={"counts": {}, "no_ai": True},
    )
    assert "Agents IA non exécutés" in md


# ── Truncated-LLM badge ─────────────────────────────────────────────


def test_truncated_finding_marked_in_report():
    """A finding with finish_reason=length in evidence gets a ⚑ marker."""
    f = _mk(
        verdict="CONFIRMED",
        evidence=["normal evidence", "TRUNCATED:length detected"],
    )
    md = reporter.render_markdown([f], target="telemo.gov.gn")
    assert "tronquée" in md.lower() or "⚑" in md


# ── File generation ─────────────────────────────────────────────────


def test_generate_report_writes_file_with_target_and_date(tmp_path):
    f = _mk(verdict="CONFIRMED")
    path = reporter.generate_report(
        [f],
        target="telemo.gov.gn",
        results_dir=tmp_path,
        metadata={"counts": {}, "no_ai": True},
    )
    assert path.exists()
    assert path.suffix == ".md"
    assert "telemo.gov.gn" in path.name
    text = path.read_text(encoding="utf-8")
    assert "SecAudit — Rapport" in text
    assert f.title in text


def test_export_json_for_dashboard_writes_array(tmp_path):
    findings = [_mk(verdict="CONFIRMED"), _mk(verdict="NUANCED", confidence=0.6)]
    out = tmp_path / "dashboard.json"
    reporter.export_json_for_dashboard(findings, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == 2
    assert {f["critic_verdict"] for f in data} == {"CONFIRMED", "NUANCED"}


def test_render_handles_empty_findings():
    """Edge case — pipeline that produced zero findings."""
    md = reporter.render_markdown([], target="telemo.gov.gn", metadata={})
    assert "0 findings" in md or "0 finding" in md
    assert "Aucun finding confirmé" in md
