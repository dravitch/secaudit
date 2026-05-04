"""
reports/reporter.py
Génère un rapport Markdown auditable depuis une liste de Finding.

Sections (CLAUDE.md §11) :
  1. Résumé exécutif (compteurs sévérité × verdict)
  2. Findings confirmés      (CONFIRMED + confidence ≥ 0.75)
  3. À investiguer            (NUANCED, ou 0.50 ≤ confidence < 0.75)
  4. Findings rejetés         (REJECTED + tout le reste)
  5. Annexe technique : modèles, coûts API estimés, pipeline metadata.

Mindset 15 — Explainability First : un auditeur humain doit pouvoir lire
ce rapport en moins de 30 secondes et voir l'essentiel (résumé exécutif,
findings confirmés en tête).
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agents.classifier import classify_finding
from schemas.finding import Finding

DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# ── Pricing tables (USD per 1M tokens) ──────────────────────────────────
# Indicative — used to ballpark a per-run cost in the technical annex.
ANTHROPIC_PRICING = {
    "claude-sonnet-4-5": {"input": 3.00, "output": 15.00, "cache_read": 0.30},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00, "cache_read": 0.30},
    "claude-opus-4-7":   {"input": 15.00, "output": 75.00, "cache_read": 1.50},
}
DEEPSEEK_PRICING = {
    # Native DeepSeek API pricing (api.deepseek.com), USD per 1M tokens.
    "deepseek-chat":    {"input": 0.27, "output": 1.10},
    "deepseek-reasoner": {"input": 0.55, "output": 2.19},
}


def _classify_all(findings: list[Finding]) -> dict[str, list[Finding]]:
    sections: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        sections[classify_finding(f)].append(f)
    return sections


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _verdict_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"CONFIRMED": 0, "NUANCED": 0, "REJECTED": 0, "PENDING": 0}
    for f in findings:
        counts[f.critic_verdict] = counts.get(f.critic_verdict, 0) + 1
    return counts


def _normalize_model(model_name: str) -> str:
    """Strip provider suffix like ':novita' for pricing lookup."""
    return (model_name or "").split(":")[0]


def _estimate_cost(usage: Optional[dict], pricing: dict) -> dict:
    """Return {input_tokens, output_tokens, cost_usd} or zero-filled dict."""
    if not usage:
        return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
    inp = int(usage.get("input_tokens", 0))
    out = int(usage.get("output_tokens", 0))
    cache_read = int(usage.get("cache_read_input_tokens", 0))
    cost = (
        (inp / 1_000_000) * pricing.get("input", 0.0)
        + (out / 1_000_000) * pricing.get("output", 0.0)
        + (cache_read / 1_000_000) * pricing.get("cache_read", 0.0)
    )
    return {
        "input_tokens": inp,
        "output_tokens": out,
        "cache_read_tokens": cache_read,
        "cost_usd": round(cost, 4),
    }


def _build_cost_summary(metadata: Optional[dict]) -> Optional[dict]:
    """Return a dict ready for the annexe template, or None if no AI ran."""
    if not metadata:
        return None
    s5 = (metadata.get("counts") or {}).get("s5") or {}
    if not s5:
        return None

    analyst_model = _normalize_model(s5.get("analyst_model", ""))
    critic_model = _normalize_model(s5.get("critic_model", ""))
    analyst_pricing = ANTHROPIC_PRICING.get(analyst_model, {})
    critic_pricing = DEEPSEEK_PRICING.get(critic_model, {})

    analyst = _estimate_cost(s5.get("analyst_usage"), analyst_pricing)
    critic = _estimate_cost(s5.get("critic_usage"), critic_pricing)
    return {
        "analyst_model": s5.get("analyst_model", "?"),
        "critic_model": s5.get("critic_model", "?"),
        "analyst": analyst,
        "critic": critic,
        "total_cost_usd": round(analyst["cost_usd"] + critic["cost_usd"], 4),
    }


def _truncated_finding_ids(findings: list[Finding]) -> set[str]:
    """Findings flagged with finish_reason=length (max_tokens hit)."""
    out: set[str] = set()
    for f in findings:
        # Convention: agents may append 'TRUNCATED:length' to evidence when
        # they detect finish_reason == 'length' on the LLM response.
        for line in f.evidence:
            if "finish_reason=length" in line or "TRUNCATED" in line:
                out.add(f.id)
                break
    return out


def _disagreement_rate(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    total = len(findings)
    disagreements = sum(
        1 for f in findings if f.critic_verdict in ("NUANCED", "REJECTED")
    )
    return round(disagreements / total, 3)


def render_markdown(
    findings: list[Finding],
    target: str,
    metadata: Optional[dict] = None,
    templates_dir: Optional[Path] = None,
) -> str:
    """Render the Markdown report as a string. Pure (no I/O)."""
    env = Environment(
        loader=FileSystemLoader(str(templates_dir or DEFAULT_TEMPLATES_DIR)),
        autoescape=select_autoescape(disabled_extensions=("md", "j2")),
        keep_trailing_newline=True,
    )
    template = env.get_template("report.md.j2")

    sections = _classify_all(findings)
    context = {
        "target": target,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "total": len(findings),
        "severity_counts": _severity_counts(findings),
        "verdict_counts": _verdict_counts(findings),
        "disagreement_rate": _disagreement_rate(findings),
        "confirmed": sections.get("findings_confirmed", []),
        "investigate": sections.get("findings_investigate", []),
        "rejected": sections.get("findings_rejected", []),
        "pending": sections.get("findings_pending", []),
        "metadata": metadata or {},
        "cost": _build_cost_summary(metadata),
        "truncated_ids": _truncated_finding_ids(findings),
    }
    return template.render(**context)


def generate_report(
    findings: list[Finding],
    target: str,
    results_dir: Path,
    metadata: Optional[dict] = None,
    templates_dir: Optional[Path] = None,
    filename: Optional[str] = None,
) -> Path:
    """Render the report and write it under results_dir. Returns the path."""
    text = render_markdown(
        findings,
        target=target,
        metadata=metadata,
        templates_dir=templates_dir,
    )
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    date_tag = datetime.utcnow().strftime("%Y%m%d")
    name = filename or f"report_{safe_target}_{date_tag}.md"
    out_path = Path(results_dir) / name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return out_path


def export_json_for_dashboard(
    findings: list[Finding],
    out_path: Path,
) -> Path:
    """Write the findings array as JSON for ui/dashboard.html FileReader."""
    payload = [json.loads(f.model_dump_json()) for f in findings]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return out_path
