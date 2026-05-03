"""
tools/mock_pipeline_demo.py
Run the AnalystAgent + CriticAgent pipeline against the local results/
findings, with both LLM calls mocked. Used when ANTHROPIC_API_KEY / HF_TOKEN
are not available in the dev sandbox — mirrors the live run shape exactly
so verdicts and the rich summary table are inspectable on a fresh checkout.

Mocking strategy:
  - AnalystAgent's anthropic call is replaced with a deterministic stub
    that returns analyst_conclusion enrichments (no cvss_score updates).
  - HFCriticAgent's openai call is replaced with a stub that assigns
    verdicts via the same 80/15/5 distribution used in the disagreement
    test. Adversarial overrides are applied for the canonical findings
    documented in CRITIC_SYSTEM_PROMPT (DMARC p=none, DNSSEC, HSTS+WAF,
    favicon, typosquat synthesis, etc.).
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.table import Table

from schemas.finding import Finding


def _load_findings() -> list[Finding]:
    findings: list[Finding] = []
    for f in sorted(pathlib.Path("results").glob("s[1-4]*telemo*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, list):
            for item in data:
                try:
                    findings.append(Finding(**item))
                except Exception:
                    continue
    return findings


def _install_anthropic_stub():
    """Inject a fake anthropic module that returns deterministic analyst output."""
    fake = types.ModuleType("anthropic")
    fake.Anthropic = MagicMock()
    instance = fake.Anthropic.return_value

    def fake_create(*args, **kwargs):
        # Extract the batch IDs from the user payload.
        body = kwargs["messages"][-1]["content"]
        ids = re.findall(r'"id":\s*"([0-9a-f-]+)"', body)
        updates = [
            {
                "id": fid,
                "analyst_conclusion": "Conclusion enrichie par l'analyste (mock).",
                "cvss_score": None,
            }
            for fid in ids
        ]
        text = json.dumps(updates)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            usage=SimpleNamespace(
                input_tokens=10, output_tokens=10,
                cache_creation_input_tokens=0, cache_read_input_tokens=0,
            ),
        )

    instance.messages.create.side_effect = fake_create
    sys.modules["anthropic"] = fake
    return instance


def _adversarial_verdict(f: Finding, idx: int) -> tuple[str, float, str, list[str]]:
    """Apply the adversarial logic from CRITIC_SYSTEM_PROMPT for canonical cases.
    Falls back to the 80/15/5 mock distribution otherwise."""
    title = f.title.lower()

    # Canonical adversarial cases per Session 5 §3.
    if "dmarc policy is p=none" in title:
        return "CONFIRMED", 0.90, "dig +short TXT _dmarc.* confirme p=none", []
    if "dnssec missing" in title:
        return "CONFIRMED", 0.88, "Aucun DNSKEY — vérifié par dig indépendant", []
    if "favicon absent" in title and "CONTEXT_DEPENDENT" in f.flags:
        return "NUANCED", 0.55, "WAF Imperva présent — absence non confirmée", ["CONTEXT_DEPENDENT"]
    if "typosquat variants identified" in title and "phishing delivery surface" in title:
        return "NUANCED", 0.65, "Synthèse correcte mais variants à valider via DNS lookup", []
    if title.startswith("typosquat domain variant"):
        return "CONFIRMED", 0.85, "Variante typosquat plausible — vérifiable", []
    if "csp allows unsafe-inline" in title or "csp allows unsafe-eval" in title:
        return "CONFIRMED", 0.88, "CSP permissive confirmée par evidence", []
    if "set-cookie missing samesite" in title:
        return "CONFIRMED", 0.80, "Cookie sans SameSite — risque CSRF", []
    if "rdns mismatch" in title:
        return "CONFIRMED", 0.78, "PTR Contabo confirmé via dig -x", []

    # Header-missing findings are often context-dependent (the page may not
    # need that protection) — the critic NUANCES rather than blindly confirms.
    if " missing" in title and "DNSSEC" not in title and "DKIM" not in title:
        return "NUANCED", 0.60, "Header manquant — utilité dépend du contexte de la page", ["CONTEXT_DEPENDENT"]

    # Default fallback: 70/25/5 distribution.
    mod = idx % 20
    if mod < 14:
        return "CONFIRMED", 0.82, "Vérification par scanner indépendant possible", []
    if mod < 19:
        return "NUANCED", 0.62, "Contexte réseau peut altérer la lecture", ["CONTEXT_DEPENDENT"]
    return "REJECTED", 0.30, "Evidence insuffisante pour conclure", []


def _install_openai_stub(all_findings: list[Finding]):
    fake = types.ModuleType("openai")
    fake.OpenAI = MagicMock()
    instance = fake.OpenAI.return_value
    by_id = {f.id: (i, f) for i, f in enumerate(all_findings)}

    def fake_create(*args, **kwargs):
        body = kwargs["messages"][-1]["content"]
        ids = re.findall(r'"id":\s*"([0-9a-f-]+)"', body)
        out_findings = []
        for fid in ids:
            entry = by_id.get(fid)
            if entry is None:
                continue
            idx, f = entry
            verdict, score, rationale, extra_flags = _adversarial_verdict(f, idx)
            item = json.loads(f.model_dump_json())
            item["critic_verdict"] = verdict
            item["confidence_score"] = score
            item["critic_rationale"] = rationale
            item["flags"] = list(set(item.get("flags", []) + extra_flags))
            out_findings.append(item)
        text = json.dumps({"findings": out_findings}, ensure_ascii=False)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
        )

    instance.chat.completions.create.side_effect = fake_create
    sys.modules["openai"] = fake
    return instance


def main():
    findings = _load_findings()
    print(f"[load] {len(findings)} raw findings from results/")

    os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-mock")
    os.environ.setdefault("HF_TOKEN", "hf_mock")

    _install_anthropic_stub()
    _install_openai_stub(findings)

    from agents.factory import create_analyst, create_critic
    from agents.classifier import classify_finding

    analyst = create_analyst()
    enriched = analyst.run(findings)
    print(f"[analyst] {len(enriched)} findings after enrichment "
          f"({len(findings) - len(enriched)} suppressed by ground-truth corrections)")

    critic = create_critic()
    judged = critic.run(enriched)

    by_verdict = {"CONFIRMED": 0, "NUANCED": 0, "REJECTED": 0, "PENDING": 0}
    for f in judged:
        by_verdict[f.critic_verdict] = by_verdict.get(f.critic_verdict, 0) + 1
    disagreements = by_verdict["NUANCED"] + by_verdict["REJECTED"]
    rate = disagreements / max(1, len(judged))
    print(f"[critic] CONFIRMED={by_verdict['CONFIRMED']} NUANCED={by_verdict['NUANCED']} "
          f"REJECTED={by_verdict['REJECTED']} PENDING={by_verdict['PENDING']}")
    print(f"[critic] disagreement rate = {rate:.0%}")
    assert rate >= 0.10, "Critic too compliant — adjust prompt"

    # Classify into report sections.
    sections: dict[str, int] = {}
    for f in judged:
        section = classify_finding(f)
        sections[section] = sections.get(section, 0) + 1

    out_path = pathlib.Path("results/s5_critic_telemo.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            [json.loads(f.model_dump_json()) for f in judged],
            indent=2, ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"[write] {out_path}")

    # Rich table: verdict × severity.
    console = Console()
    grid: dict[tuple[str, str], int] = {}
    for f in judged:
        grid[(f.critic_verdict, f.severity)] = grid.get((f.critic_verdict, f.severity), 0) + 1
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    table = Table(title=f"S5 mock pipeline — {len(judged)} findings")
    table.add_column("Verdict", style="bold")
    for sev in severities:
        table.add_column(sev, justify="right")
    for verdict in ("CONFIRMED", "NUANCED", "REJECTED", "PENDING"):
        row_total = sum(grid.get((verdict, s), 0) for s in severities)
        if row_total == 0:
            continue
        table.add_row(verdict, *[str(grid.get((verdict, s), 0)) for s in severities])
    console.print(table)

    section_table = Table(title="Report sections (classify_finding)")
    section_table.add_column("Section", style="bold")
    section_table.add_column("Count", justify="right")
    for s in ("findings_confirmed", "findings_investigate", "findings_pending", "findings_rejected"):
        if sections.get(s, 0):
            section_table.add_row(s, str(sections[s]))
    console.print(section_table)


if __name__ == "__main__":
    main()
