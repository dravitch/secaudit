"""
main.py — orchestrateur séquentiel S1 → S5 (CLAUDE.md §9, Session 6).

Pipeline :
  S1  → tools.recon.scan        (nmap, ports 80/443)
  S1  → tools.scanner.scan      (HTTP headers, 60+ checks)
  S2  → tools.scanner.scan_tls  (testssl.sh)
  S2  → tools.scanner.scan_dns  (dig DNSSEC/SPF/DMARC/DKIM/MX/rDNS)
  S3+4→ tools.phishing_surface.scan
  S5  → agents.factory.create_analyst().run()
  S5  → agents.factory.create_critic().run()
  Out → reports.reporter.generate_report()

CLI :
  python main.py --target telemo.gov.gn --sprints 1,2,3,4,5
  python main.py --target telemo.gov.gn --sprints 1,2,3 --no-ai

Programmatic API :
  from main import run
  result = run(target="telemo.gov.gn", sprints=[1, 2, 3, 4, 5])
  result["findings_total"], result["report_path"], result["agents_called"]
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Allow running as a script (`python main.py ...`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import typer
from rich.console import Console
from rich.table import Table

from schemas.finding import Finding

app = typer.Typer(add_completion=False)
console = Console()

DEFAULT_RESULTS_DIR = Path("results")
SPRINTS_DEFAULT = "1,2,3,4,5"


def _parse_sprints(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n < 1 or n > 5:
            raise ValueError(f"Sprint number out of range: {n}")
        out.append(n)
    return sorted(set(out))


def _write_findings(findings: list[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(f.model_dump_json()) for f in findings]
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _check_env(want_ai: bool) -> dict:
    """Return a small dict describing key presence (does not call APIs)."""
    import os

    info = {
        "anthropic": bool(os.getenv("ANTHROPIC_API_KEY")),
        "huggingface": bool(os.getenv("HF_TOKEN")),
        "want_ai": want_ai,
    }
    if want_ai and not (info["anthropic"] and info["huggingface"]):
        missing = [
            "ANTHROPIC_API_KEY" if not info["anthropic"] else None,
            "HF_TOKEN" if not info["huggingface"] else None,
        ]
        missing = [m for m in missing if m]
        raise EnvironmentError(
            f"Missing env vars for the AI stage: {', '.join(missing)}. "
            f"Run `python test_api_keys.py` to diagnose, then re-run with "
            f"valid .env or use --no-ai to skip the agents."
        )
    return info


def _run_sprint1(target: str, http_target: str, results_dir: Path) -> tuple[list[Finding], dict]:
    """recon (nmap) + scanner (HTTP headers)."""
    from tools import recon as recon_mod
    from tools import scanner as scanner_mod

    findings: list[Finding] = []
    counts: dict[str, int] = {}

    try:
        recon_findings = recon_mod.scan(target)
    except RuntimeError as e:
        console.print(f"[yellow][S1][/yellow] recon skipped — {e}")
        recon_findings = []
    findings.extend(recon_findings)
    counts["recon"] = len(recon_findings)
    _write_findings(recon_findings, results_dir / "s1_recon.json")

    headers_findings = scanner_mod.scan(http_target)
    findings.extend(headers_findings)
    counts["headers"] = len(headers_findings)
    _write_findings(headers_findings, results_dir / "s1_headers.json")

    return findings, counts


def _run_sprint2(target: str, results_dir: Path) -> tuple[list[Finding], dict]:
    """testssl (TLS) + dig (DNS)."""
    from tools import scanner as scanner_mod

    findings: list[Finding] = []
    counts: dict[str, int] = {}

    try:
        tls_findings = scanner_mod.scan_tls(target)
    except RuntimeError as e:
        console.print(f"[yellow][S2][/yellow] TLS skipped — {e}")
        tls_findings = []
    findings.extend(tls_findings)
    counts["tls"] = len(tls_findings)
    _write_findings(tls_findings, results_dir / "s2_tls.json")

    try:
        dns_findings = scanner_mod.scan_dns(target)
    except RuntimeError as e:
        console.print(f"[yellow][S2][/yellow] DNS skipped — {e}")
        dns_findings = []
    findings.extend(dns_findings)
    counts["dns"] = len(dns_findings)
    _write_findings(dns_findings, results_dir / "s2_dns.json")

    return findings, counts


def _run_sprint3_4(http_target: str, results_dir: Path) -> tuple[list[Finding], dict]:
    """Phishing surface (login parser + SRI + favicon + typosquats)."""
    from tools import phishing_surface as phishing

    phishing_findings = phishing.scan(http_target)
    _write_findings(phishing_findings, results_dir / "s3_phishing.json")
    return phishing_findings, {"phishing": len(phishing_findings)}


def _run_sprint5(
    findings: list[Finding], results_dir: Path
) -> tuple[list[Finding], dict]:
    """AnalystAgent (Anthropic) + CriticAgent (HF/DeepSeek)."""
    from agents.factory import create_analyst, create_critic

    analyst = create_analyst()
    enriched = analyst.run(findings)
    critic = create_critic()
    judged = critic.run(enriched)
    _write_findings(judged, results_dir / "s5_critic.json")

    counts = {
        "before_analyst": len(findings),
        "after_analyst": len(enriched),
        "after_critic": len(judged),
        "analyst_model": getattr(analyst, "model", "?"),
        "critic_model": getattr(critic, "model", "?"),
        "analyst_usage": getattr(analyst, "_total_usage", None),
        "critic_usage": getattr(critic, "_total_usage", None),
    }
    return judged, counts


def _print_breakdown(findings: list[Finding], title: str) -> None:
    sev_counts: dict[str, int] = {}
    verdict_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        verdict_counts[f.critic_verdict] = verdict_counts.get(f.critic_verdict, 0) + 1

    table = Table(title=title)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(sev, 0):
            table.add_row(sev, str(sev_counts[sev]))
    console.print(table)

    if any(v != "PENDING" for v in verdict_counts):
        vtable = Table(title="Verdict breakdown")
        vtable.add_column("Verdict", style="bold")
        vtable.add_column("Count", justify="right")
        for v in ["CONFIRMED", "NUANCED", "REJECTED", "PENDING"]:
            if verdict_counts.get(v, 0):
                vtable.add_row(v, str(verdict_counts[v]))
        console.print(vtable)


def run(
    target: str,
    sprints: Optional[list[int]] = None,
    no_ai: bool = False,
    results_dir: Optional[Path] = None,
    write_report: bool = True,
) -> dict:
    """Programmatic entry point. Returns a summary dict."""
    sprints = sorted(set(sprints or [1, 2, 3, 4, 5]))
    results_dir = Path(results_dir) if results_dir else DEFAULT_RESULTS_DIR

    want_ai = (5 in sprints) and (not no_ai)
    env_info = _check_env(want_ai=want_ai)

    http_target = target if target.startswith(("http://", "https://")) else f"https://{target}"
    started_at = time.time()
    summary: dict = {
        "target": target,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "sprints_requested": sprints,
        "no_ai": no_ai,
        "env": env_info,
        "counts": {},
        "agents_called": False,
        "findings_total": 0,
        "report_path": None,
    }

    all_findings: list[Finding] = []

    if 1 in sprints:
        f, c = _run_sprint1(target, http_target, results_dir)
        all_findings.extend(f)
        summary["counts"]["s1"] = c
        console.print(f"[bold cyan][S1][/bold cyan] recon={c['recon']} headers={c['headers']}")

    if 2 in sprints:
        f, c = _run_sprint2(target, results_dir)
        all_findings.extend(f)
        summary["counts"]["s2"] = c
        console.print(f"[bold cyan][S2][/bold cyan] tls={c['tls']} dns={c['dns']}")

    if 3 in sprints or 4 in sprints:
        f, c = _run_sprint3_4(http_target, results_dir)
        all_findings.extend(f)
        summary["counts"]["s3_4"] = c
        console.print(f"[bold cyan][S3+4][/bold cyan] phishing={c['phishing']}")

    summary["findings_pre_ai"] = len(all_findings)

    if want_ai and all_findings:
        f, c = _run_sprint5(all_findings, results_dir)
        all_findings = f
        summary["counts"]["s5"] = c
        summary["agents_called"] = True
        console.print(
            f"[bold cyan][S5][/bold cyan] "
            f"{c['before_analyst']} → {c['after_analyst']} → {c['after_critic']} "
            f"(analyst={c['analyst_model']} critic={c['critic_model']})"
        )

    summary["findings_total"] = len(all_findings)
    summary["duration_sec"] = round(time.time() - started_at, 2)
    _print_breakdown(all_findings, title=f"Pipeline result — {len(all_findings)} findings")

    if write_report and all_findings:
        from reports.reporter import generate_report

        report_path = generate_report(
            all_findings,
            target=target,
            results_dir=results_dir,
            metadata=summary,
        )
        summary["report_path"] = str(report_path)
        console.print(f"[bold green][REPORT][/bold green] → {report_path}")

    console.print(
        f"[dim][duration][/dim] {summary['duration_sec']}s · findings={summary['findings_total']}"
    )
    return summary


@app.command()
def cli(
    target: str = typer.Option(..., "--target", help="Hostname or URL"),
    sprints: str = typer.Option(SPRINTS_DEFAULT, "--sprints", help="Comma-separated 1-5"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip Sprint 5 (agents)"),
    results_dir: Path = typer.Option(DEFAULT_RESULTS_DIR, "--results-dir"),
):
    """Run the SecAudit pipeline end-to-end on a single target."""
    run(
        target=target,
        sprints=_parse_sprints(sprints),
        no_ai=no_ai,
        results_dir=results_dir,
    )


if __name__ == "__main__":
    app()
