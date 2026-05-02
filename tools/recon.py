"""
tools/recon.py
Sprint 1 — wrapper nmap (subprocess) → Finding JSON.

Scan ports 80/443 par défaut, parsing XML via xml.etree.
1 Finding par port OUVERT. Severity = INFO (443) / LOW (80) / MEDIUM (autre).
Rejette toute cible absente de config/scope.yaml.
"""
from __future__ import annotations

import json
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# Allow running as a script (`python tools/recon.py ...`) per CLAUDE.md §12.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import typer
from rich.console import Console
from rich.table import Table

from schemas.finding import Finding
from tools._scope import assert_in_scope, normalize_host

DEFAULT_PORTS = "80,443"
NMAP_TIMEOUT_SEC = 60

app = typer.Typer(add_completion=False)


def _severity_for_port(port: int) -> str:
    if port == 443:
        return "INFO"
    if port == 80:
        return "LOW"
    return "MEDIUM"


def run_nmap(
    target: str, ports: str = DEFAULT_PORTS, timeout: int = NMAP_TIMEOUT_SEC
) -> str:
    """Run nmap and return raw XML stdout. Raises RuntimeError on failure."""
    cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-p", ports,
        "--max-retries", "1",
        "-oX", "-",
        target,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"nmap failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def parse_nmap_xml(xml_text: str, target: str) -> list[Finding]:
    """Convert nmap XML output to Finding list (one per OPEN port)."""
    findings: list[Finding] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid", "0"))
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service = (
                service_el.get("name", "") if service_el is not None else ""
            )
            evidence_line = f"{portid}/{protocol} open {service}".strip()
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    sprint=1,
                    tool="recon",
                    target=target,
                    timestamp=datetime.utcnow(),
                    title=f"Port {portid}/{protocol} open ({service or 'unknown'})",
                    finding=(
                        f"nmap reports {portid}/{protocol} open "
                        f"({service or 'unknown'})"
                    ),
                    evidence=[evidence_line],
                    analyst_conclusion=(
                        "Service exposé publiquement — nécessite audit "
                        "d'authentification et de durcissement TLS."
                    ),
                    severity=_severity_for_port(portid),
                )
            )
    return findings


def scan(target: str, ports: str = DEFAULT_PORTS) -> list[Finding]:
    """Full scan: scope check → nmap → parse."""
    assert_in_scope(target, sprint=1)
    host = normalize_host(target)
    xml_out = run_nmap(host, ports=ports)
    return parse_nmap_xml(xml_out, target=host)


def write_findings(findings: list[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [json.loads(f.model_dump_json()) for f in findings]
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def print_summary(findings: list[Finding], tool: str) -> None:
    console = Console()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    table = Table(title=f"{tool} — {len(findings)} finding(s)")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev, 0):
            table.add_row(sev, str(counts[sev]))
    console.print(table)


@app.command()
def main(
    target: str = typer.Option(..., "--target", help="Hostname or URL to scan"),
    output: Path = typer.Option(..., "--output", help="JSON output file"),
    ports: str = typer.Option(DEFAULT_PORTS, "--ports", help="Comma-separated ports"),
):
    """Sprint 1 recon — nmap wrapper."""
    findings = scan(target, ports=ports)
    write_findings(findings, output)
    typer.echo(f"[recon] {len(findings)} finding(s) → {output}")
    print_summary(findings, tool="recon")


if __name__ == "__main__":
    app()
