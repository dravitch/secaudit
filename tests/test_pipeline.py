"""
tests/test_pipeline.py
Couvre main.py — orchestrateur séquentiel.

Stratégie : monkeypatch chaque tools.* + agents.factory.* au lieu de mocker
subprocess / httpx individuellement. On vérifie le câblage, pas la logique
des outils (déjà couverte par les tests S1-S5).
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from schemas.finding import Finding


def _mk_finding(
    *,
    sprint: int = 1,
    title: str = "f",
    severity: str = "MEDIUM",
    target: str = "telemo.gov.gn",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        sprint=sprint,
        tool="t",
        target=target,
        title=title,
        finding=title,
        evidence=["e"],
        analyst_conclusion="conc",
        severity=severity,
    )


# ── Sprint dispatch ──────────────────────────────────────────────────


def test_main_sprints_only_runs_requested_sprints(monkeypatch, tmp_path):
    """--sprints 1 → only S1 helpers called."""
    import main

    calls: dict[str, int] = {}

    def fake_recon(target):
        calls["recon"] = calls.get("recon", 0) + 1
        return [_mk_finding(sprint=1, title="port 443")]

    def fake_scanner(target):
        calls["scanner"] = calls.get("scanner", 0) + 1
        return [_mk_finding(sprint=1, title="header")]

    def fake_tls(target):
        calls["tls"] = calls.get("tls", 0) + 1
        return []

    def fake_dns(target):
        calls["dns"] = calls.get("dns", 0) + 1
        return []

    def fake_phishing(target):
        calls["phishing"] = calls.get("phishing", 0) + 1
        return []

    monkeypatch.setattr("tools.recon.scan", fake_recon)
    monkeypatch.setattr("tools.scanner.scan", fake_scanner)
    monkeypatch.setattr("tools.scanner.scan_tls", fake_tls)
    monkeypatch.setattr("tools.scanner.scan_dns", fake_dns)
    monkeypatch.setattr("tools.phishing_surface.scan", fake_phishing)

    summary = main.run(
        target="telemo.gov.gn",
        sprints=[1],
        no_ai=True,
        results_dir=tmp_path,
        write_report=False,
    )
    assert "recon" in calls and "scanner" in calls
    assert "tls" not in calls and "dns" not in calls and "phishing" not in calls
    assert summary["findings_total"] == 2


def test_main_full_pipeline_no_ai_skips_agents(monkeypatch, tmp_path):
    """--no-ai → S5 agents are never instantiated."""
    import main

    monkeypatch.setattr("tools.recon.scan", lambda t: [_mk_finding(sprint=1, title="A")])
    monkeypatch.setattr("tools.scanner.scan", lambda t: [_mk_finding(sprint=1, title="B")])
    monkeypatch.setattr("tools.scanner.scan_tls", lambda t: [])
    monkeypatch.setattr("tools.scanner.scan_dns", lambda t: [])
    monkeypatch.setattr("tools.phishing_surface.scan", lambda t: [])

    def boom_analyst():
        raise AssertionError("AnalystAgent must NOT be instantiated with --no-ai")

    def boom_critic():
        raise AssertionError("CriticAgent must NOT be instantiated with --no-ai")

    monkeypatch.setattr("agents.factory.create_analyst", boom_analyst)
    monkeypatch.setattr("agents.factory.create_critic", boom_critic)

    summary = main.run(
        target="telemo.gov.gn",
        sprints=[1, 2, 3, 4, 5],
        no_ai=True,
        results_dir=tmp_path,
        write_report=False,
    )
    assert summary["agents_called"] is False
    assert summary["findings_total"] == 2


def test_main_no_ai_produces_per_sprint_json_files(monkeypatch, tmp_path):
    """--no-ai → JSON per sprint written, no s5_critic.json."""
    import main

    monkeypatch.setattr("tools.recon.scan", lambda t: [_mk_finding(sprint=1, title="A")])
    monkeypatch.setattr("tools.scanner.scan", lambda t: [_mk_finding(sprint=1, title="B")])
    monkeypatch.setattr("tools.scanner.scan_tls", lambda t: [])
    monkeypatch.setattr("tools.scanner.scan_dns", lambda t: [])
    monkeypatch.setattr("tools.phishing_surface.scan", lambda t: [])

    main.run(
        target="telemo.gov.gn",
        sprints=[1, 2, 3, 4, 5],
        no_ai=True,
        results_dir=tmp_path,
        write_report=False,
    )

    assert (tmp_path / "s1_recon.json").exists()
    assert (tmp_path / "s1_headers.json").exists()
    assert (tmp_path / "s2_tls.json").exists()
    assert (tmp_path / "s2_dns.json").exists()
    assert (tmp_path / "s3_phishing.json").exists()
    assert not (tmp_path / "s5_critic.json").exists()


# ── Env validation ───────────────────────────────────────────────────


def test_main_with_ai_raises_when_keys_missing(monkeypatch, tmp_path):
    """run() with want_ai=True but missing keys → EnvironmentError before any scan."""
    import main

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY|DEEPSEEK_API_KEY"):
        main.run(
            target="telemo.gov.gn",
            sprints=[1, 2, 3, 4, 5],
            no_ai=False,
            results_dir=tmp_path,
            write_report=False,
        )


def test_main_no_ai_does_not_require_keys(monkeypatch, tmp_path):
    """--no-ai → no env-var check."""
    import main

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    monkeypatch.setattr("tools.recon.scan", lambda t: [])
    monkeypatch.setattr("tools.scanner.scan", lambda t: [_mk_finding()])
    monkeypatch.setattr("tools.scanner.scan_tls", lambda t: [])
    monkeypatch.setattr("tools.scanner.scan_dns", lambda t: [])
    monkeypatch.setattr("tools.phishing_surface.scan", lambda t: [])

    summary = main.run(
        target="telemo.gov.gn",
        sprints=[1, 2, 3, 4, 5],
        no_ai=True,
        results_dir=tmp_path,
        write_report=False,
    )
    assert summary["findings_total"] == 1
    assert summary["agents_called"] is False


# ── Sprint parser ────────────────────────────────────────────────────


def test_parse_sprints_accepts_comma_separated():
    import main

    assert main._parse_sprints("1,2,3") == [1, 2, 3]
    assert main._parse_sprints("1, 5,3") == [1, 3, 5]
    assert main._parse_sprints("2") == [2]


def test_parse_sprints_rejects_out_of_range():
    import main

    with pytest.raises(ValueError):
        main._parse_sprints("0,1,2")
    with pytest.raises(ValueError):
        main._parse_sprints("6")


def test_main_loads_dotenv_at_import_before_check_env(tmp_path, monkeypatch):
    """Bug 1 regression: main.py must load .env BEFORE _check_env() reads
    os.getenv(). Otherwise the AI stage rejects valid keys with
    EnvironmentError because config.settings is only imported later (inside
    _run_sprint5).

    We assert the symptom: with both keys in a .env file at the repo root
    (and NOT in the shell env), main.run(want_ai=True) must NOT raise
    EnvironmentError before any sprint runs.
    """
    import importlib
    import main as main_mod

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    # Put a .env next to main.py for this run.
    repo_root = Path(main_mod.__file__).resolve().parent
    env_path = repo_root / ".env"
    backup = env_path.read_text() if env_path.exists() else None
    env_path.write_text(
        "ANTHROPIC_API_KEY=sk-ant-from-dotenv\nDEEPSEEK_API_KEY=sk-ds-from-dotenv\n"
    )
    try:
        importlib.reload(main_mod)
        # _check_env should now see the keys via load_dotenv.
        info = main_mod._check_env(want_ai=True)
        assert info["anthropic"] is True
        assert info["critic_key_present"] is True
    finally:
        if backup is None:
            env_path.unlink(missing_ok=True)
        else:
            env_path.write_text(backup)


# ── End-to-end with stubbed agents (no real LLM call) ────────────────


def test_main_full_pipeline_with_ai_writes_report(monkeypatch, tmp_path):
    """When agents are present (stubbed), report file is written."""
    import main

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-ds-test")

    f1 = _mk_finding(sprint=1, title="A", severity="HIGH")
    f2 = _mk_finding(sprint=2, title="B", severity="MEDIUM")
    monkeypatch.setattr("tools.recon.scan", lambda t: [f1])
    monkeypatch.setattr("tools.scanner.scan", lambda t: [])
    monkeypatch.setattr("tools.scanner.scan_tls", lambda t: [])
    monkeypatch.setattr("tools.scanner.scan_dns", lambda t: [f2])
    monkeypatch.setattr("tools.phishing_surface.scan", lambda t: [])

    class FakeAnalyst:
        model = "claude-sonnet-4-5"
        _total_usage = {
            "input_tokens": 100, "output_tokens": 30,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        }

        def run(self, findings):
            return findings

    class FakeCritic:
        model = "deepseek-chat"
        _total_usage = {"input_tokens": 80, "output_tokens": 20}

        def run(self, findings):
            for f in findings:
                f.critic_verdict = "CONFIRMED"
                f.confidence_score = 0.85
                f.critic_rationale = "verified"
            return findings

    monkeypatch.setattr("agents.factory.create_analyst", lambda: FakeAnalyst())
    monkeypatch.setattr("agents.factory.create_critic", lambda: FakeCritic())

    summary = main.run(
        target="telemo.gov.gn",
        sprints=[1, 2, 3, 4, 5],
        no_ai=False,
        results_dir=tmp_path,
        write_report=True,
    )
    assert summary["agents_called"] is True
    assert summary["report_path"] is not None
    report_path = Path(summary["report_path"])
    assert report_path.exists()
    text = report_path.read_text(encoding="utf-8")
    assert "Findings confirmés (2)" in text
    assert "claude-sonnet-4-5" in text
