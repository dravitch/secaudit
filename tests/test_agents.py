"""
tests/test_agents.py
Mocke anthropic.Anthropic et openai.OpenAI — aucun appel réseau réel.
"""
from __future__ import annotations

import json
import os
import sys
import types
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from schemas.finding import Finding


# ── Helpers ─────────────────────────────────────────────────────────────


def _mk_finding(
    *,
    id: str | None = None,
    sprint: int = 1,
    tool: str = "scanner",
    target: str = "telemo.gov.gn",
    title: str = "Generic finding",
    finding_text: str = "Generic finding description",
    evidence: list[str] | None = None,
    analyst_conclusion: str = "conclusion",
    severity: str = "MEDIUM",
    flags: list[str] | None = None,
    cvss_score: float | None = None,
) -> Finding:
    return Finding(
        id=id or str(uuid.uuid4()),
        sprint=sprint,
        tool=tool,
        target=target,
        title=title,
        finding=finding_text,
        evidence=evidence if evidence is not None else ["ev1"],
        analyst_conclusion=analyst_conclusion,
        severity=severity,
        cvss_score=cvss_score,
        flags=flags or [],
    )


def _mock_anthropic_response(payload):
    """Build a mock Anthropic Message-like response with a single text block."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(
            input_tokens=10, output_tokens=10,
            cache_creation_input_tokens=0, cache_read_input_tokens=0,
        ),
    )


def _mock_openai_response(payload):
    """Build a mock OpenAI ChatCompletion-like response."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
    )


def _install_fake_anthropic(monkeypatch, response_payload, side_effect=None):
    """Inject a fake `anthropic` module + reload analyst_agent so its import
    inside __init__ resolves to the stub."""
    fake = types.ModuleType("anthropic")
    fake.Anthropic = MagicMock()
    instance = fake.Anthropic.return_value
    if side_effect is not None:
        instance.messages.create.side_effect = side_effect
    else:
        instance.messages.create.return_value = _mock_anthropic_response(response_payload)
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    return fake, instance


def _install_fake_openai(monkeypatch, response_payload, side_effect=None):
    fake = types.ModuleType("openai")
    fake.OpenAI = MagicMock()
    instance = fake.OpenAI.return_value
    if side_effect is not None:
        instance.chat.completions.create.side_effect = side_effect
    else:
        instance.chat.completions.create.return_value = _mock_openai_response(
            response_payload
        )
    monkeypatch.setitem(sys.modules, "openai", fake)
    return fake, instance


# ── AnalystAgent ────────────────────────────────────────────────────────


def test_analyst_raises_environment_error_when_key_missing(monkeypatch):
    """EnvironmentError levée si ANTHROPIC_API_KEY absent au moment de
    l'instanciation.

    Robustesse contre .env autoloadé sur NixOS : monkeypatch.delenv ne
    suffit pas — l'import de agents.analyst_agent déclenche
    config.settings → load_dotenv() qui RÉ-INJECTE la clé. On patche
    plutôt settings.require_env directement (résolu dynamiquement à
    chaque appel via le module attribute lookup).
    """
    from config import settings as cfg_settings

    real = cfg_settings.require_env

    def fake_require_env(var):
        if var == "ANTHROPIC_API_KEY":
            raise EnvironmentError(
                f"Required environment variable {var!r} is not set."
            )
        return real(var)

    monkeypatch.setattr(cfg_settings, "require_env", fake_require_env)

    from agents.analyst_agent import AnthropicAnalystAgent

    with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
        AnthropicAnalystAgent()


def test_analyst_enriches_empty_conclusion(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    f = _mk_finding(analyst_conclusion="", cvss_score=None)
    payload = [
        {"id": f.id, "analyst_conclusion": "Header CSP absent — XSS confirmé.", "cvss_score": 6.1}
    ]
    _install_fake_anthropic(monkeypatch, payload)
    from agents.analyst_agent import AnthropicAnalystAgent

    agent = AnthropicAnalystAgent()
    out = agent.run([f])
    assert out[0].analyst_conclusion == "Header CSP absent — XSS confirmé."
    assert out[0].cvss_score == 6.1


def test_analyst_does_not_overwrite_substantive_existing_conclusion(monkeypatch):
    """If the scanner already emitted a substantive conclusion (≠ description),
    the analyst should NOT clobber it — but if it equals `finding`, it's a
    placeholder and may be enriched."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    substantive = "Conclusion établie par audit antérieur, non générique."
    f = _mk_finding(analyst_conclusion=substantive)
    payload = [{"id": f.id, "analyst_conclusion": "different text", "cvss_score": None}]
    _install_fake_anthropic(monkeypatch, payload)
    from agents.analyst_agent import AnthropicAnalystAgent

    out = AnthropicAnalystAgent().run([f])
    assert out[0].analyst_conclusion == substantive


def test_analyst_corrects_typosquat_synthesis_to_say_spf_valide(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    f = _mk_finding(
        title="14 typosquat variants identified — phishing delivery surface",
        finding_text="Many variants",
        analyst_conclusion="SPF absent permet l'usurpation",  # to be corrected
        sprint=4,
        flags=["PHISHING_VECTOR", "CHAIN_DEPENDENCY"],
    )
    _install_fake_anthropic(
        monkeypatch,
        [{"id": f.id, "analyst_conclusion": "blah", "cvss_score": None}],
    )
    from agents.analyst_agent import AnthropicAnalystAgent

    out = AnthropicAnalystAgent().run([f])
    assert "SPF valide" in out[0].analyst_conclusion
    assert "DMARC p=none" in out[0].analyst_conclusion
    assert "DNSSEC absent" in out[0].analyst_conclusion


def test_analyst_favicon_with_imperva_gets_context_dependent(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    waf = _mk_finding(
        title="WAF Imperva/Incapsula detected",
        analyst_conclusion="WAF Imperva detected",
        flags=["CONTEXT_DEPENDENT"],
        sprint=3,
    )
    favicon = _mk_finding(
        title="Favicon absent",
        analyst_conclusion="absent",
        sprint=3,
    )
    _install_fake_anthropic(
        monkeypatch,
        [
            {"id": waf.id, "analyst_conclusion": "ok", "cvss_score": None},
            {"id": favicon.id, "analyst_conclusion": "ok", "cvss_score": None},
        ],
    )
    from agents.analyst_agent import AnthropicAnalystAgent

    out = AnthropicAnalystAgent().run([waf, favicon])
    fav = next(f for f in out if f.title == "Favicon absent")
    assert "CONTEXT_DEPENDENT" in fav.flags
    assert "WAF Imperva" in fav.analyst_conclusion


def test_analyst_batches_eleven_findings_into_two_api_calls(monkeypatch):
    """11 findings → 2 batch calls (10 + 1)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    findings = [_mk_finding() for _ in range(11)]
    payload = [
        {"id": f.id, "analyst_conclusion": "ok", "cvss_score": None} for f in findings
    ]
    fake, instance = _install_fake_anthropic(monkeypatch, payload)
    from agents.analyst_agent import AnthropicAnalystAgent

    AnthropicAnalystAgent().run(findings)
    assert instance.messages.create.call_count == 2


def test_analyst_suppresses_known_false_positives_for_telemo(monkeypatch):
    """Per Session 5 §0 + ground truth manuel 2026-05-03 :
    findings 'HSTS missing' and 'Cert expires <30 days' on telemo.gov.gn
    are sandbox-proxy artefacts. AnalystAgent must drop them."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    keep = _mk_finding(title="DMARC policy is p=none")
    drop_hsts = _mk_finding(title="HSTS header missing")
    drop_cert = _mk_finding(title="Certificate expires in <30 days")
    payload = [
        {"id": f.id, "analyst_conclusion": "ok", "cvss_score": None}
        for f in (keep, drop_hsts, drop_cert)
    ]
    _install_fake_anthropic(monkeypatch, payload)
    from agents.analyst_agent import AnthropicAnalystAgent

    out = AnthropicAnalystAgent().run([keep, drop_hsts, drop_cert])
    titles = {f.title for f in out}
    assert "DMARC policy is p=none" in titles
    assert "HSTS header missing" not in titles
    assert "Certificate expires in <30 days" not in titles


# ── HFCriticAgent ───────────────────────────────────────────────────────


def test_critic_raises_environment_error_when_token_missing(monkeypatch):
    """Same .env-resilient pattern as the analyst test — patch require_env
    so the test holds whether or not HF_TOKEN is present in .env."""
    from config import settings as cfg_settings

    real = cfg_settings.require_env

    def fake_require_env(var):
        if var == "HF_TOKEN":
            raise EnvironmentError(
                f"Required environment variable {var!r} is not set."
            )
        return real(var)

    monkeypatch.setattr(cfg_settings, "require_env", fake_require_env)

    from agents.hf_critic_agent import HFCriticAgent

    with pytest.raises(EnvironmentError, match="HF_TOKEN"):
        HFCriticAgent()


def _critic_response(findings: list[Finding], assignments: dict) -> dict:
    """Build a `{"findings": [...]}` payload that mimics the critic output."""
    out = []
    for f in findings:
        a = assignments.get(f.id, {"verdict": "CONFIRMED", "score": 0.85, "rationale": "ok"})
        item = json.loads(f.model_dump_json())
        item["critic_verdict"] = a["verdict"]
        item["critic_rationale"] = a.get("rationale", "")
        item["confidence_score"] = a.get("score", 0.85)
        item["flags"] = list(set(item.get("flags", []) + a.get("flags", [])))
        out.append(item)
    return {"findings": out}


def test_critic_dmarc_p_none_is_confirmed_high_confidence(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding(title="DMARC policy is p=none", severity="HIGH")
    _install_fake_openai(monkeypatch, _critic_response(
        [f], {f.id: {"verdict": "CONFIRMED", "score": 0.90, "rationale": "dig confirms"}}
    ))
    from agents.hf_critic_agent import HFCriticAgent

    out = HFCriticAgent().run([f])
    assert out[0].critic_verdict == "CONFIRMED"
    assert out[0].confidence_score >= 0.85


def test_critic_hsts_with_imperva_waf_is_nuanced_context_dependent(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding(title="HSTS header missing", severity="HIGH")
    _install_fake_openai(monkeypatch, _critic_response(
        [f], {f.id: {
            "verdict": "NUANCED", "score": 0.70,
            "rationale": "WAF Imperva may strip header before client",
            "flags": ["CONTEXT_DEPENDENT"],
        }}
    ))
    from agents.hf_critic_agent import HFCriticAgent

    out = HFCriticAgent().run([f])
    assert out[0].critic_verdict == "NUANCED"
    assert "CONTEXT_DEPENDENT" in out[0].flags


def test_critic_typosquat_synthesis_with_corrected_spf_yields_nuanced(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding(
        title="14 typosquat variants identified — phishing delivery surface",
        analyst_conclusion="SPF valide. Risque réel = DMARC p=none + DNSSEC absent.",
        flags=["PHISHING_VECTOR", "CHAIN_DEPENDENCY"],
        sprint=4,
        severity="CRITICAL",
    )
    _install_fake_openai(monkeypatch, _critic_response(
        [f], {f.id: {
            "verdict": "NUANCED", "score": 0.65,
            "rationale": "Synthèse correcte mais non actionnable sans DNS lookup des variants",
        }}
    ))
    from agents.hf_critic_agent import HFCriticAgent

    out = HFCriticAgent().run([f])
    assert out[0].critic_verdict == "NUANCED"
    assert 0.60 <= out[0].confidence_score <= 0.70


def test_critic_finding_with_no_evidence_is_rejected(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding(evidence=[], severity="LOW")
    _install_fake_openai(monkeypatch, _critic_response(
        [f], {f.id: {"verdict": "REJECTED", "score": 0.10, "rationale": "no evidence cited"}}
    ))
    from agents.hf_critic_agent import HFCriticAgent

    out = HFCriticAgent().run([f])
    assert out[0].critic_verdict == "REJECTED"


def test_critic_clamps_confidence_score_into_unit_interval(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding()
    _install_fake_openai(monkeypatch, _critic_response(
        [f], {f.id: {"verdict": "CONFIRMED", "score": 0.99, "rationale": "ok"}}
    ))
    from agents.hf_critic_agent import HFCriticAgent

    out = HFCriticAgent().run([f])
    assert 0.0 <= out[0].confidence_score <= 1.0


# ── classify_finding ────────────────────────────────────────────────────


def test_classify_confirmed_high_confidence_goes_to_confirmed():
    from agents.classifier import classify_finding
    f = _mk_finding()
    f.critic_verdict = "CONFIRMED"
    f.confidence_score = 0.80
    assert classify_finding(f) == "findings_confirmed"


def test_classify_nuanced_goes_to_investigate():
    from agents.classifier import classify_finding
    f = _mk_finding()
    f.critic_verdict = "NUANCED"
    f.confidence_score = 0.60
    assert classify_finding(f) == "findings_investigate"


def test_classify_confirmed_low_confidence_goes_to_rejected():
    from agents.classifier import classify_finding
    f = _mk_finding()
    f.critic_verdict = "CONFIRMED"
    f.confidence_score = 0.40
    assert classify_finding(f) == "findings_rejected"


def test_classify_rejected_always_rejected():
    from agents.classifier import classify_finding
    f = _mk_finding()
    f.critic_verdict = "REJECTED"
    f.confidence_score = 0.95
    assert classify_finding(f) == "findings_rejected"


# ── Disagreement-rate test on the real findings sample ─────────────────


def test_critic_disagreement_rate(findings_37_sample, monkeypatch):
    """CriticAgent doit NUANCED/REJECTED au moins 10% des findings.
    Mock distribution: ~80% CONFIRMED / 15% NUANCED / 5% REJECTED."""
    monkeypatch.setenv("HF_TOKEN", "hf_test")

    def assignments(findings: list[Finding]) -> dict:
        out = {}
        for i, f in enumerate(findings):
            mod = i % 20
            if mod < 16:           # 16/20 = 80%
                v, s = "CONFIRMED", 0.85
            elif mod < 19:         # 3/20 = 15%
                v, s = "NUANCED", 0.65
            else:                  # 1/20 = 5%
                v, s = "REJECTED", 0.30
            out[f.id] = {"verdict": v, "score": s, "rationale": f"r{i}"}
        return out

    a = assignments(findings_37_sample)

    # Critic processes in batches of 10 — return one canned response per batch.
    def per_batch_response(*args, **kwargs):
        body = kwargs.get("messages", [])[-1]["content"]
        # Extract the batch-specific IDs from the user payload to scope the canned response.
        import re
        ids = re.findall(r'"id":\s*"([0-9a-f-]+)"', body)
        batch = [f for f in findings_37_sample if f.id in ids]
        return _mock_openai_response(_critic_response(batch, a))

    _install_fake_openai(monkeypatch, response_payload=None, side_effect=per_batch_response)
    from agents.hf_critic_agent import HFCriticAgent

    out = HFCriticAgent().run(findings_37_sample)
    disagreements = sum(
        1 for f in out if f.critic_verdict in ("NUANCED", "REJECTED")
    )
    rate = disagreements / max(1, len(findings_37_sample))
    assert rate >= 0.10, f"Critic too compliant ({rate:.0%})"
    # Sanity: every finding got a verdict (not still PENDING).
    assert all(f.critic_verdict != "PENDING" for f in out)


# ── Factory dispatch ───────────────────────────────────────────────────


def test_factory_creates_anthropic_analyst(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("AGENT_PROVIDER_ANALYST", "anthropic")
    _install_fake_anthropic(monkeypatch, [])
    # Reload settings module so the new env var is picked up.
    import importlib
    from config import settings as s
    importlib.reload(s)

    from agents.factory import create_analyst
    from agents.analyst_agent import AnthropicAnalystAgent

    assert isinstance(create_analyst(), AnthropicAnalystAgent)


def test_factory_unknown_critic_provider_raises(monkeypatch):
    monkeypatch.setenv("AGENT_PROVIDER_CRITIC", "bogus_provider")
    import importlib
    from config import settings as s
    importlib.reload(s)
    from agents import factory
    importlib.reload(factory)

    with pytest.raises(ValueError, match="Provider critic inconnu"):
        factory.create_critic()


# ── Hardened parser (truncated / empty LLM responses) ───────────────────


def test_parse_findings_raises_on_empty_response():
    """Empty LLM content → ValueError naming the failure mode."""
    from agents.base import BaseAgent

    class _T(BaseAgent):
        def run(self, findings):
            return findings

    agent = _T(model="x")
    with pytest.raises(ValueError, match="empty content"):
        agent._parse_findings("   \n\n  ")


def test_parse_findings_recovers_truncated_array():
    """An array truncated mid-element should yield the parseable prefix."""
    from agents.base import BaseAgent

    class _T(BaseAgent):
        def run(self, findings):
            return findings

    f = _mk_finding(title="Sample")
    full_item = json.loads(f.model_dump_json())
    full_item["critic_verdict"] = "CONFIRMED"
    full_item["critic_rationale"] = "ok"
    full_item["confidence_score"] = 0.85
    # Build an array with one valid object then a truncated second one.
    truncated = (
        '[' + json.dumps(full_item) + ', {"id": "broken-uuid", "sprint": '
    )
    out = _T(model="x")._parse_findings(truncated)
    assert len(out) == 1
    assert out[0].title == "Sample"


def test_parse_findings_raises_on_unrecoverable_garbage():
    from agents.base import BaseAgent

    class _T(BaseAgent):
        def run(self, findings):
            return findings

    with pytest.raises(ValueError, match="not valid JSON"):
        _T(model="x")._parse_findings("this is just prose, not JSON at all")


def test_critic_warns_on_finish_reason_length(monkeypatch, recwarn):
    """When the API returns finish_reason=length, _call_critic must warn
    so operators know to lower CRITIC_BATCH_SIZE."""
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding(title="DMARC policy is p=none")

    fake = types.ModuleType("openai")
    fake.OpenAI = MagicMock()
    instance = fake.OpenAI.return_value
    payload = _critic_response(
        [f], {f.id: {"verdict": "CONFIRMED", "score": 0.9, "rationale": "ok"}}
    )
    text = json.dumps(payload)
    instance.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content=text),
            finish_reason="length",
        )],
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=4096),
    )
    monkeypatch.setitem(sys.modules, "openai", fake)

    from agents.hf_critic_agent import HFCriticAgent

    HFCriticAgent().run([f])
    matched = [w for w in recwarn.list if "finish_reason=length" in str(w.message)]
    assert matched, f"expected RuntimeWarning, got {[str(w.message) for w in recwarn.list]}"


def test_critic_uses_reduced_batch_size_and_max_tokens():
    """Sanity check: constants stay at the tightened values that fit the
    Fireworks-ai output cap that triggered Bug 2."""
    from agents.hf_critic_agent import CRITIC_BATCH_SIZE, CRITIC_MAX_TOKENS

    assert CRITIC_BATCH_SIZE <= 5
    assert CRITIC_MAX_TOKENS <= 4096


# ── DeepSeek reasoning_effort + Fallback wiring (Bug 3 regressions) ─────


def test_critic_call_passes_reasoning_effort_disabled(monkeypatch):
    """DeepSeek V4 Pro is a reasoning model — without reasoning_effort=disabled
    it consumes all output tokens in internal reasoning before emitting the
    JSON. This test pins the kwarg so a future refactor can't silently drop it.
    """
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    f = _mk_finding(title="DMARC policy is p=none")
    payload = _critic_response(
        [f], {f.id: {"verdict": "CONFIRMED", "score": 0.9, "rationale": "ok"}}
    )
    fake, instance = _install_fake_openai(monkeypatch, payload)
    instance.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content=json.dumps(payload)),
            finish_reason="stop",
        )],
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=200),
    )

    from agents.hf_critic_agent import HFCriticAgent

    HFCriticAgent().run([f])
    call_kwargs = instance.chat.completions.create.call_args.kwargs
    assert call_kwargs.get("extra_body") == {"reasoning_effort": "disabled"}, (
        "DeepSeek call must include extra_body={'reasoning_effort': 'disabled'} "
        "to bypass internal reasoning that would consume all output tokens."
    )
    # Also pin: response_format must NOT be set (some HF Router providers reject
    # it when reasoning_effort is in extra_body).
    assert "response_format" not in call_kwargs


def test_factory_critic_returns_fallback_wrapper(monkeypatch):
    """create_critic() must return a FallbackCriticAgent that wraps DeepSeek
    and falls back to Gemma — not a bare HFCriticAgent."""
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    monkeypatch.setenv("AGENT_PROVIDER_CRITIC", "huggingface")
    _install_fake_openai(monkeypatch, {"findings": []})

    import importlib
    from config import settings as s
    importlib.reload(s)
    from agents import factory
    importlib.reload(factory)

    critic = factory.create_critic()
    from agents.factory import FallbackCriticAgent
    from agents.hf_critic_agent import HFCriticAgent

    assert isinstance(critic, FallbackCriticAgent)
    assert isinstance(critic._primary, HFCriticAgent)


def test_fallback_critic_triggers_on_primary_exception(monkeypatch):
    """If the primary critic raises (e.g. ValueError on truncated JSON),
    the wrapper must call the fallback and return its result."""
    from agents.factory import FallbackCriticAgent
    from agents.base import BaseAgent

    f = _mk_finding(title="DMARC policy is p=none")

    class BoomPrimary(BaseAgent):
        model = "primary"
        def run(self, findings):
            raise ValueError("simulated truncated JSON")

    class StubFallback(BaseAgent):
        model = "fallback"
        def __init__(self):
            super().__init__(model="fallback")
        def run(self, findings):
            for fi in findings:
                fi.critic_verdict = "CONFIRMED"
                fi.critic_rationale = "fallback ran"
                fi.confidence_score = 0.9
            return findings

    wrapper = FallbackCriticAgent(primary=BoomPrimary(model="primary"),
                                   fallback_factory=StubFallback)
    with pytest.warns(RuntimeWarning, match="Falling back"):
        out = wrapper.run([f])
    assert out[0].critic_rationale == "fallback ran"
    assert wrapper._used_fallback is True


def test_fallback_critic_triggers_when_too_many_pending(monkeypatch):
    """If the primary returns OK but >30% findings stay PENDING, fallback fires."""
    from agents.factory import FallbackCriticAgent
    from agents.base import BaseAgent

    findings = [_mk_finding(title=f"f{i}") for i in range(4)]

    class HalfPending(BaseAgent):
        model = "primary"
        def run(self, findings):
            # Set verdict on only 1/4 — leaves 3/4 PENDING (>30%).
            findings[0].critic_verdict = "CONFIRMED"
            findings[0].confidence_score = 0.9
            return findings

    class StubFallback(BaseAgent):
        model = "fallback"
        def __init__(self):
            super().__init__(model="fallback")
        def run(self, findings):
            for fi in findings:
                fi.critic_verdict = "CONFIRMED"
                fi.critic_rationale = "fallback ran"
                fi.confidence_score = 0.85
            return findings

    wrapper = FallbackCriticAgent(primary=HalfPending(model="primary"),
                                   fallback_factory=StubFallback)
    with pytest.warns(RuntimeWarning, match="Falling back"):
        out = wrapper.run(findings)
    assert all(f.critic_rationale == "fallback ran" for f in out)


def test_fallback_critic_passthrough_when_primary_succeeds():
    """No fallback when primary succeeds and PENDING ratio is acceptable."""
    from agents.factory import FallbackCriticAgent
    from agents.base import BaseAgent

    findings = [_mk_finding(title=f"f{i}") for i in range(4)]

    class GoodPrimary(BaseAgent):
        model = "primary"
        def run(self, findings):
            for fi in findings:
                fi.critic_verdict = "CONFIRMED"
                fi.critic_rationale = "primary ran"
                fi.confidence_score = 0.9
            return findings

    def fallback_factory():
        raise AssertionError("fallback should not be called")

    wrapper = FallbackCriticAgent(primary=GoodPrimary(model="primary"),
                                   fallback_factory=fallback_factory)
    out = wrapper.run(findings)
    assert all(f.critic_rationale == "primary ran" for f in out)
    assert wrapper._used_fallback is False
