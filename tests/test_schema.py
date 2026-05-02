"""
tests/test_schema.py
Valide le contrat API Finding (Mindset 10 — API Contract First).
"""
from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from pydantic import ValidationError

from schemas.finding import Finding


def _minimal_payload(**overrides):
    base = {
        "id": str(uuid.uuid4()),
        "sprint": 1,
        "tool": "recon",
        "target": "127.0.0.1",
        "title": "Open port detected",
        "finding": "Port 22/tcp ssh open",
        "analyst_conclusion": "SSH service exposed",
        "severity": "INFO",
    }
    base.update(overrides)
    return base


def test_minimal_finding_is_valid():
    f = Finding(**_minimal_payload())
    assert f.id
    assert f.sprint == 1
    assert isinstance(f.timestamp, datetime)
    # Defaults
    assert f.evidence == []
    assert f.flags == []
    assert f.critic_verdict == "PENDING"
    assert f.critic_rationale == ""
    assert f.confidence_score == 0.0
    assert f.cvss_score is None


def test_sprint_bounds_enforced():
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(sprint=0))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(sprint=6))


def test_severity_literal_enforced():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        Finding(**_minimal_payload(severity=sev))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(severity="UNKNOWN"))


def test_critic_verdict_literal_enforced():
    for v in ("CONFIRMED", "NUANCED", "REJECTED", "PENDING"):
        Finding(**_minimal_payload(critic_verdict=v))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(critic_verdict="MAYBE"))


def test_confidence_score_bounds():
    Finding(**_minimal_payload(confidence_score=0.0))
    Finding(**_minimal_payload(confidence_score=1.0))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(confidence_score=-0.1))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(confidence_score=1.01))


def test_cvss_score_bounds():
    Finding(**_minimal_payload(cvss_score=0.0))
    Finding(**_minimal_payload(cvss_score=10.0))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(cvss_score=-0.1))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(cvss_score=10.1))


def test_flags_literal_enforced():
    valid = [
        "CONTEXT_DEPENDENT",
        "NEEDS_RETEST",
        "FALSE_POSITIVE_RISK",
        "PHISHING_VECTOR",
        "CHAIN_DEPENDENCY",
    ]
    Finding(**_minimal_payload(flags=valid))
    with pytest.raises(ValidationError):
        Finding(**_minimal_payload(flags=["NOT_A_FLAG"]))


def test_required_fields_missing():
    payload = _minimal_payload()
    payload.pop("severity")
    with pytest.raises(ValidationError):
        Finding(**payload)


def test_json_roundtrip():
    f = Finding(**_minimal_payload(evidence=["HTTP/1.1 200 OK"]))
    raw = f.model_dump_json()
    restored = Finding.model_validate_json(raw)
    assert restored.id == f.id
    assert restored.evidence == ["HTTP/1.1 200 OK"]
    assert restored.severity == f.severity
