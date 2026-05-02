"""
tests/test_recon.py
Mocke subprocess.run pour éviter tout vrai scan nmap.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from schemas.finding import Finding
from tools import recon

NMAP_XML_TWO_OPEN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="0" version="7.94">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="http" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_NO_OPEN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="0" version="7.94">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset" reason_ttl="0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered" reason="no-response" reason_ttl="0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_UNUSUAL_PORT = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="0" version="7.94">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="2222">
        <state state="open" reason="syn-ack" reason_ttl="0"/>
        <service name="ssh" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _fake_proc(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["nmap"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_open_ports_produce_findings():
    with patch("tools.recon.subprocess.run", return_value=_fake_proc(NMAP_XML_TWO_OPEN)):
        findings = recon.scan("127.0.0.1")
    assert len(findings) == 2
    by_port = {int(f.evidence[0].split("/", 1)[0]): f for f in findings}
    assert by_port[80].severity == "LOW"
    assert by_port[443].severity == "INFO"
    assert by_port[80].sprint == 1
    assert by_port[80].tool == "recon"
    assert "http" in by_port[80].evidence[0]
    assert "https" in by_port[443].evidence[0]


def test_closed_ports_produce_no_findings():
    with patch("tools.recon.subprocess.run", return_value=_fake_proc(NMAP_XML_NO_OPEN)):
        findings = recon.scan("127.0.0.1")
    assert findings == []


def test_unusual_port_severity_medium():
    with patch("tools.recon.subprocess.run", return_value=_fake_proc(NMAP_XML_UNUSUAL_PORT)):
        findings = recon.scan("127.0.0.1")
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].evidence[0].startswith("2222/tcp open")


def test_out_of_scope_target_raises_value_error():
    # Should raise BEFORE subprocess is invoked.
    with patch("tools.recon.subprocess.run") as mock_run:
        with pytest.raises(ValueError, match="not in authorized scope"):
            recon.scan("evil.example.com")
        mock_run.assert_not_called()


def test_url_target_normalized_to_host():
    with patch("tools.recon.subprocess.run", return_value=_fake_proc(NMAP_XML_TWO_OPEN)) as mock_run:
        findings = recon.scan("http://127.0.0.1/login")
    cmd = mock_run.call_args.args[0]
    assert cmd[-1] == "127.0.0.1", f"nmap target should be host only, got {cmd[-1]}"
    assert all(f.target == "127.0.0.1" for f in findings)


def test_nmap_failure_raises_runtime_error():
    with patch("tools.recon.subprocess.run", return_value=_fake_proc("", returncode=2, stderr="boom")):
        with pytest.raises(RuntimeError, match="nmap failed"):
            recon.scan("127.0.0.1")


def test_write_findings_json_roundtrip(tmp_path: Path):
    with patch("tools.recon.subprocess.run", return_value=_fake_proc(NMAP_XML_TWO_OPEN)):
        findings = recon.scan("127.0.0.1")
    out = tmp_path / "recon.json"
    recon.write_findings(findings, out)

    raw = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(raw, list) and len(raw) == 2
    # Each entry must re-validate against the Finding schema.
    restored = [Finding.model_validate(item) for item in raw]
    assert {f.severity for f in restored} == {"LOW", "INFO"}
    assert all(f.tool == "recon" for f in restored)
