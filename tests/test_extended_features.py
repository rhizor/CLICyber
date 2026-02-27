"""
Tests for the extended features of the CyberAgent CLI including
malware scanning, hardening checks, Blue Team operations and Red Team
simulations. These tests ensure that the new engines integrate with
the CLI and produce expected outputs in controlled conditions.
"""

import os
import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cybercli.cli import app, _LABS_DIR


runner = CliRunner()


def test_malware_scan_detects_malicious_file(tmp_path):
    # Create a temporary file with known contents
    malicious_content = b"evil malware"
    malicious_file = tmp_path / "infected.bin"
    malicious_file.write_bytes(malicious_content)
    # Compute SHA256 manually to build signature DB
    import hashlib

    sha256 = hashlib.sha256(malicious_content).hexdigest()
    sig_db_path = tmp_path / "db.json"
    sig_db_path.write_text(json.dumps({sha256: "TestMalware"}))
    # Run malware scan on the temp directory
    result = runner.invoke(
        app,
        ["scan", "malware", str(tmp_path), "--signature-db", str(sig_db_path), "--no-recurse"],
    )
    assert result.exit_code == 0
    # Expect detection message and file path in output
    assert "Potential malware detected" in result.output
    assert str(malicious_file) in result.output
    assert "TestMalware" in result.output


def test_hardening_command_executes():
    # Run hardening scan; do not assert specific checks as system state varies
    result = runner.invoke(app, ["scan", "hardening"])  # uses default profile
    assert result.exit_code == 0
    # Should mention assessment complete
    assert "Hardening assessment completed" in result.output


def test_blue_vuln_scan_manual_ports():
    # Provide manual ports for vulnerability scan
    result = runner.invoke(
        app,
        ["blue", "vuln-scan", "--no-use-history", "--ports", "22,80"],
    )
    assert result.exit_code == 0
    # Should list recommendations for SSH and HTTP
    assert "SSH uses strong encryption" in result.output or "HTTP traffic is unencrypted" in result.output


def test_blue_log_analysis(tmp_path):
    # Create a fake log file with failed login entries
    log_file = tmp_path / "auth.log"
    log_contents = """
    Feb  1 12:00:00 host sshd[123]: Failed password for invalid user test from 192.168.1.1 port 22
    Feb  1 12:00:01 host sshd[123]: Failed password for invalid user admin from 192.168.1.1 port 22
    Feb  1 12:00:02 host sshd[123]: Failed password for invalid user root from 10.0.0.5 port 22
    """
    log_file.write_text(log_contents.strip())
    result = runner.invoke(app, ["blue", "log-analysis", str(log_file)])
    assert result.exit_code == 0
    assert "Failed login attempts" in result.output
    assert "192.168.1.1" in result.output
    assert "10.0.0.5" in result.output


def test_red_exploit_lab(tmp_path):
    # Create a lab with a challenge and a flag
    from cybercli.cli import _ensure_config_dir
    import shutil
    # Clean labs directory
    if os.path.isdir(_LABS_DIR):
        shutil.rmtree(_LABS_DIR)
    _ensure_config_dir()
    lab_name = "exploitlab"
    lab_dir = Path(_LABS_DIR) / lab_name
    (lab_dir / "challenge1").mkdir(parents=True, exist_ok=True)
    (lab_dir / "challenge1" / "flag.txt").write_text("FLAG{pwned}")
    # Run exploit-lab command
    result = runner.invoke(app, ["red", "exploit-lab", lab_name])
    assert result.exit_code == 0
    assert "FLAG{pwned}" in result.output
    # Destroy lab
    shutil.rmtree(_LABS_DIR)