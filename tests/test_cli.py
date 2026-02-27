"""
Unit tests for the CyberAgent CLI skeleton.

These tests use Typer's CliRunner to invoke commands defined in
``cybercli.cli`` and assert that they produce expected output or exit
behaviour. The implementation is intentionally minimal and serves to
verify that the CLI command structure is sound and the placeholder
functions operate as intended.
"""

import os
import pytest
from typer.testing import CliRunner

from cybercli.cli import app


runner = CliRunner()


def test_scan_network():
    # Scan the local host for a small number of ports to ensure the scanner works and completes quickly.
    result = runner.invoke(app, ["scan", "network", "127.0.0.1", "--top-ports", "5"])
    assert result.exit_code == 0
    # Should include initiation and completion messages
    assert "Initiating network scan" in result.output
    assert "Network scan completed" in result.output
    # Should show results for the scanned host
    assert "Results for" in result.output


def test_ai_requires_key():
    # Ensure the environment variable is not set
    if "CYBERCLI_AI_API_KEY" in os.environ:
        del os.environ["CYBERCLI_AI_API_KEY"]
    result = runner.invoke(app, ["ai", "hello"], env={})
    # Expect exit due to missing key
    assert result.exit_code != 0
    assert "No AI API key configured" in result.output


def test_ai_with_key():
    # Set a dummy API key
    env = {"CYBERCLI_AI_API_KEY": "dummy"}
    result = runner.invoke(app, ["ai", "hello"], env=env)
    assert result.exit_code == 0
    # The placeholder reverses the prompt
    assert "olleh" in result.output


def test_ctf_create_list_and_destroy():
    # Ensure lab directory is clean before test
    from cybercli.cli import _LABS_DIR
    import shutil
    if os.path.isdir(_LABS_DIR):
        shutil.rmtree(_LABS_DIR)
    # Create a lab
    result_create = runner.invoke(app, ["ctf", "create", "testlab", "--challenges", "2"])
    assert result_create.exit_code == 0
    assert "CTF lab 'testlab'" in result_create.output
    # List labs
    result_list = runner.invoke(app, ["ctf", "list"])
    assert result_list.exit_code == 0
    assert "testlab (2 challenges)" in result_list.output
    # Destroy lab
    result_destroy = runner.invoke(app, ["ctf", "destroy", "testlab", "--force"])
    assert result_destroy.exit_code == 0
    assert "Lab 'testlab' removed" in result_destroy.output