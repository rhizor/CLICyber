"""
Unit tests for the ISO 27001 compliance assessment command.

These tests verify both interactive and file‑based compliance checks. They also
validate that AI integration is invoked correctly when the ``--ai`` flag is
provided and an API key is set.
"""

import json
import os
import tempfile
from typer.testing import CliRunner

from cybercli.cli import app


runner = CliRunner()


def test_compliance_interactive_all_yes():
    """Simulate an interactive session where the user answers 'yes' to all themes."""
    # Four themes prompts -> 4 times 'y\n'
    user_input = "y\ny\ny\ny\n"
    result = runner.invoke(app, ["compliance"], input=user_input)
    assert result.exit_code == 0
    # Should report 4 out of 4 themes implemented
    assert "You have implemented 4 out of 4" in result.output
    # Each theme should be marked as implemented (✅)
    assert "✅ Organizational" in result.output
    assert "✅ People" in result.output
    assert "✅ Physical" in result.output
    assert "✅ Technological" in result.output


def test_compliance_file_partial():
    """Check compliance evaluation from a controls file with partial implementation."""
    # Create a temporary controls JSON file with only two themes implemented
    data = {
        "organizational": True,
        "people": False,
        "physical": True,
        "technological": False,
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        file_path = f.name
    try:
        result = runner.invoke(app, ["compliance", "--controls", file_path])
        assert result.exit_code == 0
        # Should report 2 out of 4 themes implemented
        assert "2 out of 4" in result.output
        # Check individual statuses
        assert "✅ Organizational" in result.output
        assert "❌ People" in result.output
        assert "✅ Physical" in result.output
        assert "❌ Technological" in result.output
    finally:
        os.unlink(file_path)


def test_compliance_ai_recommendations():
    """Ensure that the AI recommendation path executes when --ai is provided and key is set."""
    # Create a temporary file with minimal controls
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"organizational": False, "people": False, "physical": False, "technological": False}, f)
        file_path = f.name
    try:
        env = {"CYBERCLI_AI_API_KEY": "dummy"}
        result = runner.invoke(app, ["compliance", "--controls", file_path, "--ai"], env=env)
        # Should succeed
        assert result.exit_code == 0
        # Should include the AI recommendations section header
        assert "AI Recommendations" in result.output
    finally:
        os.unlink(file_path)