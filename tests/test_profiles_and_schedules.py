"""
Tests for scan profile and scheduling management.

These tests ensure profiles can be saved, listed and executed, and that scheduled
scans can be added, listed and removed without persisting state across tests.
"""

import os
import json
import tempfile
from typer.testing import CliRunner

from cybercli.cli import app, _PROFILES_FILE, _SCHEDULES_FILE

runner = CliRunner()


def setup_module(module):  # noqa: D401
    """Clean up any existing configuration files before tests run."""
    # Ensure the config files are removed to avoid interference
    for path in (_PROFILES_FILE, _SCHEDULES_FILE):
        try:
            os.remove(path)
        except OSError:
            pass


def test_save_and_list_profile():
    # Save a profile
    result_save = runner.invoke(
        app,
        ["scan", "save-profile", "web", "--ports", "80,443", "--description", "Web services"],
    )
    assert result_save.exit_code == 0
    assert "Saved scan profile 'web'" in result_save.output
    # List profiles
    result_list = runner.invoke(app, ["scan", "list-profiles"])
    assert result_list.exit_code == 0
    assert "web" in result_list.output


def test_run_saved_profile():
    # Ensure profile exists
    runner.invoke(app, ["scan", "save-profile", "ssh", "--ports", "22"], env={})
    result = runner.invoke(app, ["scan", "run-profile", "ssh", "10.0.0.0/24"], env={})
    assert result.exit_code == 0
    # Should show the target and ports in the JSON output
    assert "10.0.0.0/24" in result.output
    assert "22" in result.output


def test_schedule_add_list_remove():
    # Add a schedule
    result_add = runner.invoke(
        app,
        ["schedule", "add", "daily-scan", "192.168.0.0/24", "--cron", "0 3 * * *", "--ports", "22,80"],
    )
    assert result_add.exit_code == 0
    assert "Scheduled scan 'daily-scan'" in result_add.output
    # List schedules
    result_list = runner.invoke(app, ["schedule", "list"])
    assert result_list.exit_code == 0
    assert "daily-scan" in result_list.output
    # Remove schedule
    result_remove = runner.invoke(app, ["schedule", "remove", "daily-scan"])
    assert result_remove.exit_code == 0
    assert "Removed scheduled scan 'daily-scan'" in result_remove.output
    # List again should show nothing or indicate no schedules
    result_list2 = runner.invoke(app, ["schedule", "list"])
    assert result_list2.exit_code == 0
    assert "No scans have been scheduled" in result_list2.output