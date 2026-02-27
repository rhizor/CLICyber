"""
Tests for the self‑learning mechanism of the CyberAgent CLI.

These tests ensure that scan history is recorded, that the learn command produces
useful statistics from this history, and that AI summarisation can be invoked.
"""

import os
import json
from typer.testing import CliRunner

from cybercli.cli import app, _HISTORY_FILE

runner = CliRunner()


def setup_function(func):  # noqa: D401
    """Remove history file before each test to ensure isolation."""
    try:
        os.remove(_HISTORY_FILE)
    except OSError:
        pass


def test_learn_generates_history_and_analysis():
    # Start a temporary HTTP server on a common port (8080) to ensure at least one open port
    import threading
    import http.server

    port = 8080
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    try:
        # Run a network scan to populate history. Use top-ports 20 to include port 8080 from the common list.
        runner.invoke(app, ["scan", "network", "127.0.0.1", "--top-ports", "20"], env={})
        # Ensure history file was created
        assert os.path.isfile(_HISTORY_FILE)
        # Now run learn command
        result = runner.invoke(app, ["learn", "--top", "2"])
        assert result.exit_code == 0
        # Should list at least one port
        assert "Port" in result.output
    finally:
        httpd.shutdown()


def test_learn_ai():
    # Populate history with multiple scans of the local host
    runner.invoke(app, ["scan", "network", "127.0.0.1", "--top-ports", "5"], env={})
    runner.invoke(app, ["scan", "network", "127.0.0.1", "--top-ports", "5"], env={})
    env = {"CYBERCLI_AI_API_KEY": "dummy"}
    result = runner.invoke(app, ["learn", "--ai"], env=env)
    assert result.exit_code == 0
    # Should mention AI analysis header
    assert "AI analysis" in result.output