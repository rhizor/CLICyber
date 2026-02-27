# Lessons and Improvements

This file captures lessons learned and patterns to avoid repeating mistakes during the development of the CyberAgent CLI. Whenever the user provides corrections or feedback, summarise the issues here and describe rules or strategies to prevent similar problems in the future.

## Entries

### Handling package imports without pip

During early testing we attempted to install the CLI package via ``pip install -e .``, but the container lacked the necessary build dependencies (e.g. ``setuptools>=42``), causing installation to fail. To resolve this without external dependencies, we configured ``pytest`` to include the project root in ``PYTHONPATH`` when running tests. This ensures that the ``cybercli`` package can be imported without requiring installation. In future projects running in constrained environments, prefer adjusting ``PYTHONPATH`` or using editable installs only when the environment supports them.

### Isolating test state

Initial tests did not clean up configuration files created under ``~/.cybercli`` (profiles, schedules, labs). This could cause state leakage between tests. We added setup functions that remove these files or directories at the start of tests to ensure isolation. When writing tests that modify the file system, always clean up after test execution to prevent interference.

### Aligning CLI output with test expectations

During the implementation of the Blue Team log analysis command, the tests were written to search for a specific phrase ("Failed login attempts") in the CLI output. The initial implementation used a lowercase phrase ("failed login attempts"), leading to test failures despite the functionality being correct. We resolved this by adjusting the output to match the expected case rather than weakening the test. Lesson: when tests assert on specific user‑facing strings, ensure the CLI output uses the agreed phrasing; if discrepancies arise, modify the implementation to align with expectations instead of altering the tests unless the tests are clearly wrong.