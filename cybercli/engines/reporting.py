"""Reporting engine for CyberCLI.

This module consolidates the generation of reports into HTML and PDF formats.
Reports summarise scan results, vulnerability assessments, anomalies and risk
scores.  Templates are defined inline using Jinja2 and can be customised
further by modifying the template string or supplying external templates.

If WeasyPrint is available, the HTML report can be converted to PDF.  If
WeasyPrint is not installed or fails, the caller should fall back to the
HTML version.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Any

from jinja2 import Environment, BaseLoader

try:
    from weasyprint import HTML  # type: ignore
except Exception:
    HTML = None  # type: ignore


def _create_environment() -> Environment:
    """Create a Jinja2 environment configured for our inline templates."""
    return Environment(loader=BaseLoader(), autoescape=True)


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #2c3e50; }
    h2 { color: #34495e; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .section { margin-bottom: 30px; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <p>Generated on {{ date }}</p>

  {% if scan_results %}
  <div class="section">
    <h2>Network Scan Results</h2>
    <table>
      <tr><th>Host</th><th>Open Ports</th></tr>
      {% for host, ports in scan_results.items() %}
      <tr><td>{{ host }}</td><td>{{ ports | join(', ') if ports else 'None' }}</td></tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

  {% if vulnerabilities %}
  <div class="section">
    <h2>Vulnerability Assessment</h2>
    {% for host, recs in vulnerabilities.items() %}
    <h3>{{ host }}</h3>
    <ul>
      {% for rec in recs %}
      <li>{{ rec }}</li>
      {% endfor %}
    </ul>
    {% endfor %}
  </div>
  {% endif %}

  {% if anomalies %}
  <div class="section">
    <h2>Port Anomalies</h2>
    {% for host, change in anomalies.items() %}
    <h3>{{ host }}</h3>
    <p>
      {% if change.added %}<strong>Added ports:</strong> {{ change.added | join(', ') }}<br>{% endif %}
      {% if change.removed %}<strong>Removed ports:</strong> {{ change.removed | join(', ') }}{% endif %}
    </p>
    {% endfor %}
  </div>
  {% endif %}

  {% if risk_scores %}
  <div class="section">
    <h2>Risk Scores</h2>
    <table>
      <tr><th>Host</th><th>Score</th></tr>
      {% for host, score in risk_scores.items() %}
      <tr><td>{{ host }}</td><td>{{ '{:.2f}'.format(score) }}</td></tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

</body>
</html>
"""


def generate_html_report(
    title: str,
    date: str,
    scan_results: Dict[str, List[int]] | None,
    vulnerabilities: Dict[str, List[str]] | None,
    anomalies: Dict[str, Dict[str, List[int]]] | None,
    risk_scores: Dict[str, float] | None,
) -> str:
    """Render an HTML report from the provided data.

    Args:
        title: Title of the report.
        date: Human-readable date string.
        scan_results: Mapping of host -> list of open ports.
        vulnerabilities: Mapping of host -> list of vulnerability recommendations.
        anomalies: Mapping of host -> {"added": [...], "removed": [...]}.
        risk_scores: Mapping of host -> risk score.

    Returns:
        A string containing the rendered HTML report.
    """
    env = _create_environment()
    tmpl = env.from_string(REPORT_TEMPLATE)
    return tmpl.render(
        title=title,
        date=date,
        scan_results=scan_results or {},
        vulnerabilities=vulnerabilities or {},
        anomalies=anomalies or {},
        risk_scores=risk_scores or {},
    )


def generate_pdf_report(html: str, output_path: Path) -> None:
    """Convert HTML content to a PDF file using WeasyPrint.

    Args:
        html: HTML string to convert.
        output_path: Path where the PDF will be written.

    Raises:
        RuntimeError: If WeasyPrint is not available.
    """
    if HTML is None:
        raise RuntimeError("WeasyPrint is not installed; PDF generation is unavailable.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(str(output_path))


def default_report_dir() -> Path:
    """Return the default directory for storing generated reports."""
    base = Path(os.path.expanduser("~/.cybercli"))
    return base / "reports"


__all__ = [
    "generate_html_report",
    "generate_pdf_report",
    "default_report_dir",
]