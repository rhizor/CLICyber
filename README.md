# cybercli

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Tests-17%2F17-success-green.svg" alt="Tests">
</p>

`cybercli` provides an interactive command‑line interface modelled on the CyberAgent platform.  
It allows users of varying skill levels to perform network scans, query threat intelligence sources,
generate reports, check compliance against ISO&nbsp;27001 controls, create CTF laboratories, and
leverage AI models (such as Gemini or OpenAI) to summarise findings and propose remediation steps.

## ⚠️ Security Features

This project includes security-hardened code:
- **Command Blocklisting**: Dangerous commands (rm -rf, fork bombs, etc.) are blocked in remediation
- **SSL/TLS Verification**: All HTTP requests verify SSL certificates by default
- **Timeout Protection**: Commands execute with 30-second timeout to prevent hangs
- **Audit Logging**: All remediation attempts are logged

## Installation

Install in editable mode within a Python ≥ 3.8 environment:

```bash
pip install -e .
```

If your environment lacks build tools, you can still run the CLI by adding the project
root to your ``PYTHONPATH``:

```bash
export PYTHONPATH="$(pwd)"  # from the repository root
pytest  # run the test suite
```

## Features

– **Network scans:** perform real asynchronous port scans over IPv4 ranges using
  Python’s socket library. Users can specify the number of top ports to scan
  or define custom port lists via scan profiles. Results are recorded for
  self‑learning and later analysis.
– **Malware scanning:** compute SHA256 hashes for files within a given path and
  compare them against a user‑supplied database of known malicious hashes.
  Results identify which files match known malware signatures.
– **System hardening checks:** evaluate common security settings including
  SSH root login (`PermitRootLogin no`), password complexity (minimum
  length and rotation), and host firewall status. Each check includes
  remediation recommendations.
– **Blue Team operations:** assess vulnerabilities based on open ports (e.g.,
  recommending TLS enforcement on port 80/443) and perform log analysis to
  detect repeated failed login attempts across IP addresses.
– **Red Team operations:** safely exploit CTF labs created by the tool by
  reading flags within challenge directories. In real deployments this can be
  extended to run actual exploitation scripts.
– **Threat hunting and anomaly detection:** analiza los datos históricos de los
  escaneos para detectar cambios de puertos entre escaneos y calcular
  puntuaciones de riesgo por host. Esto ayuda a priorizar los equipos que
  exponen servicios de alto riesgo e identifica cambios inesperados en la
  superficie de ataque.
– **Authentication analysis:** parse authentication logs to flag logins outside
  normal working hours and summarise failed login attempts per source. This
  supports monitoring for compromised accounts and brute‑force attacks.
– **Dynamic CTF labs:** optionally generate a vulnerable web service challenge
  with a simple Python HTTP server that reflects user input, enabling users to
  practise exploiting cross‑site scripting (XSS) vulnerabilities.
– **Data export:** export scan history to JSON for integration with SIEM or
  other analysis tools.
– **Threat intelligence queries:** gather basic threat‑intel data for IPs,
  domains or hashes; optionally summarise results with AI assistance.
– **Reporting:** generate technical, executive or compliance reports in PDF,
  HTML or JSON formats with optional AI‑generated narrative sections.
– **ISO 27001 compliance check:** evaluate your implementation of the four
  control themes (organizational, people, physical and technological) defined in
  ISO 27001:2022【545426540923872†L61-L71】. Supports interactive prompts or
  reading from a JSON/YAML file and can provide AI‑driven recommendations.
– **Remediation and rollback:** simulate remediation actions on identified
  findings and support rolling back changes.
– **Scan profiles and scheduling:** save custom port profiles, reuse them on
  demand and schedule recurring scans using cron expressions stored locally.
– **CTF lab automation:** provision Capture‑The‑Flag training labs under
  ``~/.cybercli/labs`` with configurable numbers of challenges, list existing
  labs and destroy them when no longer needed.
– **Self‑learning mechanism:** record scan results and analyse them to
  identify frequently open ports; use AI to recommend remediation steps.
– **CVE Monitoring:** query NVD and CIRCL CVE databases, search by CVE ID,
  keyword, or product, view recent vulnerabilities with severity ratings.
– **Container Security:** scan Docker containers and Kubernetes clusters for
  security issues including privilege escalation, exposed sensitive ports,
  insecure image tags, and RBAC misconfigurations.
– **File Integrity Monitoring (FIM):** create baselines, monitor files for
  changes, detect modifications, deletions, and permission changes.
– **SIEM Integration:** send events to Splunk (HEC), Elasticsearch/ELK,
  Syslog (UDP/TCP), and custom webhooks.
– **REST API:** FastAPI-based REST API server for programmatic access to
  all CLI features.

## Usage

Invoke the CLI as follows:

```bash
python -m cybercli --help           # list top-level commands
python -m cybercli scan network 10.0.0.0/24 --top-ports 50
python -m cybercli scan save-profile web --ports 80,443 --description "Web services"
python -m cybercli scan run-profile web 10.0.0.0/24
python -m cybercli schedule add weekly-scan 10.0.0.0/24 --cron "0 0 * * 0" --profile web
python -m cybercli compliance --ai               # interactive compliance check with AI advice
python -m cybercli ctf create mylab --challenges 3
python -m cybercli learn --ai                    # analyse history and get AI recommendations
python -m cybercli scan malware /var/www --signature-db signatures.json  # scan directory for malware
python -m cybercli scan hardening                # evaluate system hardening
python -m cybercli blue vuln-scan                # generate vulnerability recommendations from last scan
python -m cybercli blue log-analysis /var/log/auth.log  # detect failed login attempts
python -m cybercli red exploit-lab mylab         # simulate exploitation of a CTF lab
python -m cybercli blue auth-analysis /var/log/auth.log --start-hour 0 --end-hour 6  # detect logins outside midnight-6am
python -m cybercli hunt anomalies                 # find changes in open ports across scans
python -m cybercli hunt risk-scores              # calculate risk scores for hosts based on last scan
python -m cybercli export history history.json   # export scan history to a JSON file for SIEM integration

# CVE Monitoring
python -m cybercli.cli cve search CVE-2024-1234 --detailed  # search specific CVE
python -m cybercli.cli cve recent --days 7 --limit 10        # recent CVEs
python -m cybercli.cli cve product nginx --vendor apache    # CVEs by product

# Container Security
python -m cybercli.cli container docker      # scan Docker containers
python -m cybercli.cli container kubernetes  # scan K8s cluster

# File Integrity Monitoring
python -m cybercli.cli fim create-baseline /etc --recursive  # create baseline
python -m cybercli.cli fim check                                   # check integrity
python -m cybercli.cli fim monitor /var/www --interval 30        # continuous monitoring
python -m cybercli.cli fim list                                    # list baseline

# SIEM Integration
python -m cybercli.cli siem send splunk "Test alert" --host splunk.example.com
python -m cybercli.cli siem test elk --host elk.example.com:9200

# REST API Server
python -m cybercli.cli api --host 0.0.0.0 --port 8000
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CYBERCLI_AI_API_KEY` | API key for AI features (Gemini, OpenAI) |
| `SHODAN_API_KEY` | Shodan API for threat intelligence |
| `ABUSEIPDB_API_KEY` | AbuseIPDB for IP reputation |
| `VIRUSTOTAL_API_KEY` | VirusTotal for malware scanning |
| `NVD_API_KEY` | National Vulnerability Database API key |
| `SPLUNK_HEC_TOKEN` | Splunk HTTP Event Collector token |
| `SPLUNK_USERNAME` | Splunk username |
| `SPLUNK_PASSWORD` | Splunk password |
| `ELASTIC_HOST` | Elasticsearch host (default: localhost:9200) |
| `ELASTIC_API_KEY` | Elasticsearch API key |
| `SMTP_SERVER` | SMTP server for email alerts |
| `SMTP_PORT` | SMTP port (default: 587) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASSWORD` | SMTP password |
| `SLACK_WEBHOOK_URL` | Slack webhook for alerts |
| `TELEGRAM_TOKEN` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | Telegram chat ID |

Configure an AI provider by setting ``CYBERCLI_AI_API_KEY`` in your environment.
Currently the AI integration uses a placeholder; integrate with Gemini or OpenAI
SDKs in a full deployment. See the source code for details on extending the
interfaces.