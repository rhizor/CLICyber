"""
Command‑line interface for CyberAgent.

This module defines a Typer application that exposes high‑level commands
to perform security scans, manage findings, execute remediations and
rollbacks, query threat intelligence sources, generate reports, check
ISO 27001 compliance, provision CTF laboratories, and leverage
generative AI (Gemini/OpenAI) for assisted analysis. Each command is
implemented as a placeholder demonstrating how it will interact with
other components; real logic should be added later. Input is validated
where appropriate, and helpful prompts are provided to guide junior
users while still offering concise options for experienced analysts.
"""

import json
import os
from datetime import datetime
from typing import Optional, Dict
from pathlib import Path

import typer

# Import engines used throughout the CLI.  Most modules are imported lazily
# within commands to avoid unnecessary overhead when a feature is unused.
from .engines.network_scanner import scan_network

# New engines for full implementation of missing features
# These imports are only for type hints and to surface modules at the package level.
from .engines import threat_intel as _threat_intel  # noqa: F401
from .engines import ml_classifier as _ml_classifier  # noqa: F401
from .engines import reporting as _reporting  # noqa: F401
from .engines import remediator as _remediator  # noqa: F401
from .engines import alerting as _alerting  # noqa: F401
from .engines import geoip as _geoip  # noqa: F401

# Create the main Typer app
app = typer.Typer(
    help="CyberAgent CLI – automate security scans, intelligence, remediation, reports and compliance checks."
)

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _load_ai_credentials() -> Optional[str]:
    """Return the API key for the AI service (Gemini/OpenAI) from environment variables.

    If no key is configured, return ``None``. In a real implementation, you may
    support multiple providers and perform additional validation.
    """
    return os.environ.get("CYBERCLI_AI_API_KEY")


def _safe_print_json(data) -> None:
    """Pretty‑print a Python object as JSON without exposing sensitive keys."""
    print(json.dumps(data, indent=2, default=str))


def _require_ai_key() -> str:
    key = _load_ai_credentials()
    if not key:
        typer.echo("❌ No AI API key configured. Set CYBERCLI_AI_API_KEY in your environment.")
        raise typer.Exit(code=1)
    return key


# ---------------------------------------------------------------------------
# Scan command group
# ---------------------------------------------------------------------------
scan_app = typer.Typer(help="Run security scans on networks, hosts and systems.")

# Paths for storing user configuration, such as scan profiles and schedules. These are
# stored in the user's home directory under a hidden folder to avoid polluting
# project repositories. Creating these directories when needed keeps the CLI
# functional even when run by junior users who may not have set up custom
# configuration locations.
_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".cybercli")
_PROFILES_FILE = os.path.join(_CONFIG_DIR, "profiles.json")
_SCHEDULES_FILE = os.path.join(_CONFIG_DIR, "schedules.json")
_HISTORY_FILE = os.path.join(_CONFIG_DIR, "history.json")
_LABS_DIR = os.path.join(_CONFIG_DIR, "labs")

def _ensure_config_dir() -> None:
    """Create the configuration directory if it does not exist."""
    if not os.path.isdir(_CONFIG_DIR):
        os.makedirs(_CONFIG_DIR, exist_ok=True)

def _load_json(path: str) -> dict:
    """Load a JSON file, returning an empty dict if the file does not exist."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_json(path: str, data: dict) -> None:
    """Save a JSON file safely."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _append_history(record: dict) -> None:
    """Append a scan record to the history file for self‑learning purposes."""
    _ensure_config_dir()
    history: list[dict] = []
    if os.path.isfile(_HISTORY_FILE):
        try:
            with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f) or []
        except Exception:
            history = []
    history.append(record)
    with open(_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, default=str)


@scan_app.command()
def network(
    target: str = typer.Argument(..., help="CIDR notation or IP address range to scan."),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of top ports to scan."),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed output."),
):
    """Perform a network port scan on the specified target range.

    This is a placeholder implementation that reports what would be scanned. In
    a complete version this function would interface with the CyberAgent scanner
    engine to perform host discovery and port enumeration.
    """
    typer.echo(f"🔍 Initiating network scan on {target} with top {top_ports} ports...")
    # Generate a basic list of ports: for demonstration use the most common ports
    # In a real implementation, this could be derived from nmap's top ports list.
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443,
    ]
    ports = common_ports[:top_ports] if top_ports <= len(common_ports) else common_ports
    # Perform the scan using the asynchronous scanner
    try:
        results = scan_network(target, ports)
    except Exception as exc:
        typer.echo(f"❌ An error occurred during scanning: {exc}")
        raise typer.Exit(code=1)
    # Record history per host
    for host, open_ports in results.items():
        record = {
            "target": host,
            "timestamp": datetime.now().isoformat(),
            "open_ports": open_ports,
        }
        _append_history(record)
    # Display results
    for host, open_ports in results.items():
        typer.echo(f"\n📍 Results for {host}:")
        if open_ports:
            typer.echo("  Open ports: " + ", ".join(str(p) for p in open_ports))
        else:
            typer.echo("  No open ports found on specified port list.")
    typer.echo("\n✅ Network scan completed. Results have been recorded.")


@scan_app.command()
def malware(
    path: str = typer.Argument("/", help="Directory path to analyse for malware."),
    recurse: bool = typer.Option(True, "--recurse/--no-recurse", help="Recursively analyse subdirectories."),
    signature_db: Optional[str] = typer.Option(
        None,
        "--signature-db",
        help="Path to a JSON file containing known malicious hashes.",
    ),
):
    """Run a malware scan on the specified directory.

    This implementation computes SHA256 hashes for each file under the given
    path and compares them against a database of known malicious hashes. If
    any matches are found, they are reported to the user. Use the
    ``--signature-db`` option to specify a custom database of SHA256 hashes.
    """
    from .engines import malware_scanner

    typer.echo(f"🦠 Starting malware scan on {path} (recursive={recurse})...")
    # Load hash database from user-supplied file if provided
    hash_db = None
    if signature_db:
        from pathlib import Path

        hash_db = malware_scanner._load_hash_db(Path(signature_db))
        typer.echo(f"📖 Loaded {len(hash_db)} signatures from {signature_db}.")
    results = malware_scanner.scan_path(path, hash_db=hash_db, recursive=recurse)
    infected_files = {fp: info for fp, (h, info) in results.items() if info}
    if infected_files:
        typer.echo("❗ Potential malware detected in the following files:")
        for fp, info in infected_files.items():
            hash_val, malware_info = results[fp]
            typer.echo(f"  - {fp} -> {malware_info or 'Unknown malware'} (hash={hash_val})")
    else:
        typer.echo("✅ No known malware detected.")


@scan_app.command()
def hardening(
    profile: str = typer.Option("cis-level1", "--profile", help="Benchmark profile to evaluate (e.g. cis-level1, cis-level2)."),
):
    """Evaluate system hardening against a given benchmark profile.

    This implementation performs a set of built‑in hardening checks such as
    verifying SSH root login restrictions, password complexity settings and
    firewall status. For each check it reports pass/fail and prints
    recommendations for remediation. Additional profiles can be added by
    extending the checks or integrating with external tools.
    """
    from .engines import hardening_checker

    typer.echo(f"🛡️ Assessing system hardening using profile '{profile}'...")
    results = hardening_checker.perform_hardening_checks()
    for res in results:
        symbol = "✅" if res.status else "❌"
        typer.echo(f"  {symbol} {res.name}: {res.description}")
        if not res.status:
            typer.echo(f"    ➤ Recommendation: {res.recommendation}")
    typer.echo("\n✅ Hardening assessment completed.")


@scan_app.command()
def full(
    target: str = typer.Argument(..., help="Network range to scan."),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of top ports for the network scan."),
):
    """Run the full suite of CyberAgent scans (network, malware and hardening)."""
    network(target, top_ports)
    malware("/")
    hardening()


# ---------------------------------------------------------------------------
# Scan profile management
# ---------------------------------------------------------------------------

@scan_app.command("save-profile")
def save_profile(
    name: str = typer.Argument(..., help="Name of the scan profile to save."),
    ports: str = typer.Option(
        "22,80,443", "--ports", help="Comma‑separated list of ports to include in the profile."
    ),
    description: str = typer.Option("", "--description", help="Human‑readable description of the profile."),
):
    """Save a custom scanning profile for reuse.

    Profiles are stored in a JSON file under ``~/.cybercli/profiles.json``. Each profile records
    the list of ports and an optional description. Users can later list and run these profiles
    without having to retype options each time.
    """
    _ensure_config_dir()
    profiles = _load_json(_PROFILES_FILE)
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    profiles[name] = {"ports": port_list, "description": description}
    _save_json(_PROFILES_FILE, profiles)
    typer.echo(f"✅ Saved scan profile '{name}' with ports {port_list}.")


@scan_app.command("list-profiles")
def list_profiles():
    """List all saved scanning profiles."""
    _ensure_config_dir()
    profiles = _load_json(_PROFILES_FILE)
    if not profiles:
        typer.echo("ℹ️  No scan profiles have been saved yet. Use 'save-profile' to create one.")
        return
    typer.echo("📁 Saved scan profiles:")
    for name, info in profiles.items():
        ports = ", ".join(str(p) for p in info.get("ports", []))
        desc = info.get("description", "")
        typer.echo(f" - {name}: ports [{ports}] {('- ' + desc) if desc else ''}")


@scan_app.command("run-profile")
def run_profile(
    name: str = typer.Argument(..., help="Name of the scan profile to run."),
    target: str = typer.Argument(..., help="Target network or host to scan."),
):
    """Execute a previously saved scanning profile against a target."""
    _ensure_config_dir()
    profiles = _load_json(_PROFILES_FILE)
    profile = profiles.get(name)
    if not profile:
        typer.echo(f"❌ Profile '{name}' not found. Use 'list-profiles' to see available profiles.")
        raise typer.Exit(code=1)
    ports = profile.get("ports", [])
    if not ports:
        typer.echo(f"❌ Profile '{name}' has no ports defined.")
        raise typer.Exit(code=1)
    typer.echo(f"🔄 Running profile '{name}' on {target} with ports {ports}...")
    try:
        results = scan_network(target, ports)
    except Exception as exc:
        typer.echo(f"❌ An error occurred during scanning: {exc}")
        raise typer.Exit(code=1)
    aggregated = {}
    for host, open_ports in results.items():
        record = {
            "target": host,
            "timestamp": datetime.now().isoformat(),
            "open_ports": open_ports,
        }
        _append_history(record)
        aggregated[host] = open_ports
    # Print JSON summary so tests can assert values easily
    _safe_print_json({"target": target, "results": aggregated})
    typer.echo("✅ Profile scan completed.")



# Register scan subcommands with the main app
app.add_typer(scan_app, name="scan")


# ---------------------------------------------------------------------------
# Blue Team command group
# ---------------------------------------------------------------------------
blue_app = typer.Typer(help="Blue Team operations: vulnerability assessment and log analysis.")


@blue_app.command("vuln-scan")
def blue_vuln_scan(
    history: bool = typer.Option(
        True,
        "--use-history/--no-use-history",
        help="Use the latest network scan results from history. If disabled, ports must be provided manually.",
    ),
    ports: str = typer.Option(
        "",
        "--ports",
        help="Comma-separated list of ports to analyse (used when --no-use-history is specified).",
    ),
):
    """Perform a vulnerability assessment based on open ports.

    This command reads the most recent network scan results from the history file
    and generates vulnerability recommendations for each discovered service.
    If ``--no-use-history`` is specified, you must supply a list of ports via
    ``--ports``.
    """
    from .engines import blue_team
    # Determine open ports mapping
    open_ports: Dict[str, Dict[int, str]] = {}
    if history:
        # Load the last network scan record from history
        _ensure_config_dir()
        if not os.path.isfile(_HISTORY_FILE):
            typer.echo("❌ No scan history found. Run 'scan network' first or use --no-use-history.")
            raise typer.Exit(code=1)
        try:
            with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Find the most recent record with open_ports
            for record in reversed(data):
                if "open_ports" in record:
                    host = record.get("target")
                    # record["open_ports"] may be a list; convert to dict for compatibility
                    ports_map = {int(p): "tcp" for p in record["open_ports"]}
                    open_ports[host] = ports_map
                    break
            if not open_ports:
                typer.echo("ℹ️  No open ports found in history.")
        except Exception as exc:
            typer.echo(f"❌ Failed to load history: {exc}")
            raise typer.Exit(code=1)
    else:
        # Parse ports manually provided by user
        if not ports:
            typer.echo("❌ You must provide ports with --ports when not using history.")
            raise typer.Exit(code=1)
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        open_ports["manual"] = {p: "tcp" for p in port_list}
    if not open_ports:
        typer.echo("✅ No ports to assess.")
        return
    # Generate vulnerability recommendations
    recs = blue_team.map_ports_to_vulnerabilities(open_ports)
    for host, recommendations in recs.items():
        typer.echo(f"📍 Vulnerability assessment for {host}:")
        for rec in recommendations:
            typer.echo(f"  • {rec}")
    typer.echo("✅ Vulnerability assessment completed.")


@blue_app.command("log-analysis")
def blue_log_analysis(
    log_file: str = typer.Argument(..., help="Path to a log file to analyse for failed logins."),
):
    """Analyse a log file to detect repeated failed login attempts.

    This command scans the specified log file and reports the total number
    of failed login attempts along with a breakdown by source IP. Use this
    for quick detection of brute force attacks and other suspicious activity.
    """
    from .engines import blue_team
    from pathlib import Path
    path = Path(log_file)
    total, by_ip = blue_team.analyse_log_file(path)
    if total == 0:
        typer.echo("✅ No failed login attempts detected or file could not be read.")
        return
    # Capitalise the phrase for consistency with test expectations
    typer.echo(f"❗ Detected {total} Failed login attempts:")
    for ip, count in by_ip.items():
        typer.echo(f"  • {ip}: {count} times")
    typer.echo("✅ Log analysis completed.")


@blue_app.command("auth-analysis")
def blue_auth_analysis(
    log_file: str = typer.Argument(..., help="Path to an authentication log file (e.g., auth.log)."),
    start_hour: int = typer.Option(8, "--start-hour", help="Start hour (24h) of normal working period."),
    end_hour: int = typer.Option(18, "--end-hour", help="End hour (24h) of normal working period."),
):
    """Analyse authentication logs for unusual login times and failed attempts.

    This command parses a log file and reports logins occurring outside
    the specified working hours and counts failed login attempts per IP.
    """
    from .engines import auth_analysis
    from pathlib import Path
    path = Path(log_file)
    result = auth_analysis.analyse_auth_log(path, working_hours=(start_hour, end_hour))
    unusual = result.get("unusual_logins", {})
    failed = result.get("failed_logins", {})
    if not unusual and not failed:
        typer.echo("✅ No unusual or failed login activity detected (or file could not be read).")
        return
    if unusual:
        typer.echo("🚨 Unusual login times detected:")
        for key, count in unusual.items():
            typer.echo(f"  • {key}: {count} times outside {start_hour}-{end_hour}h")
    if failed:
        typer.echo("❗ Failed login attempts:")
        for ip, count in failed.items():
            typer.echo(f"  • {ip}: {count} times")
    typer.echo("✅ Authentication analysis completed.")


app.add_typer(blue_app, name="blue")


# ---------------------------------------------------------------------------
# Red Team command group
# ---------------------------------------------------------------------------
red_app = typer.Typer(help="Red Team operations: safe exploitation of lab environments.")


@red_app.command("exploit-lab")
def red_exploit_lab(
    lab_name: str = typer.Argument(
        ..., help="Name of the CTF lab to exploit (as created by 'ctf create')."
    ),
):
    """Simulate exploitation of a CTF lab.

    This command attempts to read flags from each challenge within the specified
    lab directory. It requires that the lab has been created previously via
    the 'ctf create' command. In real scenarios this could run actual
    exploitation scripts; here we simply demonstrate safe behaviour.
    """
    from .engines import red_team
    lab_path = Path(_LABS_DIR) / lab_name
    flags = red_team.exploit_lab(lab_path)
    if not flags:
        typer.echo(f"ℹ️  No challenges found in lab '{lab_name}' or lab does not exist.")
        return
    typer.echo(f"🏴‍☠️ Exploitation results for lab '{lab_name}':")
    for chal, flag in flags.items():
        if flag:
            typer.echo(f"  • {chal}: FLAG = {flag}")
        else:
            typer.echo(f"  • {chal}: No flag found or could not read flag.txt")
    typer.echo("✅ Exploitation simulation completed.")

app.add_typer(red_app, name="red")


# ---------------------------------------------------------------------------
# Threat hunting command group
# ---------------------------------------------------------------------------
hunt_app = typer.Typer(help="Perform threat hunting on historical scan data.")


@hunt_app.command("anomalies")
def hunt_anomalies():
    """Detect port anomalies across network scan history.

    This command analyses the history of network scans stored in
    ``~/.cybercli/history.json`` and identifies hosts where new ports have
    appeared or previously open ports have disappeared between consecutive
    scans. It reports the changes for each host.
    """
    from .engines import threat_hunter
    # Load history
    _ensure_config_dir()
    if not os.path.isfile(_HISTORY_FILE):
        typer.echo("ℹ️  No scan history available. Run 'scan network' first.")
        raise typer.Exit(code=1)
    try:
        with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
        anomalies = threat_hunter.detect_port_anomalies(history)
        if not anomalies:
            typer.echo("✅ No anomalies detected in scan history.")
            return
        for host, changes in anomalies.items():
            added = changes.get("added", [])
            removed = changes.get("removed", [])
            if not added and not removed:
                continue
            typer.echo(f"🔍 Host {host}:")
            if added:
                typer.echo(f"  ➕ Added ports: {', '.join(str(p) for p in added)}")
            if removed:
                typer.echo(f"  ➖ Removed ports: {', '.join(str(p) for p in removed)}")
        typer.echo("✅ Anomaly detection completed.")
    except Exception as exc:
        typer.echo(f"❌ Failed to analyse history: {exc}")
        raise typer.Exit(code=1)


@hunt_app.command("risk-scores")
def hunt_risk_scores():
    """Calculate risk scores for hosts based on the latest scan.

    This command reads the last network scan entry from the history file and
    assigns a risk score to each host based on its open ports. Ports with
    known vulnerabilities (according to the Blue Team mapping) contribute
    more to the score.
    """
    from .engines import threat_hunter
    # Load the last record from history
    _ensure_config_dir()
    if not os.path.isfile(_HISTORY_FILE):
        typer.echo("ℹ️  No scan history available. Run 'scan network' first.")
        raise typer.Exit(code=1)
    try:
        with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)
        if not history:
            typer.echo("ℹ️  No scan history entries found.")
            return
        last_records = {}  # host -> ports
        for record in reversed(history):
            host = record.get("target")
            if host not in last_records and record.get("open_ports"):
                last_records[host] = [int(p) for p in record["open_ports"]]
            # Break if we've collected data for all hosts in this record set
            if len(last_records) >= 10:
                break
        if not last_records:
            typer.echo("ℹ️  No port data found in the latest scan.")
            return
        scores = threat_hunter.calculate_risk_scores(last_records)
        for host, score in scores.items():
            typer.echo(f"🔒 {host}: risk score {score:.1f}")
        typer.echo("✅ Risk score calculation completed.")
    except Exception as exc:
        typer.echo(f"❌ Failed to calculate risk scores: {exc}")
        raise typer.Exit(code=1)

app.add_typer(hunt_app, name="hunt")


# ---------------------------------------------------------------------------
# Export command group
# ---------------------------------------------------------------------------
export_app = typer.Typer(help="Export data from CyberCLI for integration with other tools.")


@export_app.command("history")
def export_history(
    out_file: str = typer.Argument(..., help="Destination file to write the scan history (JSON)."),
):
    """Export the full scan history to a JSON file.

    This allows integration with SIEMs or other analysis tools. The history
    contains a chronological list of all network scans performed with their
    timestamps and open port lists.
    """
    _ensure_config_dir()
    if not os.path.isfile(_HISTORY_FILE):
        typer.echo("❌ No scan history found. Nothing to export.")
        raise typer.Exit(code=1)
    try:
        with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        with open(out_file, "w", encoding="utf-8") as outf:
            json.dump(data, outf, indent=2, default=str)
        typer.echo(f"✅ History exported to {out_file}")
    except Exception as exc:
        typer.echo(f"❌ Failed to export history: {exc}")
        raise typer.Exit(code=1)

app.add_typer(export_app, name="export")


# ---------------------------------------------------------------------------
# Intelligence command group
# ---------------------------------------------------------------------------
intel_app = typer.Typer(help="Query threat intelligence services and related utilities.")


@intel_app.command()
def search(
    indicator: str = typer.Argument(
        ..., help="IP address, domain, URL, file hash or CVE identifier to query."
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Use AI to summarise threat intelligence results."
    ),
):
    """Query threat intelligence sources for information about an indicator.

    This implementation uses the ``threat_intel`` engine to perform lookups
    across multiple services.  It aggregates results for IP addresses (Shodan,
    AbuseIPDB), file hashes/URLs (VirusTotal) and CVE identifiers (NVD) and
    prints them as JSON.  When ``--ai`` is provided and an AI key is
    configured, the results are summarised using the configured AI service.
    """
    typer.echo(f"🔎 Looking up threat intelligence for {indicator}...")
    try:
        from .engines import threat_intel
        intel_data = threat_intel.aggregate_intel(indicator)
    except Exception as exc:
        typer.echo(f"❌ Failed to query threat intelligence services: {exc}")
        raise typer.Exit(code=1)
    # Add the indicator to the result for context
    intel_data["indicator"] = indicator
    if ai:
        # Summarise using AI service
        _require_ai_key()
        typer.echo("🧠 Using AI to summarise threat intelligence results...")
        summary_prompt = (
            "Summarise the following threat intelligence information and highlight any malicious findings.\n"
            + json.dumps(intel_data, indent=2)
        )
        # Placeholder: reverse the prompt to simulate AI output
        ai_summary = summary_prompt[::-1]
        intel_data["ai_summary"] = ai_summary
    _safe_print_json(intel_data)


@intel_app.command("geoip")
def intel_geoip(
    ip: str = typer.Argument(..., help="IP address (IPv4 or IPv6) to look up geolocation information for."),
):
    """Look up geolocation information for an IP address.

    This command queries a GeoIP service (defaulting to ipapi.co) to retrieve
    country, region, city, ASN and other data for the provided IP address.
    The service URL can be overridden with the ``GEOIP_SERVICE_URL``
    environment variable.
    """
    typer.echo(f"🌍 Performing GeoIP lookup for {ip}...")
    from .engines import geoip as geoip_engine
    result = geoip_engine.lookup_ip(ip)
    _safe_print_json(result)


app.add_typer(intel_app, name="intel")

# ---------------------------------------------------------------------------
# Machine learning command group
# ---------------------------------------------------------------------------
ml_app = typer.Typer(help="Machine learning operations: training and prediction.")


@ml_app.command("train")
def ml_train(
    dataset: Optional[str] = typer.Option(
        None,
        "--dataset",
        help=(
            "Path to a JSON file containing training data.  If omitted, the model "
            "will be trained on a synthetic dataset.  The dataset should be a list of "
            "objects with 'open_ports' (list[int]) and 'label' (0, 1 or 2) keys."
        ),
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help="Path to save the trained model.  Defaults to ~/.cybercli/risk_classifier.joblib.",
    ),
    samples: int = typer.Option(
        200,
        "--samples",
        help="Number of synthetic samples to generate when no dataset is provided.",
    ),
):
    """Train a risk classification model for open ports.

    This command trains a multinomial logistic regression model to classify
    hosts into low, medium or high risk categories based on their open
    ports.  It can either learn from a user-provided dataset or generate
    synthetic training data.  The resulting model is saved to disk for
    later use.
    """
    typer.echo("🎓 Training risk classifier...")
    from .engines import ml_classifier
    model = None
    if dataset:
        try:
            import json as _json
            with open(dataset, "r", encoding="utf-8") as f:
                data = _json.load(f)
            X = []
            y = []
            for item in data:
                ports = item.get("open_ports", [])
                label = int(item.get("label", 0))
                features = ml_classifier.extract_features(ports)
                X.append(features)
                y.append(label)
            model = ml_classifier.train_classifier(X, y)
            typer.echo(f"✅ Trained model on {len(y)} samples from {dataset}.")
        except Exception as exc:
            typer.echo(f"❌ Failed to load dataset: {exc}")
            raise typer.Exit(code=1)
    else:
        # Generate a synthetic dataset
        model = ml_classifier.train_default_model(samples=samples)
        typer.echo(f"✅ Trained model on {samples} synthetic samples.")
    # Determine output path
    out_path = ml_classifier.model_path() if not output else Path(output)
    try:
        ml_classifier.save_model(model, out_path)
        typer.echo(f"💾 Saved trained model to {out_path}.")
    except Exception as exc:
        typer.echo(f"❌ Failed to save model: {exc}")
        raise typer.Exit(code=1)


@ml_app.command("predict")
def ml_predict(
    ports: str = typer.Argument(..., help="Comma-separated list of open ports to classify."),
    model_file: Optional[str] = typer.Option(
        None,
        "--model",
        help="Path to a trained model file.  Defaults to ~/.cybercli/risk_classifier.joblib.",
    ),
):
    """Predict the risk level of a host given its open ports.

    This command loads a previously trained risk classifier and computes the
    risk class for the provided list of ports.  It outputs the predicted
    class (0=Low, 1=Medium, 2=High) and the classifier's confidence.
    """
    from .engines import ml_classifier
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    if not port_list:
        typer.echo("❌ You must provide at least one port.")
        raise typer.Exit(code=1)
    # Load model
    mpath = Path(model_file) if model_file else ml_classifier.model_path()
    try:
        model = ml_classifier.load_model(mpath)
    except Exception as exc:
        typer.echo(f"❌ Failed to load model from {mpath}: {exc}")
        raise typer.Exit(code=1)
    features = ml_classifier.extract_features(port_list)
    pred, conf = ml_classifier.predict(model, features)
    # Map class to human-readable string
    class_names = {0: "Low", 1: "Medium", 2: "High"}
    typer.echo(f"🔮 Predicted risk: {class_names.get(pred, pred)} (confidence {conf:.2f})")

# Register ML subcommands
app.add_typer(ml_app, name="ml")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
@app.command()
def report(
    report_type: str = typer.Option(
        "technical",
        "--type",
        help="Type of report: executive, technical or compliance.  Determines narrative emphasis.",
    ),
    format: str = typer.Option(
        "pdf",
        "--format",
        help="Output format: pdf, html or json.",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Use the configured AI provider to generate narrative sections.",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help="Destination file name for the report.  Defaults to ~/.cybercli/reports/<timestamp>.{html|pdf|json}",
    ),
):
    """Generate a consolidated security report.

    This command collates information from recent scans, vulnerability
    assessments, anomaly detection and risk scoring to produce a comprehensive
    report.  Reports can be generated in HTML, PDF or JSON formats.  When
    the ``--ai`` flag is provided and an AI API key is configured, an
    additional narrative section is generated by reversing the summary (as
    a placeholder for an AI call).
    """
    from .engines import reporting
    from .engines import blue_team, threat_hunter
    # Ensure history exists
    _ensure_config_dir()
    if not os.path.isfile(_HISTORY_FILE):
        typer.echo("❌ No scan history available. Run 'scan network' first.")
        raise typer.Exit(code=1)
    try:
        with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f) or []
    except Exception as exc:
        typer.echo(f"❌ Failed to load history: {exc}")
        raise typer.Exit(code=1)
    if not history:
        typer.echo("ℹ️  History is empty. Cannot generate report.")
        raise typer.Exit(code=1)
    # Collect scan results from the last scan entry for each host
    scan_results: Dict[str, list[int]] = {}
    for record in reversed(history):
        host = record.get("target")
        ports = record.get("open_ports")
        if host and ports and host not in scan_results:
            scan_results[host] = [int(p) for p in ports]
        # If we've collected results for a few hosts we can break
        if len(scan_results) >= 20:
            break
    # Generate vulnerabilities using Blue Team mapping
    open_ports_map: Dict[str, Dict[int, str]] = {h: {p: "tcp" for p in ps} for h, ps in scan_results.items()}
    vulnerabilities = blue_team.map_ports_to_vulnerabilities(open_ports_map)
    # Anomalies across history
    anomalies = threat_hunter.detect_port_anomalies(history)
    # Risk scores for last scan results
    risk_scores = threat_hunter.calculate_risk_scores({h: ps for h, ps in scan_results.items()})
    # Determine default output path
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not output:
        report_dir = reporting.default_report_dir()
        report_dir.mkdir(parents=True, exist_ok=True)
        ext = format.lower()
        output_path = report_dir / f"report_{now_str}.{ext}"
    else:
        output_path = Path(output)
    # Build report content
    title = f"CyberCLI {report_type.title()} Report"
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if format.lower() == "json":
        # Export as JSON structure
        report_data = {
            "title": title,
            "date": date_str,
            "scan_results": scan_results,
            "vulnerabilities": vulnerabilities,
            "anomalies": anomalies,
            "risk_scores": risk_scores,
        }
        if ai:
            _require_ai_key()
            summary = json.dumps(report_data, indent=2)
            ai_section = summary[::-1]  # placeholder for AI summary
            report_data["ai_summary"] = ai_section
        # Write JSON file
        with open(output_path, "w", encoding="utf-8") as outf:
            json.dump(report_data, outf, indent=2, default=str)
        typer.echo(f"✅ JSON report saved to {output_path}")
        return
    # Generate HTML using the reporting engine
    html = reporting.generate_html_report(
        title=title,
        date=date_str,
        scan_results=scan_results,
        vulnerabilities=vulnerabilities,
        anomalies=anomalies,
        risk_scores=risk_scores,
    )
    # Append AI section if requested
    if ai:
        _require_ai_key()
        summary_text = (
            f"Report generated on {date_str}. Hosts scanned: {len(scan_results)}. "
            f"High-risk hosts: {sum(1 for s in risk_scores.values() if s >= 5)}."
        )
        ai_output = summary_text[::-1]  # placeholder for AI narrative
        html += f"\n<hr/><h2>AI Narrative</h2><p>{ai_output}</p>"
    # Write HTML or convert to PDF
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if format.lower() == "html":
        with open(output_path, "w", encoding="utf-8") as outf:
            outf.write(html)
        typer.echo(f"✅ HTML report saved to {output_path}")
    elif format.lower() == "pdf":
        # Try to convert HTML to PDF via WeasyPrint
        try:
            reporting.generate_pdf_report(html, output_path)
            typer.echo(f"✅ PDF report saved to {output_path}")
        except Exception as exc:
            typer.echo(f"⚠️  PDF generation failed: {exc}. Saving HTML instead.")
            html_path = output_path.with_suffix(".html")
            with open(html_path, "w", encoding="utf-8") as outf:
                outf.write(html)
            typer.echo(f"✅ HTML report saved to {html_path}")
    else:
        typer.echo(f"❌ Unsupported report format: {format}. Use html, pdf or json.")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Compliance checks
# ---------------------------------------------------------------------------
@app.command()
def compliance(
    controls_file: Optional[str] = typer.Option(
        None,
        "--controls",
        help=(
            "Path to a JSON or YAML file containing your organisation's ISO 27001 control status. "
            "If omitted, the CLI will prompt you interactively."
        ),
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Use the configured AI service to suggest improvements based on your responses.",
    ),
):
    """Assess compliance with ISO 27001 control objectives.

    This command performs a high‑level assessment against the four control themes defined in ISO 27001:2022 —
    organisational, people, physical and technological — which together encompass 93 controls【545426540923872†L61-L71】.
    You can either supply a JSON/YAML file describing which themes are implemented or answer prompts interactively.

    An optional ``--ai`` flag will use the configured generative AI service to summarise the findings and offer
    tailored recommendations. A valid API key must be present in the environment variable
    ``CYBERCLI_AI_API_KEY`` for AI support.
    """
    typer.echo("📋 Starting ISO 27001 compliance assessment...")
    themes = [
        "organizational",
        "people",
        "physical",
        "technological",
    ]
    # Normalise keys to lowercase for comparison
    implemented = {theme: False for theme in themes}
    if controls_file:
        # Attempt to load the provided file as JSON or YAML
        import pathlib
        path = pathlib.Path(controls_file)
        if not path.exists():
            typer.echo(f"❌ Controls file '{controls_file}' does not exist.")
            raise typer.Exit(code=1)
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            data = None
            if controls_file.endswith(('.yaml', '.yml')):
                try:
                    import yaml  # type: ignore
                except ImportError:
                    typer.echo("⚠️ YAML support is not available. Please install PyYAML or provide a JSON file.")
                    raise typer.Exit(code=1)
                data = yaml.safe_load(content)
            else:
                data = json.loads(content)
            if not isinstance(data, dict):
                typer.echo("⚠️ Controls file must contain a JSON/YAML object with theme names as keys.")
                raise typer.Exit(code=1)
            for theme in themes:
                implemented[theme] = bool(data.get(theme) or data.get(theme.capitalize()) or data.get(theme.title()))
            typer.echo(f"Loaded control status from {controls_file}.")
        except Exception as exc:
            typer.echo(f"❌ Failed to parse controls file: {exc}")
            raise typer.Exit(code=1)
    else:
        # Interactive prompts to assess each theme
        typer.echo("No controls file provided. Answer the following questions to indicate which control themes are in place:")
        for theme in themes:
            question = f"Have you implemented the {theme} control theme?"
            # Provide a brief description of each theme for user guidance
            if theme == "organizational":
                typer.echo("Organizational controls cover governance, policies, third‑party management and access control"  # noqa: E501
                           "【545426540923872†L61-L71】.")
            elif theme == "people":
                typer.echo("People controls address HR security, training and awareness【545426540923872†L61-L71】.")
            elif theme == "physical":
                typer.echo("Physical controls relate to facility access, equipment protection and environmental security"  # noqa: E501
                           "【545426540923872†L61-L71】.")
            elif theme == "technological":
                typer.echo("Technological controls include encryption, system monitoring, logging and malware defence"  # noqa: E501
                           "【545426540923872†L61-L71】.")
            implemented[theme] = typer.confirm(question, default=False)
    # Summarise results
    total = len(themes)
    count = sum(1 for val in implemented.values() if val)
    typer.echo(f"\n🎯 You have implemented {count} out of {total} ISO 27001 control themes.")
    for theme, status in implemented.items():
        symbol = "✅" if status else "❌"
        typer.echo(f"  {symbol} {theme.title()}")
    if ai:
        # Use AI to provide tailored recommendations
        _require_ai_key()
        typer.echo("\n🧠 Generating AI‑driven compliance recommendations...")
        # Compose a prompt summarising the status. In a real implementation this prompt would
        # include more context and possibly the user's controls file. Here we build a simple summary.
        summary_lines = [f"{theme.title()}: {'implemented' if status else 'missing'}" for theme, status in implemented.items()]
        prompt = (
            "Provide actionable recommendations to achieve ISO 27001 compliance based on the following "
            "control themes status:\n" + "\n".join(summary_lines)
        )
        # Placeholder: call AI service; we reverse the prompt as a dummy "response"
        ai_response = prompt[::-1]
        typer.echo("\n💡 AI Recommendations (placeholder):")
        typer.echo(ai_response)
    typer.echo("\n✅ Compliance assessment complete.")


# ---------------------------------------------------------------------------
# Remediation and rollback
# ---------------------------------------------------------------------------
remediation_app = typer.Typer(help="Apply remediations and manage rollbacks.")


@remediation_app.command()
def remediate(
    finding_id: int = typer.Argument(..., help="Identifier of the finding to remediate."),
    approve: bool = typer.Option(False, "--approve", help="Automatically approve remediation without manual confirmation."),
):
    """Apply a remediation for a given finding."""
    if not approve:
        proceed = typer.confirm(
            f"Apply remediation for finding {finding_id}? This may modify system state.", default=False
        )
        if not proceed:
            typer.echo("❌ Remediation aborted by user.")
            raise typer.Exit()
    typer.echo(f"🛠️ Applying remediation for finding {finding_id} (placeholder)...")
    typer.echo("✅ Remediation applied successfully (placeholder).")


@remediation_app.command("suggest")
def remediation_suggest(
    use_history: bool = typer.Option(
        True,
        "--use-history/--no-use-history",
        help="Use the last network scan results from history to derive remediation actions.",
    ),
    ports: str = typer.Option(
        "",
        "--ports",
        help="Comma-separated list of ports when not using history (e.g., 22,80,443).",
    ),
):
    """Suggest remediation actions based on vulnerability assessments.

    This command analyses the most recent network scan results (or a user‑provided
    list of ports) to generate vulnerability recommendations via the Blue
    Team module, then derives high‑level remediation steps using the
    remediator engine.  The suggestions are printed for manual review and
    approval.
    """
    from .engines import blue_team, remediator
    # Determine open ports
    open_ports_map: Dict[str, Dict[int, str]] = {}
    if use_history:
        _ensure_config_dir()
        if not os.path.isfile(_HISTORY_FILE):
            typer.echo("❌ No scan history found. Run 'scan network' first or use --no-use-history.")
            raise typer.Exit(code=1)
        try:
            with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
            for record in reversed(history):
                host = record.get("target")
                ports_list = record.get("open_ports")
                if host and ports_list and host not in open_ports_map:
                    open_ports_map[host] = {int(p): "tcp" for p in ports_list}
                if len(open_ports_map) >= 20:
                    break
        except Exception as exc:
            typer.echo(f"❌ Failed to read history: {exc}")
            raise typer.Exit(code=1)
    else:
        if not ports:
            typer.echo("❌ Please provide ports via --ports when --no-use-history is specified.")
            raise typer.Exit(code=1)
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        if not port_list:
            typer.echo("❌ Invalid port list provided.")
            raise typer.Exit(code=1)
        open_ports_map["manual"] = {p: "tcp" for p in port_list}
    if not open_ports_map:
        typer.echo("✅ No ports to suggest remediations for.")
        return
    # Generate vulnerability recommendations
    vuln_recs = blue_team.map_ports_to_vulnerabilities(open_ports_map)
    # Suggest remediation actions
    actions = remediator.suggest_remediations(vuln_recs)
    for host, steps in actions.items():
        typer.echo(f"🛠️  Remediation suggestions for {host}:")
        for idx, step in enumerate(steps, 1):
            typer.echo(f"  {idx}. {step}")
    typer.echo("✅ Suggested remediation actions generated.")


@remediation_app.command("apply")
def remediation_apply(
    step: str = typer.Argument(..., help="The remediation step or command to execute."),
    simulate: bool = typer.Option(
        True,
        "--simulate/--execute",
        help="Simulate the remediation without running commands. Use --execute to run the commands.",
    ),
):
    """Apply a remediation step.

    Provide a remediation action (as printed by the 'suggest' command) and it
    will either be printed (simulation) or executed using subprocess.  Use
    this with caution when executing commands.
    """
    from .engines import remediator
    typer.echo(f"⚙️  Applying remediation step{' (simulation)' if simulate else ''}:")
    typer.echo(step)
    try:
        remediator.apply_remediation_step(step, simulate=simulate)
        typer.echo("✅ Remediation step handled.")
    except Exception as exc:
        typer.echo(f"❌ Failed to apply remediation: {exc}")
        raise typer.Exit(code=1)


@remediation_app.command()
def rollback(
    remediation_id: int = typer.Argument(..., help="Identifier of the remediation to roll back."),
):
    """Rollback a previously applied remediation."""
    typer.echo(f"⏪ Rolling back remediation {remediation_id} (placeholder)...")
    typer.echo("✅ Rollback completed (placeholder).")


app.add_typer(remediation_app, name="remediation")

# ---------------------------------------------------------------------------
# Alerting command group
# ---------------------------------------------------------------------------
alert_app = typer.Typer(help="Send alerts via email, Slack or Telegram.")


@alert_app.command("email")
def alert_email(
    to: str = typer.Argument(..., help="Recipient email address."),
    subject: str = typer.Option("CyberCLI Alert", "--subject", help="Email subject."),
    message: str = typer.Option("", "--message", help="Body of the alert message."),
):
    """Send an alert via SMTP email.

    Requires SMTP credentials to be set in the environment variables
    ``SMTP_SERVER``, ``SMTP_PORT``, ``SMTP_USER`` and ``SMTP_PASSWORD``.
    """
    from .engines import alerting
    result = alerting.send_email_alert(to_address=to, subject=subject, body=message)
    _safe_print_json(result)


@alert_app.command("slack")
def alert_slack(
    message: str = typer.Argument(..., help="Alert message text to send to Slack."),
    webhook_url: Optional[str] = typer.Option(
        None,
        "--webhook-url",
        help="Slack webhook URL.  If omitted, SLACK_WEBHOOK_URL env variable is used.",
    ),
):
    """Send an alert message to Slack via incoming webhook."""
    from .engines import alerting
    result = alerting.send_slack_alert(message=message, webhook_url=webhook_url)
    _safe_print_json(result)


@alert_app.command("telegram")
def alert_telegram(
    message: str = typer.Argument(..., help="Alert message text to send via Telegram."),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help="Telegram bot token.  If omitted, TELEGRAM_TOKEN env variable is used.",
    ),
    chat_id: Optional[str] = typer.Option(
        None,
        "--chat-id",
        help="Telegram chat ID.  If omitted, TELEGRAM_CHAT_ID env variable is used.",
    ),
):
    """Send an alert message via Telegram Bot API."""
    from .engines import alerting
    result = alerting.send_telegram_alert(message=message, token=token, chat_id=chat_id)
    _safe_print_json(result)

# Register alert subcommands
app.add_typer(alert_app, name="alert")


# ---------------------------------------------------------------------------
# CTF lab management
# ---------------------------------------------------------------------------
ctf_app = typer.Typer(help="Provision and manage Capture‑The‑Flag laboratories.")


@ctf_app.command()
def create(
    name: str = typer.Argument(..., help="Name of the CTF lab to create."),
    challenges: int = typer.Option(5, "--challenges", help="Number of challenges to generate."),
    web_challenge: bool = typer.Option(
        False,
        "--web-challenge/--no-web-challenge",
        help="Include a simple vulnerable web service challenge in the lab.",
    ),
):
    """Create a new CTF lab with the specified number of challenges.

    Labs are stored under ``~/.cybercli/labs/<name>``. Each challenge directory
    contains a ``README.md`` with instructions and a hidden ``flag.txt`` file
    containing a randomly generated flag. This simulates a simple training
    environment and can be extended with more complex scenarios.
    """
    _ensure_config_dir()
    import random
    import string
    lab_path = os.path.join(_LABS_DIR, name)
    if os.path.exists(lab_path):
        typer.echo(f"❌ Lab '{name}' already exists. Choose a different name or destroy the existing lab.")
        raise typer.Exit(code=1)
    os.makedirs(lab_path, exist_ok=True)
    for i in range(1, challenges + 1):
        challenge_dir = os.path.join(lab_path, f"challenge{i}")
        os.makedirs(challenge_dir, exist_ok=True)
        # Write a simple README for the challenge
        with open(os.path.join(challenge_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(f"# Challenge {i}\n\nFind the hidden flag in this directory.\n")
        # Generate a random flag
        flag = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        with open(os.path.join(challenge_dir, "flag.txt"), "w", encoding="utf-8") as f:
            f.write(f"FLAG{{{flag}}}\n")
    # Optionally add a vulnerable web challenge
    if web_challenge:
        web_dir = os.path.join(lab_path, "web_challenge")
        os.makedirs(web_dir, exist_ok=True)
        with open(os.path.join(web_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(
                "# Web Challenge\n\n"
                "This challenge contains a simple Python HTTP server that reflects user input. "
                "Run `python vulnerable_server.py` and visit http://localhost:8000/?name=YourName "
                "to observe the output. Try to inject HTML or JavaScript to demonstrate XSS.\n"
            )
        # Write a vulnerable server script
        vulnerable_code = (
            "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
            "import urllib.parse\n\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)\n"
            "        name = params.get('name', [''])[0]\n"
            "        message = f'Hello {name}'  # XSS vulnerability\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-type', 'text/html')\n"
            "        self.end_headers()\n"
            "        self.wfile.write(message.encode())\n\n"
            "if __name__ == '__main__':\n"
            "    HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()\n"
        )
        with open(os.path.join(web_dir, "vulnerable_server.py"), "w", encoding="utf-8") as f:
            f.write(vulnerable_code)
    typer.echo(
        f"✅ CTF lab '{name}' created with {challenges} challenges"
        + (" and a web challenge" if web_challenge else "")
        + ". Use 'ctf list' to view labs."
    )


@ctf_app.command()
def list():
    """List existing CTF labs."""
    _ensure_config_dir()
    if not os.path.isdir(_LABS_DIR):
        typer.echo("ℹ️  No CTF labs have been created yet. Use 'ctf create' to provision one.")
        return
    labs = []
    for entry in sorted(os.listdir(_LABS_DIR)):
        lab_dir = os.path.join(_LABS_DIR, entry)
        if os.path.isdir(lab_dir):
            # Count challenges by enumerating subdirectories
            challenge_count = len([d for d in os.listdir(lab_dir) if os.path.isdir(os.path.join(lab_dir, d))])
            labs.append((entry, challenge_count))
    if not labs:
        typer.echo("ℹ️  No CTF labs have been created yet. Use 'ctf create' to provision one.")
        return
    typer.echo("🎮 Available CTF labs:")
    for name, count in labs:
        typer.echo(f" - {name} ({count} challenges)")


@ctf_app.command()
def destroy(
    name: str = typer.Argument(..., help="Name of the CTF lab to delete."),
    force: bool = typer.Option(False, "--force", help="Force deletion without confirmation."),
):
    """Remove a CTF lab and all its resources."""
    lab_path = os.path.join(_LABS_DIR, name)
    if not os.path.isdir(lab_path):
        typer.echo(f"❌ Lab '{name}' does not exist.")
        raise typer.Exit(code=1)
    if not force:
        proceed = typer.confirm(f"Are you sure you want to delete lab '{name}'?", default=False)
        if not proceed:
            typer.echo("❌ Deletion aborted by user.")
            raise typer.Exit()
    # Remove directory recursively
    import shutil
    shutil.rmtree(lab_path)
    typer.echo(f"✅ Lab '{name}' removed.")


app.add_typer(ctf_app, name="ctf")


# ---------------------------------------------------------------------------
# Scan scheduling
# ---------------------------------------------------------------------------
schedule_app = typer.Typer(help="Manage scheduled scans.")


@schedule_app.command("add")
def schedule_add(
    name: str = typer.Argument(..., help="Name of the scheduled task."),
    target: str = typer.Argument(..., help="Target network or host to scan."),
    cron: str = typer.Option(
        "@daily",
        "--cron",
        help=(
            "Cron expression defining when the scan runs. For example '@daily', '0 2 * * *'"
        ),
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="Optional name of a saved scan profile to use. If omitted, default ports will be used.",
    ),
    ports: Optional[str] = typer.Option(
        None,
        "--ports",
        help="Comma‑separated list of ports when not using a saved profile.",
    ),
):
    """Schedule a recurring network scan.

    This command only records the schedule configuration. In a complete deployment, a
    background service or cron job would execute the scans based on the saved
    configuration. Here we store the details in ``~/.cybercli/schedules.json``.
    """
    _ensure_config_dir()
    schedules = _load_json(_SCHEDULES_FILE)
    if name in schedules:
        typer.echo(f"❌ A schedule named '{name}' already exists. Use a different name or remove the old schedule.")
        raise typer.Exit(code=1)
    profile_data = None
    port_list: Optional[list[int]] = None
    if profile:
        profiles = _load_json(_PROFILES_FILE)
        profile_data = profiles.get(profile)
        if not profile_data:
            typer.echo(f"❌ Profile '{profile}' not found. Use 'scan list-profiles' to see available profiles.")
            raise typer.Exit(code=1)
        port_list = profile_data.get("ports")
    elif ports:
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    else:
        port_list = [22, 80, 443]
    schedules[name] = {
        "target": target,
        "cron": cron,
        "ports": port_list,
    }
    _save_json(_SCHEDULES_FILE, schedules)
    typer.echo(f"✅ Scheduled scan '{name}' for target {target} at '{cron}' with ports {port_list}.")


@schedule_app.command("list")
def schedule_list():
    """List all scheduled scans."""
    _ensure_config_dir()
    schedules = _load_json(_SCHEDULES_FILE)
    if not schedules:
        typer.echo("ℹ️  No scans have been scheduled. Use 'schedule add' to create one.")
        return
    typer.echo("📅 Scheduled scans:")
    for name, cfg in schedules.items():
        typer.echo(
            f" - {name}: target={cfg['target']} cron='{cfg['cron']}' ports={cfg['ports']}"
        )


@schedule_app.command("remove")
def schedule_remove(name: str = typer.Argument(..., help="Name of the scheduled task to remove.")):
    """Remove a scheduled scan."""
    _ensure_config_dir()
    schedules = _load_json(_SCHEDULES_FILE)
    if name not in schedules:
        typer.echo(f"❌ No scheduled scan named '{name}' exists.")
        raise typer.Exit(code=1)
    schedules.pop(name)
    _save_json(_SCHEDULES_FILE, schedules)
    typer.echo(f"✅ Removed scheduled scan '{name}'.")


# Register schedule subcommands with the main app
app.add_typer(schedule_app, name="schedule")


# ---------------------------------------------------------------------------
# Self‑learning mechanism
# ---------------------------------------------------------------------------

@app.command()
def learn(
    top: int = typer.Option(
        5, "--top", help="Number of most frequent open ports or issues to display."
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Use AI to summarise trends and suggest improvements."
    ),
):
    """Analyse past scan history and identify recurring patterns.

    The CLI maintains a local history of scan results in ``~/.cybercli/history.json``. This
    command analyses that history, identifies the most frequently observed open ports or
    other recurring issues, and provides simple statistics to the user. When the
    ``--ai`` flag is provided, the configured AI provider (if any) will generate a
    narrative summarising these trends and recommending mitigation steps.
    """
    _ensure_config_dir()
    if not os.path.isfile(_HISTORY_FILE):
        typer.echo("📂 No history records found. Run scans to generate history.")
        raise typer.Exit(code=0)
    try:
        with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f) or []
    except Exception as exc:
        typer.echo(f"❌ Failed to load history: {exc}")
        raise typer.Exit(code=1)
    # Count occurrences of open ports across history
    port_counts: dict[int, int] = {}
    for record in history:
        for port in record.get("open_ports", []):
            port_counts[port] = port_counts.get(port, 0) + 1
    if not port_counts:
        typer.echo("ℹ️  No open ports recorded in history.")
    else:
        # Sort ports by frequency
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:top]
        typer.echo(f"📊 Top {len(sorted_ports)} most common open ports:")
        for port, count in sorted_ports:
            typer.echo(f" - Port {port}: {count} occurrences")
    if ai:
        _require_ai_key()
        typer.echo("\n🧠 Using AI to analyse historical trends (placeholder)...")
        # Compose a prompt summarising the counts
        summary = ", ".join([f"port {p} appears {c} times" for p, c in sorted_ports]) if port_counts else "no data"
        prompt = (
            "Analyse the following scan history summary and suggest ways to reduce exposure on these open ports: "
            + summary
        )
        ai_response = prompt[::-1]
        typer.echo("💡 AI analysis (placeholder):")
        typer.echo(ai_response)
    typer.echo("\n✅ Learning analysis complete.")


# ---------------------------------------------------------------------------
# AI assistance
# ---------------------------------------------------------------------------
@app.command()
def ai(
    prompt: str = typer.Argument(..., help="Natural language prompt to send to the AI assistant."),
    model: str = typer.Option("openai", "--model", help="AI provider to use: openai or gemini."),
):
    """Send a free‑form prompt to the configured AI model and display its response."""
    key = _require_ai_key()
    typer.echo(f"🤖 Sending prompt to {model} model (placeholder)...")
    # Placeholder: call AI API; here we just reverse the prompt as a dummy response
    response = prompt[::-1]
    typer.echo("📨 AI response (placeholder):")
    typer.echo(response)


if __name__ == "__main__":
    app()