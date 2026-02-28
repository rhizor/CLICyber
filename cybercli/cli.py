"""
CyberCLI - Simplified Security CLI
Solo comandos funcionales: scan, hardening, compliance, API
"""

import json
import os
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

import typer

# Import engines que funcionan
from cybercli.engines.network_scanner import scan_network
from cybercli.engines.hardening_checker import perform_hardening_checks

app = typer.Typer(
    help="CyberCLI - Simplified Security Operations CLI"
)

# Config
_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".cybercli")
_PROFILES_FILE = os.path.join(_CONFIG_DIR, "profiles.json")

def _ensure_config_dir():
    if not os.path.isdir(_CONFIG_DIR):
        os.makedirs(_CONFIG_DIR, exist_ok=True)

def _load_json(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_json(path: str, data: dict) -> None:
    _ensure_config_dir()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------
scan_app = typer.Typer(help="Network and security scans")

@scan_app.command("network")
def scan_network_cmd(
    target: str = typer.Argument(..., help="Target IP or network (e.g., 192.168.1.0/24)"),
    top_ports: int = typer.Option(20, "--top-ports", help="Number of top ports to scan"),
    timeout: int = typer.Option(2, "--timeout", help="Timeout per port in seconds"),
    category: str = typer.Option(None, "--category", help="Port category: web, db, mail, remote, all"),
):
    """Perform a network port scan."""
    # Port categories
    PORT_CATEGORIES = {
        "web": [
            80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000,
            8008, 8043, 8888, 9443, 10443, 17001
        ],
        "db": [
            3306, 5432, 27017, 6379, 1433, 1521, 5000, 9200, 9300,
            5984, 5432, 3307, 27018, 27019, 28017
        ],
        "mail": [
            25, 110, 143, 465, 587, 993, 995, 2525, 2526, 25025
        ],
        "remote": [
            22, 23, 3389, 5900, 5901, 2222, 22222, 5522, 9922
        ],
        "file": [
            20, 21, 69, 115, 139, 445, 2049, 10000, 11000, 49152
        ],
        "dns": [
            53, 853, 5353, 5050, 5060, 5061
        ],
        "all": []  # Will be filled with all categories
    }
    
    # Add all categories to "all"
    PORT_CATEGORIES["all"] = list(set(
        port for ports in PORT_CATEGORIES.values() for port in ports
    ))
    
    # Common ports (default fallback)
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443,
    ]
    
    # Determine ports to scan
    if category:
        category = category.lower()
        if category not in PORT_CATEGORIES:
            typer.echo(f"❌ Unknown category: {category}")
            typer.echo(f"   Available: {', '.join(PORT_CATEGORIES.keys())}")
            raise typer.Exit(1)
        ports = PORT_CATEGORIES[category]
        typer.echo(f"🔍 Scanning {target} (category: {category}, {len(ports)} ports)...")
    else:
        ports = common_ports[:top_ports] if top_ports <= len(common_ports) else common_ports
        typer.echo(f"🔍 Scanning {target} (top {len(ports)} ports)...")
    
    results = scan_network(target, ports, timeout=timeout)
    
    for host, ports in results.items():
        typer.echo(f"\n📍 {host}:")
        if ports:
            typer.echo(f"   Open ports: {', '.join(map(str, ports))}")
        else:
            typer.echo("   No open ports found")
    
    for host, ports in results.items():
        typer.echo(f"\n📍 {host}:")
        if ports:
            typer.echo(f"   Open ports: {', '.join(map(str, ports))}")
        else:
            typer.echo("   No open ports found")
    
    # Save to history
    _ensure_config_dir()
    history_file = os.path.join(_CONFIG_DIR, "history.json")
    history = _load_json(history_file)
    
    if not isinstance(history, dict):
        history = {}
    
    scans = history.get("scans", [])
    if not isinstance(scans, list):
        scans = []
    scans.append({
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "ports_found": sum(len(p) for p in results.values())
    })
    history["scans"] = scans
    _save_json(history_file, history)
    
    typer.echo("\n✅ Scan completed")


@scan_app.command("save-profile")
def save_profile(
    name: str = typer.Argument(..., help="Profile name"),
    ports: str = typer.Option(..., "--ports", help="Comma-separated ports (e.g., 22,80,443)"),
    description: str = typer.Option("", "--description", help="Profile description"),
):
    """Save a scanning profile."""
    profiles = _load_json(_PROFILES_FILE)
    profiles[name] = {
        "ports": ports,
        "description": description
    }
    _save_json(_PROFILES_FILE, profiles)
    typer.echo(f"✅ Profile '{name}' saved")


@scan_app.command("list-profiles")
def list_profiles():
    """List saved scanning profiles."""
    profiles = _load_json(_PROFILES_FILE)
    if not profiles:
        typer.echo("No profiles saved")
        return
    
    for name, data in profiles.items():
        typer.echo(f"\n📋 {name}")
        typer.echo(f"   Ports: {data.get('ports', '')}")
        typer.echo(f"   Description: {data.get('description', '-')}")


@scan_app.command("run-profile")
def run_profile(
    profile: str = typer.Argument(..., help="Profile name"),
    target: str = typer.Argument(..., help="Target IP or network"),
):
    """Run a saved profile against a target."""
    profiles = _load_json(_PROFILES_FILE)
    if profile not in profiles:
        typer.echo(f"❌ Profile '{profile}' not found")
        raise typer.Exit(1)
    
    ports = profiles[profile].get("ports", "80,443")
    port_list = [int(p.strip()) for p in ports.split(",")]
    
    typer.echo(f"🔍 Running profile '{profile}' on {target}...")
    results = scan_network(target, port_list=port_list)
    
    for host, open_ports in results.items():
        typer.echo(f"\n📍 {host}: {', '.join(map(str, open_ports))}")


# ---------------------------------------------------------------------------
# Hardening command
# ---------------------------------------------------------------------------
@app.command("hardening")
def hardening_cmd(
    profile: str = typer.Option("cis-level1", "--profile", help="Hardening profile"),
):
    """Evaluate system hardening."""
    typer.echo(f"🛡️ Checking system hardening (profile: {profile})...")
    
    results = perform_hardening_checks()
    
    for check in results:
        status = "✅" if check.status else "❌"
        typer.echo(f"  {status} {check.name}")
        if not check.status:
            typer.echo(f"     ➤ {check.recommendation}")
    
    passed = sum(1 for r in results if r.status)
    total = len(results)
    typer.echo(f"\n✅ Hardening: {passed}/{total} checks passed")


# ---------------------------------------------------------------------------
# Compliance command
# ---------------------------------------------------------------------------
@app.command("compliance")
def compliance_cmd(
    controls_file: Optional[str] = typer.Option(None, "--controls", help="JSON/YAML with controls"),
    interactive: bool = typer.Option(True, "--interactive/--no-interactive", help="Interactive mode"),
):
    """Assess ISO 27001 compliance."""
    if interactive:
        typer.echo("📋 ISO 27001 Compliance Assessment")
        typer.echo("=" * 40)
        
        themes = {
            "A.5": "Organizational Controls",
            "A.6": "People Controls", 
            "A.7": "Physical Controls",
            "A.8": "Technological Controls"
        }
        
        results = {}
        for code, name in themes.items():
            typer.echo(f"\n{code} - {name}")
            score = typer.prompt(f"  Implementation level (0-100)", type=int, default=50)
            results[code] = score
        
        typer.echo("\n📊 Results:")
        for code, score in results.items():
            status = "✅" if score >= 70 else "⚠️" if score >= 40 else "❌"
            typer.echo(f"  {status} {code}: {score}%")
        
        avg = sum(results.values()) / len(results)
        typer.echo(f"\n🎯 Overall: {avg:.0f}%")
    else:
        typer.echo("Use --controls to specify a controls file")


# ---------------------------------------------------------------------------
# API command
# ---------------------------------------------------------------------------
@app.command("api")
def api_cmd(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind"),
    port: int = typer.Option(8000, "--port", help="Port to bind"),
):
    """Start the REST API server."""
    from cybercli import api as api_module
    
    typer.echo(f"🚀 Starting API server on {host}:{port}")
    typer.echo(f"   Docs: http://{host}:{port}/docs")
    
    # Import and run the API
    import uvicorn
    from cybercli.api import app as api_app
    
    uvicorn.run(api_app, host=host, port=port, log_level="info")


# ---------------------------------------------------------------------------
# Stats command
# ---------------------------------------------------------------------------
@app.command("stats")
def stats_cmd():
    """Show scan statistics."""
    history_file = os.path.join(_CONFIG_DIR, "history.json")
    history = _load_json(history_file)
    
    if not isinstance(history, dict):
        history = {}
    
    scans = history.get("scans", [])
    if not isinstance(scans, list):
        scans = []
    
    typer.echo("📊 Scan Statistics")
    typer.echo("=" * 30)
    typer.echo(f"Total scans: {len(scans)}")
    
    if scans:
        last = scans[-1]
        typer.echo(f"Last scan: {last['target']} ({last['timestamp'][:10]})")


# Register scan group
app.add_typer(scan_app, name="scan")


if __name__ == "__main__":
    app()
