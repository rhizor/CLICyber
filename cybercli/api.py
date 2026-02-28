"""
REST API Server for CyberCLI.

Provides a FastAPI-based REST API for:
- Scanning operations
- Threat intelligence queries
- Compliance checks
- Report generation
- CTF lab management
"""

import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
import uvicorn

# Import engines
from .engines import network_scanner, malware_scanner, hardening_checker
from .engines import threat_intel as ti
from .engines import cve_monitor
from .engines import compliance
from .engines import container_security
from .engines import file_integrity
from .engines import reporting


app = FastAPI(
    title="CyberCLI API",
    description="REST API for CyberAgent security CLI",
    version="1.0.0"
)

# Store background scan results
scan_results: Dict[str, Any] = {}


# --- Request Models ---

class NetworkScanRequest(BaseModel):
    """Network scan request."""
    target: str = Field(..., description="CIDR or IP address")
    top_ports: int = Field(100, description="Number of top ports")
    

class MalwareScanRequest(BaseModel):
    """Malware scan request."""
    path: str = Field(..., description="Directory to scan")
    recursive: bool = Field(True, description="Scan recursively")


class ThreatIntelRequest(BaseModel):
    """Threat intel query request."""
    indicator: str = Field(..., description="IP, domain, or hash")
    sources: List[str] = Field(["shodan"], description="Sources to query")


class CVEQueryRequest(BaseModel):
    """CVE query request."""
    cve_id: Optional[str] = None
    keyword: Optional[str] = None
    product: Optional[str] = None
    days: int = Field(7, description="Recent CVE days")


class ComplianceCheckRequest(BaseModel):
    """Compliance check request."""
    controls: List[str] = Field(..., description="ISO 27001 controls to check")


class ContainerScanRequest(BaseModel):
    """Container scan request."""
    target: str = Field("docker", description="docker or kubernetes")


class FIMRequest(BaseModel):
    """File integrity request."""
    action: str = Field(..., description="create-baseline, check, monitor")
    paths: List[str] = Field(..., description="Paths to monitor")


class ReportRequest(BaseModel):
    """Report generation request."""
    report_type: str = Field("technical", description="technical, executive, compliance")
    format: str = Field("json", description="json, html, pdf")
    include_ai: bool = Field(False, description="Include AI analysis")


class RemediationRequest(BaseModel):
    """Remediation request."""
    finding_id: str = Field(..., description="Finding to remediate")
    dry_run: bool = Field(True, description="Simulate only")


# --- Response Models ---

class ScanResponse(BaseModel):
    """Generic scan response."""
    status: str
    target: str
    timestamp: str
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    timestamp: str
    services: Dict[str, str] = {}


# --- API Endpoints ---

@app.get("/", response_model=Dict)
async def root():
    """Root endpoint."""
    return {
        "service": "CyberCLI API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now().isoformat(),
        services={
            "api": "up",
            "scanner": "up"
        }
    )


# --- Network Scanning ---

@app.post("/scan/network", response_model=ScanResponse)
async def scan_network(req: NetworkScanRequest):
    """Perform network port scan."""
    try:
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        ports = common_ports[:req.top_ports]
        
        results = network_scanner.scan_network(req.target, ports)
        
        return ScanResponse(
            status="completed",
            target=req.target,
            timestamp=datetime.now().isoformat(),
            results={"hosts": results}
        )
    
    except Exception as e:
        return ScanResponse(
            status="error",
            target=req.target,
            timestamp=datetime.now().isoformat(),
            error=str(e)
        )


@app.get("/scan/history", response_model=List[Dict])
async def get_scan_history(limit: int = Query(50)):
    """Get scan history."""
    history_file = os.path.join(os.path.expanduser("~"), ".cybercli", "history.json")
    
    if not os.path.exists(history_file):
        return []
    
    try:
        with open(history_file, "r") as f:
            history = json.load(f)
        return history[-limit:]
    except Exception:
        return []


# --- Malware Scanning ---

@app.post("/scan/malware", response_model=ScanResponse)
async def scan_malware(req: MalwareScanRequest):
    """Perform malware scan."""
    try:
        results = malware_scanner.scan_path(req.path, recursive=req.recursive)
        
        infected = {fp: info for fp, (h, info) in results.items() if info}
        
        return ScanResponse(
            status="completed",
            target=req.path,
            timestamp=datetime.now().isoformat(),
            results={
                "total_files": len(results),
                "infected": len(infected),
                "findings": {fp: {"hash": h, "info": info} for fp, (h, info) in infected.items()}
            }
        )
    
    except Exception as e:
        return ScanResponse(
            status="error",
            target=req.path,
            timestamp=datetime.now().isoformat(),
            error=str(e)
        )


# --- Hardening Checks ---

@app.get("/hardening", response_model=Dict)
async def get_hardening_checks():
    """Run system hardening checks."""
    try:
        results = hardening_checker.run_checks()
        return {
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Threat Intelligence ---

@app.post("/threatintel", response_model=Dict)
async def query_threat_intel(req: ThreatIntelRequest):
    """Query threat intelligence sources."""
    results = {}
    
    try:
        # Query each source
        if "shodan" in req.sources:
            try:
                from .engines.threat_intel import query_shodan
                results["shodan"] = query_shodan(req.indicator)
            except Exception as e:
                results["shodan"] = {"error": str(e)}
        
        if "abuseipdb" in req.sources:
            try:
                from .engines.threat_intel import query_abuseipdb
                results["abuseipdb"] = query_abuseipdb(req.indicator)
            except Exception as e:
                results["abuseipdb"] = {"error": str(e)}
        
        if "virustotal" in req.sources:
            try:
                from .engines.threat_intel import query_virustotal
                results["virustotal"] = query_virustotal(req.indicator)
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        
        return {
            "indicator": req.indicator,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- CVE Monitoring ---

@app.post("/cve/query", response_model=Dict)
async def query_cve(req: CVEQueryRequest):
    """Query CVE database."""
    monitor = cve_monitor.CVEMonitor()
    
    try:
        if req.cve_id:
            cve = monitor.search_cve(req.cve_id)
            if cve:
                return {
                    "cve": {
                        "id": cve.id,
                        "description": cve.description,
                        "severity": cve.severity,
                        "cvss_score": cve.cvss_score,
                        "published": cve.published,
                        "remediation": cve.remediation
                    }
                }
            return {"error": "CVE not found"}
        
        elif req.keyword:
            cves = monitor.search_by_keyword(req.keyword)
            return {
                "keyword": req.keyword,
                "count": len(cves),
                "cves": [
                    {
                        "id": c.id,
                        "severity": c.severity,
                        "cvss_score": c.cvss_score,
                        "published": c.published
                    }
                    for c in cves
                ]
            }
        
        elif req.product:
            cves = monitor.get_cves_by_product(req.product)
            return {
                "product": req.product,
                "count": len(cves),
                "cves": [
                    {
                        "id": c.id,
                        "severity": c.severity,
                        "cvss_score": c.cvss_score,
                        "published": c.published
                    }
                    for c in cves
                ]
            }
        
        else:
            cves = monitor.get_recent_cves(days=req.days)
            return {
                "days": req.days,
                "count": len(cves),
                "cves": [
                    {
                        "id": c.id,
                        "severity": c.severity,
                        "cvss_score": c.cvss_score,
                        "published": c.published
                    }
                    for c in cves
                ]
            }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Compliance ---

@app.post("/compliance", response_model=Dict)
async def check_compliance(req: ComplianceCheckRequest):
    """Check ISO 27001 compliance."""
    try:
        results = compliance.check_controls(req.controls)
        return {
            "controls": req.controls,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Container Security ---

@app.post("/container/scan", response_model=Dict)
async def scan_container(req: ContainerScanRequest):
    """Scan containers for security issues."""
    try:
        if req.target.lower() == "docker":
            findings = container_security.docker_scan()
        elif req.target.lower() == "kubernetes":
            findings = container_security.kubernetes_scan()
        else:
            raise HTTPException(status_code=400, detail="Invalid target: use 'docker' or 'kubernetes'")
        
        return {
            "target": req.target,
            "timestamp": datetime.now().isoformat(),
            "findings_count": len(findings),
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "resource": f.resource
                }
                for f in findings
            ]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- File Integrity ---

@app.post("/fim", response_model=Dict)
async def file_integrity_monitoring(req: FIMRequest):
    """File integrity operations."""
    monitor = file_integrity.FileIntegrityMonitor()
    
    try:
        if req.action == "create-baseline":
            count = monitor.create_baseline(req.paths)
            return {
                "action": "create-baseline",
                "status": "completed",
                "files_tracked": count
            }
        
        elif req.action == "check":
            alerts = monitor.check_integrity(req.paths)
            return {
                "action": "check",
                "status": "completed",
                "alerts_count": len(alerts),
                "alerts": [
                    {
                        "type": a.type,
                        "path": a.path,
                        "old_value": a.old_value,
                        "new_value": a.new_value
                    }
                    for a in alerts
                ]
            }
        
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Reports ---

@app.post("/report", response_model=Dict)
async def generate_report(req: ReportRequest):
    """Generate security report."""
    try:
        # Gather data
        history_file = os.path.join(os.path.expanduser("~"), ".cybercli", "history.json")
        history = []
        if os.path.exists(history_file):
            with open(history_file, "r") as f:
                history = json.load(f)
        
        report_data = {
            "report_type": req.report_type,
            "format": req.format,
            "generated_at": datetime.now().isoformat(),
            "scan_history": history[-50:] if history else [],
            "summary": {
                "total_scans": len(history)
            }
        }
        
        # Generate report content
        content = reporting.generate_report(
            report_data,
            report_type=req.report_type,
            output_format=req.format
        )
        
        return {
            "status": "completed",
            "report_type": req.report_type,
            "format": req.format,
            "data": report_data
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Utility Functions ---

def start_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Start the API server."""
    uvicorn.run(
        "cybercli.api:app",
        host=host,
        port=port,
        reload=reload
    )


if __name__ == "__main__":
    start_server()
