"""
CVE Monitoring Engine.

Provides CVE monitoring using NVD (National Vulnerability Database)
and CIRCL CVE Search API. Supports vulnerability tracking, severity
analysis, and remediation recommendations.
"""

import json
import os
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass


@dataclass
class CVEEntry:
    """Represents a CVE vulnerability entry."""
    id: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: float
    published: str
    affected_products: List[str]
    references: List[str]
    remediation: Optional[str] = None


class CVEMonitor:
    """CVE monitoring using NVD and CIRCL APIs."""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CIRCL_API_URL = "https://cve.circl.lu/api"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self._cache: Dict[str, Any] = {}
    
    def _make_request(self, url: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with error handling."""
        try:
            if params:
                url += "?" + urllib.parse.urlencode(params)
            
            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            print(f"Warning: API request failed: {e}")
            return None
    
    def search_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Search for a specific CVE by ID."""
        # Try CIRCL first (no API key required)
        data = self._make_request(f"{self.CIRCL_API_URL}/cve/{cve_id}")
        if data:
            return self._parse_circl_cve(data)
        
        # Fallback to NVD
        params = {"cveId": cve_id}
        data = self._make_request(self.NVD_API_URL, params)
        if data and data.get("vulnerabilities"):
            return self._parse_nvd_cve(data["vulnerabilities"][0])
        
        return None
    
    def search_by_keyword(self, keyword: str, limit: int = 10) -> List[CVEEntry]:
        """Search CVEs by keyword (product name, vendor, etc.)."""
        cves = []
        
        # Use CIRCL for search (no API key needed)
        params = {"keyword": keyword, "limit": limit}
        data = self._make_request(f"{self.CIRCL_API_URL}/search/{keyword}", {"limit": limit})
        
        if data:
            for item in data.get("results", [])[:limit]:
                cve = self._parse_circl_cve(item)
                if cve:
                    cves.append(cve)
        
        return cves
    
    def get_recent_cves(self, days: int = 7, limit: int = 20) -> List[CVEEntry]:
        """Get recent CVEs from the last N days."""
        cves = []
        date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        
        params = {
            "pubStartDate": date_from,
            "resultsPerPage": limit
        }
        
        data = self._make_request(self.NVD_API_URL, params)
        if data:
            for vuln in data.get("vulnerabilities", [])[:limit]:
                cve = self._parse_nvd_cve(vuln)
                if cve:
                    cves.append(cve)
        
        return cves
    
    def get_cves_by_product(self, product: str, vendor: str = "apache") -> List[CVEEntry]:
        """Get CVEs for a specific product."""
        return self.search_by_keyword(f"{vendor}:{product}")
    
    def _parse_circl_cve(self, data: Dict) -> Optional[CVEEntry]:
        """Parse CVE data from CIRCL API."""
        try:
            cve_id = data.get("id", "")
            summary = data.get("summary", "")
            
            # Extract CVSS score
            cvss = data.get("cvss", 0.0)
            if cvss:
                if cvss >= 9.0:
                    severity = "CRITICAL"
                elif cvss >= 7.0:
                    severity = "HIGH"
                elif cvss >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                severity = "UNKNOWN"
                cvss = 0.0
            
            # Get affected products
            products = []
            for ref in data.get("references", []):
                if "affected" in ref:
                    products.append(ref.get("product", ""))
            
            refs = [r.get("url", "") for r in data.get("references", [])]
            
            return CVEEntry(
                id=cve_id,
                description=summary,
                severity=severity,
                cvss_score=cvss,
                published=data.get("published", ""),
                affected_products=products,
                references=refs,
                remediation=self._generate_remediation(cve_id, severity)
            )
        except Exception:
            return None
    
    def _parse_nvd_cve(self, vuln: Dict) -> Optional[CVEEntry]:
        """Parse CVE data from NVD API."""
        try:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get CVSS metrics
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                base_severity = cvss_data.get("baseSeverity", "UNKNOWN")
            else:
                cvss_score = 0.0
                base_severity = "UNKNOWN"
            
            # Get affected products
            products = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria:
                            products.append(criteria)
            
            # Get references
            refs = [r.get("url", "") for r in cve_data.get("references", [])]
            
            return CVEEntry(
                id=cve_id,
                description=description,
                severity=base_severity,
                cvss_score=cvss_score,
                published=cve_data.get("published", ""),
                affected_products=products[:10],  # Limit
                references=refs[:10],
                remediation=self._generate_remediation(cve_id, base_severity)
            )
        except Exception:
            return None
    
    def _generate_remediation(self, cve_id: str, severity: str) -> str:
        """Generate remediation advice based on CVE severity."""
        if severity == "CRITICAL":
            return (
                f"URGENT: Apply available patch immediately. "
                f"If no patch available, consider isolating affected system. "
                f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
        elif severity == "HIGH":
            return (
                f"Schedule patch deployment within 24-48 hours. "
                f"Implement compensating controls if immediate patching not possible. "
                f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
        elif severity == "MEDIUM":
            return (
                f"Apply patch within standard maintenance window. "
                f"Review CVSS vector for specific attack requirements. "
                f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
        else:
            return (
                f"Monitor for updates. Evaluate risk in context of your environment. "
                f"Reference: https://nvd.nist.gov/vuln/detail/{cve_id}"
            )


# CLI command integration
def cve_search(cve_id: str, detailed: bool = False) -> None:
    """Search for a specific CVE."""
    monitor = CVEMonitor()
    cve = monitor.search_cve(cve_id)
    
    if cve:
        print(f"\n📋 CVE: {cve.id}")
        print(f"   Severity: {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"   Published: {cve.published}")
        print(f"   Description: {cve.description[:200]}...")
        
        if detailed and cve.remediation:
            print(f"\n🛡️ Remediation:\n   {cve.remediation}")
    else:
        print(f"❌ CVE {cve_id} not found")


def cve_recent(days: int = 7, limit: int = 10) -> None:
    """Show recent CVEs."""
    monitor = CVEMonitor()
    cves = monitor.get_recent_cves(days=days, limit=limit)
    
    print(f"\n📊 Recent CVEs (last {days} days):\n")
    for cve in cves:
        severity_emoji = "🔴" if cve.severity == "CRITICAL" else "🟠" if cve.severity == "HIGH" else "🟡"
        print(f"  {severity_emoji} {cve.id} - {cve.severity} ({cve.cvss_score}) - {cve.published[:10]}")
        print(f"     {cve.description[:80]}...")
