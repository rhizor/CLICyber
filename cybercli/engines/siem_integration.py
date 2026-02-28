"""
SIEM Integration Engine.

Provides integration with SIEM platforms:
- Splunk
- Elasticsearch/ELK
- Syslog (rsyslog, syslog-ng)
- Custom webhooks
"""

import json
import os
import socket
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class SIEMEvent:
    """Represents a SIEM event."""
    timestamp: str
    source: str
    event_type: str
    severity: str
    message: str
    raw_data: Dict[str, Any]


class SplunkConnector:
    """Splunk SIEM connector."""
    
    def __init__(self, host: str, port: int = 8089, username: str = None, password: str = None, token: str = None):
        self.host = host
        self.port = port
        self.username = username or os.environ.get("SPLUNK_USERNAME")
        self.password = password or os.environ.get("SPLUNK_PASSWORD")
        self.token = token or os.environ.get("SPLUNK_TOKEN")
        self.base_url = f"https://{host}:{port}"
    
    def _get_auth_header(self) -> str:
        """Get authentication header."""
        if self.token:
            return f"Bearer {self.token}"
        elif self.username and self.password:
            return f"Basic {urllib.parse.b64encode(f'{self.username}:{self.password}'.encode()).decode()}"
        else:
            raise ValueError("No authentication credentials provided")
    
    def send_event(self, event: SIEMEvent, index: str = "main", sourcetype: str = "cybercli") -> bool:
        """Send event to Splunk HEC (HTTP Event Collector)."""
        try:
            # Try HEC first
            hec_url = f"{self.base_url}/services/collector"
            hec_token = self.token or os.environ.get("SPLUNK_HEC_TOKEN")
            
            if hec_token:
                payload = {
                    "time": datetime.fromisoformat(event.timestamp).timestamp(),
                    "host": event.source,
                    "source": sourcetype,
                    "sourcetype": sourcetype,
                    "event": asdict(event)
                }
                
                req = urllib.request.Request(
                    hec_url,
                    data=json.dumps(payload).encode(),
                    headers={
                        "Authorization": f"Bearer {hec_token}",
                        "Content-Type": "application/json"
                    },
                    method="POST"
                )
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    return response.status == 200
            
            return False
        
        except Exception as e:
            print(f"Splunk HEC error: {e}")
            return False
    
    def search(self, query: str, earliest: str = "-24h", latest: str = "now") -> List[Dict]:
        """Execute a Splunk search query."""
        try:
            # Use Splunk REST API
            url = f"{self.base_url}/services/search/jobs"
            
            # Create search job
            params = {
                "search": f"search {query}",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json"
            }
            
            req = urllib.request.Request(
                url,
                data=urllib.parse.urlencode(params).encode(),
                headers={
                    "Authorization": self._get_auth_header(),
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                method="POST"
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode())
                sid = result.get("sid")
            
            if not sid:
                return []
            
            # Get results
            results_url = f"{self.base_url}/services/search/jobs/{sid}/results?output_mode=json"
            req = urllib.request.Request(results_url, headers={"Authorization": self._get_auth_header()})
            
            with urllib.request.urlopen(req, timeout=60) as response:
                results = json.loads(response.read().decode())
                return results.get("results", [])
        
        except Exception as e:
            print(f"Search error: {e}")
            return []


class ELKConnector:
    """Elasticsearch/Logstash/Kibana connector."""
    
    def __init__(self, hosts: List[str] = None, index: str = "cybercli-logs", api_key: str = None):
        self.hosts = hosts or [os.environ.get("ELASTIC_HOST", "localhost:9200")]
        self.index = index
        self.api_key = api_key or os.environ.get("ELASTIC_API_KEY")
    
    def _get_auth(self) -> Optional[tuple]:
        """Get authentication tuple."""
        if self.api_key:
            return ("elastic", self.api_key)
        return None
    
    def send_event(self, event: SIEMEvent) -> bool:
        """Send event to Elasticsearch."""
        try:
            url = f"http://{self.hosts[0]}/{self.index}/_doc"
            
            payload = {
                "@timestamp": event.timestamp,
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "message": event.message,
                "data": event.raw_data
            }
            
            auth = self._get_auth()
            
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            if auth:
                import urllib.request
                pw_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                pw_manager.add_password(None, url, auth[0], auth[1])
                handler = urllib.request.HTTPBasicAuthHandler(pw_manager)
                opener = urllib.request.build_opener(handler)
                response = opener.open(req, timeout=30)
            else:
                with urllib.request.urlopen(req, timeout=30) as response:
                    pass
            
            return True
        
        except Exception as e:
            print(f"Elasticsearch error: {e}")
            return False
    
    def search(self, query: str, size: int = 100) -> List[Dict]:
        """Search Elasticsearch."""
        try:
            url = f"http://{self.hosts[0]}/{self.index}/_search"
            
            payload = {
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["message", "event_type", "source"]
                    }
                },
                "size": size
            }
            
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode())
                return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
        
        except Exception as e:
            print(f"Elasticsearch search error: {e}")
            return []


class SyslogConnector:
    """Syslog connector (rsyslog, syslog-ng)."""
    
    # Syslog severity levels
    SEVERITY = {
        "EMERGENCY": 0,
        "ALERT": 1,
        "CRITICAL": 2,
        "ERROR": 3,
        "WARNING": 4,
        "NOTICE": 5,
        "INFO": 6,
        "DEBUG": 7
    }
    
    # Syslog facilities
    FACILITY_LOCAL0 = 16
    FACILITY_LOCAL7 = 23
    
    def __init__(self, host: str = "localhost", port: int = 514, protocol: str = "udp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.socket = None
    
    def _connect(self) -> None:
        """Establish syslog connection."""
        if self.protocol == "udp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
    
    def _format_syslog(self, event: SIEMEvent) -> bytes:
        """Format event as syslog message (RFC 3164)."""
        severity = self.SEVERITY.get(event.severity.upper(), 6)
        facility = self.FACILITY_LOCAL0
        priority = (facility << 3) | severity
        
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        hostname = event.source or "cybercli"
        message = f"{event.message}"
        
        syslog_msg = f"<{priority}>{timestamp} {hostname} cybercli: {json.dumps(asdict(event))}"
        return syslog_msg.encode("utf-8")
    
    def send_event(self, event: SIEMEvent) -> bool:
        """Send event via syslog."""
        try:
            self._connect()
            msg = self._format_syslog(event)
            
            if self.protocol == "udp":
                self.socket.sendto(msg, (self.host, self.port))
            else:
                self.socket.send(msg)
            
            return True
        
        except Exception as e:
            print(f"Syslog error: {e}")
            return False
        
        finally:
            if self.socket:
                self.socket.close()
                self.socket = None
    
    def send_batch(self, events: List[SIEMEvent]) -> int:
        """Send multiple events."""
        success_count = 0
        for event in events:
            if self.send_event(event):
                success_count += 1
        return success_count


class WebhookConnector:
    """Generic webhook connector for custom integrations."""
    
    def __init__(self, url: str, method: str = "POST", headers: Dict[str, str] = None):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
    
    def send_event(self, event: SIEMEvent) -> bool:
        """Send event to webhook."""
        try:
            payload = asdict(event)
            
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode(),
                headers=self.headers,
                method=self.method
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                return 200 <= response.status < 300
        
        except Exception as e:
            print(f"Webhook error: {e}")
            return False
    
    def send_alert(self, title: str, message: str, severity: str = "INFO") -> bool:
        """Send simple alert to webhook."""
        event = SIEMEvent(
            timestamp=datetime.now().isoformat(),
            source="cybercli",
            event_type="alert",
            severity=severity,
            message=message,
            raw_data={"title": title}
        )
        return self.send_event(event)


# Factory function
def get_siem_connector(siem_type: str, **kwargs) -> Any:
    """Get SIEM connector by type."""
    connectors = {
        "splunk": SplunkConnector,
        "elk": ELKConnector,
        "elasticsearch": ELKConnector,
        "syslog": SyslogConnector,
        "webhook": WebhookConnector
    }
    
    if siem_type.lower() not in connectors:
        raise ValueError(f"Unknown SIEM type: {siem_type}. Available: {', '.join(connectors.keys())}")
    
    return connectors[siem_type.lower()](**kwargs)


# CLI functions
def siem_send(siem_type: str, message: str, severity: str = "INFO", **kwargs) -> bool:
    """Send event to SIEM."""
    try:
        connector = get_siem_connector(siem_type, **kwargs)
        
        event = SIEMEvent(
            timestamp=datetime.now().isoformat(),
            source="cybercli",
            event_type="alert",
            severity=severity.upper(),
            message=message,
            raw_data=kwargs
        )
        
        result = connector.send_event(event)
        
        if result:
            print(f"✅ Event sent to {siem_type}")
        else:
            print(f"❌ Failed to send event to {siem_type}")
        
        return result
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def siem_test(siem_type: str, **kwargs) -> bool:
    """Test SIEM connection."""
    try:
        connector = get_siem_connector(siem_type, **kwargs)
        
        event = SIEMEvent(
            timestamp=datetime.now().isoformat(),
            source="cybercli",
            event_type="test",
            severity="INFO",
            message="CyberCLI SIEM integration test",
            raw_data={"test": True}
        )
        
        result = connector.send_event(event)
        
        if result:
            print(f"✅ {siem_type} connection test successful")
        else:
            print(f"❌ {siem_type} connection test failed")
        
        return result
    
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
