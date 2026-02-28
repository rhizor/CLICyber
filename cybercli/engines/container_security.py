"""
Container Security Engine.

Provides Docker and Kubernetes security scanning including:
- Docker container vulnerability assessment
- Kubernetes cluster security checks
- Container runtime security analysis
- Image scanning recommendations
"""

import json
import os
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ContainerFinding:
    """Represents a container security finding."""
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    title: str
    description: str
    recommendation: str
    resource: Optional[str] = None


class DockerSecurityScanner:
    """Docker container security scanner."""
    
    def __init__(self):
        self.findings: List[ContainerFinding] = []
    
    def check_docker_installed(self) -> bool:
        """Check if Docker is installed and running."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_running_containers(self) -> List[ContainerFinding]:
        """Scan all running containers for security issues."""
        self.findings = []
        
        if not self.check_docker_installed():
            self.findings.append(ContainerFinding(
                severity="HIGH",
                category="Installation",
                title="Docker Not Installed",
                description="Docker is not installed on this system",
                recommendation="Install Docker for container security scanning"
            ))
            return self.findings
        
        try:
            # Get running containers
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}}|{{.Image}}|{{.Ports}}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return self.findings
            
            containers = result.stdout.strip().split("\n") if result.stdout.strip() else []
            
            for container in containers:
                if "|" not in container:
                    continue
                    
                container_id, image, ports = container.split("|")
                self._check_container(container_id, image, ports)
            
            # Check Docker daemon configuration
            self._check_docker_daemon()
            
        except Exception as e:
            self.findings.append(ContainerFinding(
                severity="MEDIUM",
                category="Access",
                title="Docker Scan Failed",
                description=f"Could not scan Docker: {str(e)}",
                recommendation="Ensure Docker daemon is running and you have permissions"
            ))
        
        return self.findings
    
    def _check_container(self, container_id: str, image: str, ports: str) -> None:
        """Check individual container security."""
        
        # Check for exposed sensitive ports
        sensitive_ports = ["3306", "5432", "6379", "27017", "9200", "11211"]
        for port in sensitive_ports:
            if port in ports:
                self.findings.append(ContainerFinding(
                    severity="HIGH",
                    category="Network",
                    title=f"Sensitive Port Exposed: {port}",
                    description=f"Container has port {port} exposed",
                    recommendation=f"Review if port {port} should be exposed. Use Docker networks for isolation.",
                    resource=container_id
                ))
        
        # Check if running as root
        result = subprocess.run(
            ["docker", "inspect", container_id, "--format", "{{.Config.User}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        user = result.stdout.strip()
        if not user or user == "root" or user == "0":
            self.findings.append(ContainerFinding(
                severity="HIGH",
                category="Privilege",
                title="Container Running as Root",
                description=f"Container {container_id[:12]} is running as root user",
                recommendation="Create and use a non-root user in the container for security",
                resource=container_id
            ))
        
        # Check container capabilities
        result = subprocess.run(
            ["docker", "inspect", container_id, "--format", "{{.HostInfo.Privileged}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.stdout.strip().lower() == "true":
            self.findings.append(ContainerFinding(
                severity="CRITICAL",
                category="Privilege",
                title="Container Running in Privileged Mode",
                description=f"Container {container_id[:12]} has privileged access",
                recommendation="Remove privileged mode unless absolutely required",
                resource=container_id
            ))
        
        # Check for insecure image tags (latest, dev)
        if ":latest" in image or ":dev" in image or ":master" in image:
            self.findings.append(ContainerFinding(
                severity="MEDIUM",
                category="Image",
                title="Insecure Image Tag",
                description=f"Image {image} uses unstable tag",
                recommendation="Use specific version tags for reproducibility and security",
                resource=container_id
            ))
    
    def _check_docker_daemon(self) -> None:
        """Check Docker daemon configuration."""
        
        # Check if Docker socket is properly secured
        socket_path = "/var/run/docker.sock"
        if os.path.exists(socket_path):
            stat_info = os.stat(socket_path)
            mode = stat_info.st_mode & 0o777
            
            if mode > 0o660:
                self.findings.append(ContainerFinding(
                    severity="MEDIUM",
                    category="Daemon",
                    title="Docker Socket Permissions Too Open",
                    description=f"Docker socket has permissions {oct(mode)}",
                    recommendation="Restrict Docker socket to docker group only (chmod 660)"
                ))
        
        # Check for Docker daemon configuration
        config_path = "/etc/docker/daemon.json"
        if not os.path.exists(config_path):
            self.findings.append(ContainerFinding(
                severity="LOW",
                category="Daemon",
                title="No Docker Daemon Configuration",
                description="No daemon.json configuration found",
                recommendation="Create /etc/docker/daemon.json with security settings"
            ))


class KubernetesSecurityScanner:
    """Kubernetes cluster security scanner."""
    
    def __init__(self, kubeconfig: Optional[str] = None):
        self.kubeconfig = kubeconfig or os.environ.get("KUBECONFIG")
        self.findings: List[ContainerFinding] = []
    
    def check_kubectl(self) -> bool:
        """Check if kubectl is available."""
        try:
            result = subprocess.run(
                ["kubectl", "version", "--client"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_cluster(self) -> List[ContainerFinding]:
        """Scan Kubernetes cluster for security issues."""
        self.findings = []
        
        if not self.check_kubectl():
            self.findings.append(ContainerFinding(
                severity="HIGH",
                category="Installation",
                title="kubectl Not Installed",
                description="kubectl is not installed or not in PATH",
                recommendation="Install kubectl for Kubernetes security scanning"
            ))
            return self.findings
        
        self._check_pod_security()
        self._check_rbac()
        self._check_network_policies()
        self._check_secrets()
        
        return self.findings
    
    def _check_pod_security(self) -> None:
        """Check Pod Security Standards compliance."""
        try:
            result = subprocess.run(
                ["kubectl", "get", "pods", "-A", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return
            
            pods = json.loads(result.stdout)
            
            for pod in pods.get("items", []):
                pod_name = pod["metadata"]["name"]
                namespace = pod["metadata"]["namespace"]
                
                # Check privilege escalation
                spec = pod.get("spec", {})
                for container in spec.get("containers", []):
                    security = container.get("securityContext", {})
                    
                    if not security.get("allowPrivilegeEscalation", False) == False:
                        self.findings.append(ContainerFinding(
                            severity="HIGH",
                            category="Pod Security",
                            title="Privilege Escalation Allowed",
                            description=f"Pod {pod_name} allows privilege escalation",
                            recommendation="Set securityContext.allowPrivilegeEscalation: false",
                            resource=f"{namespace}/{pod_name}"
                        ))
                    
                    if not security.get("runAsNonRoot", False):
                        self.findings.append(ContainerFinding(
                            severity="MEDIUM",
                            category="Pod Security",
                            title="Not Running as Non-Root",
                            description=f"Pod {pod_name} may run as root",
                            recommendation="Set securityContext.runAsNonRoot: true",
                            resource=f"{namespace}/{pod_name}"
                        ))
                    
                    # Check for sensitive host paths
                    volumes = spec.get("volumes", [])
                    for volume in volumes:
                        host_path = volume.get("hostPath", {})
                        if host_path:
                            path = host_path.get("path", "")
                            if path in ["/", "/proc", "/sys", "/var/run/docker.sock"]:
                                self.findings.append(ContainerFinding(
                                    severity="CRITICAL",
                                    category="Host Access",
                                    title="Sensitive Host Path Mounted",
                                    description=f"Pod mounts host path {path}",
                                    recommendation="Remove unnecessary hostPath mounts",
                                    resource=f"{namespace}/{pod_name}"
                                ))
        
        except Exception as e:
            self.findings.append(ContainerFinding(
                severity="LOW",
                category="Scan",
                title="Pod Scan Incomplete",
                description=f"Could not scan pods: {str(e)}",
                recommendation="Ensure kubectl is configured correctly"
            ))
    
    def _check_rbac(self) -> None:
        """Check RBAC configuration."""
        try:
            result = subprocess.run(
                ["kubectl", "get", "clusterroles", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return
            
            roles = json.loads(result.stdout)
            
            for role in roles.get("items", []):
                role_name = role["metadata"]["name"]
                
                # Skip default Kubernetes roles
                if role_name.startswith("system:"):
                    continue
                
                # Check for wildcard verbs
                rules = role.get("rules", [])
                for rule in rules:
                    verbs = rule.get("verbs", [])
                    if "*" in verbs:
                        self.findings.append(ContainerFinding(
                            severity="HIGH",
                            category="RBAC",
                            title="ClusterRole with Wildcard Verbs",
                            description=f"Role {role_name} has wildcard (*) verbs",
                            recommendation="Use specific verbs instead of wildcards",
                            resource=role_name
                        ))
        
        except Exception:
            pass
    
    def _check_network_policies(self) -> None:
        """Check if NetworkPolicies are defined."""
        try:
            result = subprocess.run(
                ["kubectl", "get", "networkpolicies", "-A", "--no-headers"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return
            
            if not result.stdout.strip():
                self.findings.append(ContainerFinding(
                    severity="MEDIUM",
                    category="Network",
                    title="No NetworkPolicies Defined",
                    description="No Kubernetes NetworkPolicies found in cluster",
                    recommendation="Define NetworkPolicies to restrict pod-to-pod communication"
                ))
        
        except Exception:
            pass
    
    def _check_secrets(self) -> None:
        """Check secrets configuration."""
        try:
            # Check for default service account tokens
            result = subprocess.run(
                ["kubectl", "get", "serviceaccounts", "-A", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return
            
            accounts = json.loads(result.stdout)
            
            for sa in accounts.get("items", []):
                if sa["metadata"]["name"] == "default" and sa["metadata"]["namespace"] == "default":
                    # Check if default SA hasautomountServiceAccountToken
                    if not sa.get("automountServiceAccountToken", True) == False:
                        self.findings.append(ContainerFinding(
                            severity="MEDIUM",
                            category="Secrets",
                            title="Default Service Account May Mount Tokens",
                            description="Default service account may have mounted tokens",
                            recommendation="Set automountServiceAccountToken: false for default SA",
                            resource="default/default"
                        ))
        
        except Exception:
            pass


# CLI functions
def docker_scan() -> List[ContainerFinding]:
    """Run Docker security scan."""
    scanner = DockerSecurityScanner()
    findings = scanner.scan_running_containers()
    
    print("\n🐳 Docker Security Scan Results:\n")
    print(f"   Containers scanned: {len([f for f in findings if f.resource and f.category == 'Network'])}")
    print(f"   Findings: {len(findings)}\n")
    
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for severity in severity_order:
        sev_findings = [f for f in findings if f.severity == severity]
        if sev_findings:
            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            print(f"   {emoji} {severity}: {len(sev_findings)}")
            for f in sev_findings:
                print(f"      - {f.title}")
    
    return findings


def kubernetes_scan() -> List[ContainerFinding]:
    """Run Kubernetes security scan."""
    scanner = KubernetesSecurityScanner()
    findings = scanner.scan_cluster()
    
    print("\n☸️ Kubernetes Security Scan Results:\n")
    print(f"   Findings: {len(findings)}\n")
    
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for severity in severity_order:
        sev_findings = [f for f in findings if f.severity == severity]
        if sev_findings:
            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            print(f"   {emoji} {severity}: {len(sev_findings)}")
            for f in sev_findings:
                print(f"      - {f.title}")
    
    return findings
