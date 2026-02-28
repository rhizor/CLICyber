"""
File Integrity Monitoring (FIM) Engine.

Provides file integrity monitoring with hash verification,
change detection, and baseline comparison.
"""

import hashlib
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class FileEntry:
    """Represents a monitored file with its hash."""
    path: str
    hash: str
    size: int
    modified: float
    permissions: str


@dataclass
class IntegrityAlert:
    """Represents an integrity alert."""
    type: str  # added, removed, modified, permissions_changed
    path: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    timestamp: Optional[str] = None


class FileIntegrityMonitor:
    """File integrity monitoring system."""
    
    def __init__(self, baseline_file: str = None):
        self.baseline_file = baseline_file or os.path.join(
            os.path.expanduser("~"), ".cybercli", "fim_baseline.json"
        )
        self.baseline: Dict[str, FileEntry] = {}
        self._load_baseline()
    
    def _load_baseline(self) -> None:
        """Load baseline from file."""
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, "r") as f:
                    data = json.load(f)
                    self.baseline = {
                        path: FileEntry(**entry) 
                        for path, entry in data.items()
                    }
            except Exception:
                self.baseline = {}
    
    def _save_baseline(self) -> None:
        """Save baseline to file."""
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        with open(self.baseline_file, "w") as f:
            json.dump(
                {path: asdict(entry) for path, entry in self.baseline.items()},
                f,
                indent=2
            )
    
    def _compute_hash(self, filepath: str) -> Optional[str]:
        """Compute SHA256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None
    
    def _get_file_info(self, filepath: str) -> Optional[FileEntry]:
        """Get file information including hash."""
        try:
            stat = os.stat(filepath)
            file_hash = self._compute_hash(filepath)
            if not file_hash:
                return None
            
            return FileEntry(
                path=filepath,
                hash=file_hash,
                size=stat.st_size,
                modified=stat.st_mtime,
                permissions=oct(stat.st_mode)[-3:]
            )
        except Exception:
            return None
    
    def create_baseline(self, paths: List[str], recursive: bool = True) -> int:
        """Create a baseline for specified paths."""
        count = 0
        
        for base_path in paths:
            if not os.path.exists(base_path):
                continue
            
            if os.path.isfile(base_path):
                entry = self._get_file_info(base_path)
                if entry:
                    self.baseline[base_path] = entry
                    count += 1
            elif recursive:
                for root, dirs, files in os.walk(base_path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        entry = self._get_file_info(filepath)
                        if entry:
                            self.baseline[filepath] = entry
                            count += 1
        
        self._save_baseline()
        return count
    
    def check_integrity(self, paths: Optional[List[str]] = None) -> List[IntegrityAlert]:
        """Check file integrity against baseline."""
        alerts = []
        check_paths = paths or list(self.baseline.keys())
        current_time = datetime.now().isoformat()
        
        # Check for modifications and deletions
        for path in check_paths:
            if path not in self.baseline:
                continue
            
            if not os.path.exists(path):
                alerts.append(IntegrityAlert(
                    type="removed",
                    path=path,
                    old_value=self.baseline[path].hash,
                    timestamp=current_time
                ))
                continue
            
            current = self._get_file_info(path)
            if not current:
                continue
            
            baseline = self.baseline[path]
            
            # Check hash
            if current.hash != baseline.hash:
                alerts.append(IntegrityAlert(
                    type="modified",
                    path=path,
                    old_value=baseline.hash[:16] + "...",
                    new_value=current.hash[:16] + "...",
                    timestamp=current_time
                ))
            
            # Check permissions
            if current.permissions != baseline.permissions:
                alerts.append(IntegrityAlert(
                    type="permissions_changed",
                    path=path,
                    old_value=baseline.permissions,
                    new_value=current.permissions,
                    timestamp=current_time
                ))
        
        # Check for new files
        for path in self.baseline:
            if os.path.dirname(path):
                continue
        
        return alerts
    
    def monitor(self, paths: List[str], interval: int = 60, max_iterations: Optional[int] = None) -> None:
        """Continuously monitor files for changes."""
        iteration = 0
        
        print(f"\n🔒 Starting FIM monitoring...")
        print(f"   Monitoring {len(paths)} paths")
        print(f"   Interval: {interval}s")
        print(f"   Press Ctrl+C to stop\n")
        
        try:
            while True:
                alerts = self.check_integrity(paths)
                
                if alerts:
                    print(f"\n⚠️  [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {len(alerts)} changes detected:")
                    for alert in alerts:
                        emoji = "➕" if alert.type == "added" else "❌" if alert.type == "removed" else "📝"
                        print(f"   {emoji} {alert.type}: {alert.path}")
                
                iteration += 1
                if max_iterations and iteration >= max_iterations:
                    break
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n\n🛑 Monitoring stopped")
    
    def export_baseline(self, output_file: str) -> None:
        """Export baseline to file."""
        with open(output_file, "w") as f:
            json.dump(
                {path: asdict(entry) for path, entry in self.baseline.items()},
                f,
                indent=2
            )
        print(f"✅ Baseline exported to {output_file}")
    
    def import_baseline(self, input_file: str) -> None:
        """Import baseline from file."""
        with open(input_file, "r") as f:
            data = json.load(f)
            self.baseline = {
                path: FileEntry(**entry) 
                for path, entry in data.items()
            }
        self._save_baseline()
        print(f"✅ Baseline imported from {input_file}")


# CLI functions
def fim_create_baseline(paths: List[str], recursive: bool = True) -> None:
    """Create a new integrity baseline."""
    monitor = FileIntegrityMonitor()
    count = monitor.create_baseline(paths, recursive)
    print(f"\n✅ Baseline created with {count} files")


def fim_check(paths: Optional[List[str]] = None) -> None:
    """Check file integrity."""
    monitor = FileIntegrityMonitor()
    alerts = monitor.check_integrity(paths)
    
    if not alerts:
        print("\n✅ No changes detected - integrity verified")
        return
    
    print(f"\n⚠️  Found {len(alerts)} changes:\n")
    for alert in alerts:
        emoji = "➕" if alert.type == "added" else "❌" if alert.type == "removed" else "📝" if alert.type == "modified" else "🔐"
        print(f"   {emoji} {alert.type}: {alert.path}")
        if alert.old_value and alert.new_value:
            print(f"      {alert.old_value} → {alert.new_value}")


def fim_monitor(paths: List[str], interval: int = 60) -> None:
    """Monitor files continuously."""
    monitor = FileIntegrityMonitor()
    monitor.monitor(paths, interval)


def fim_list_baseline() -> None:
    """List baseline files."""
    monitor = FileIntegrityMonitor()
    
    if not monitor.baseline:
        print("\n📭 No baseline found. Run 'cybercli fim create-baseline' first.")
        return
    
    print(f"\n📋 Baseline contains {len(monitor.baseline)} files:\n")
    for path, entry in sorted(monitor.baseline.items()):
        print(f"   {path}")
        print(f"      Hash: {entry.hash[:32]}...")
        print(f"      Size: {entry.size} bytes, Perms: {entry.permissions}")
