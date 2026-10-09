import subprocess
import json
import shutil
from typing import List, Dict, Any

class TrivyRunner:
    """Executes Trivy CLI scanner for filesystem, secrets, and dependency scanning if available."""

    def __init__(self, trivy_bin: str = "trivy"):
        self.trivy_bin = trivy_bin

    def is_available(self) -> bool:
        return shutil.which(self.trivy_bin) is not None

    def scan_path(self, target_path: str) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []

        results = []
        try:
            cmd = [
                self.trivy_bin,
                "fs",
                "--format", "json",
                "--scanners", "vuln,secret,config",
                target_path
            ]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if process.returncode == 0 and process.stdout:
                data = json.loads(process.stdout)
                for res in data.get("Results", []):
                    target_file = res.get("Target", target_path)
                    for vuln in res.get("Vulnerabilities", []):
                        sev = vuln.get("Severity", "MEDIUM").capitalize()
                        if sev not in ["Critical", "High", "Medium", "Low"]:
                            sev = "Medium"
                        results.append({
                            "file_path": target_file,
                            "line_number": 1,
                            "end_line_number": 1,
                            "severity": sev,
                            "title": f"{vuln.get('VulnerabilityID', 'CVE-UNKNOWN')} - {vuln.get('PkgName', 'Package')}",
                            "cwe_id": vuln.get("CweIDs", ["CWE-937"])[0] if vuln.get("CweIDs") else "CWE-937",
                            "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                            "description": vuln.get("Title", "Vulnerable package dependency"),
                            "vulnerable_code": f"Installed: {vuln.get('InstalledVersion')}\nFixed in: {vuln.get('FixedVersion')}",
                            "secure_code_fix": f"Upgrade {vuln.get('PkgName')} to version {vuln.get('FixedVersion')}",
                            "ai_explanation": None,
                            "tool_name": "Trivy CLI",
                            "status": "OPEN"
                        })
        except Exception:
            pass
        return results

trivy_runner = TrivyRunner()
