import subprocess
import json
import shutil
import os
from typing import List, Dict, Any

class SemgrepRunner:
    """Executes Semgrep CLI scanner if installed on system."""

    def __init__(self, semgrep_bin: str = "semgrep"):
        self.semgrep_bin = semgrep_bin

    def is_available(self) -> bool:
        return shutil.which(self.semgrep_bin) is not None

    def scan_path(self, target_path: str) -> List[Dict[str, Any]]:
        if not self.is_available():
            return []

        results = []
        try:
            cmd = [
                self.semgrep_bin,
                "scan",
                "--config=auto",
                "--json",
                "--quiet",
                target_path
            ]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if process.returncode in [0, 1] and process.stdout:
                data = json.loads(process.stdout)
                for match in data.get("results", []):
                    sev_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
                    extra = match.get("extra", {})
                    metadata = extra.get("metadata", {})
                    cwe = metadata.get("cwe", ["CWE-79"])[0] if isinstance(metadata.get("cwe"), list) else metadata.get("cwe", "CWE-79")
                    owasp = metadata.get("owasp", ["A03:2021-Injection"])[0] if isinstance(metadata.get("owasp"), list) else metadata.get("owasp", "A03:2021-Injection")
                    
                    results.append({
                        "file_path": match.get("path", target_path),
                        "line_number": match.get("start", {}).get("line", 1),
                        "end_line_number": match.get("end", {}).get("line", 1),
                        "severity": sev_map.get(extra.get("severity"), "Medium"),
                        "title": match.get("check_id", "Semgrep Finding"),
                        "cwe_id": str(cwe),
                        "owasp_category": str(owasp),
                        "description": extra.get("message", "Semgrep rule violation"),
                        "vulnerable_code": match.get("extra", {}).get("lines", ""),
                        "secure_code_fix": None,
                        "ai_explanation": None,
                        "tool_name": "Semgrep CLI",
                        "status": "OPEN"
                    })
        except Exception:
            pass
        return results

semgrep_runner = SemgrepRunner()
