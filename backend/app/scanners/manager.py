import os
from typing import List, Dict, Any, Tuple
from app.scanners.builtin_sast import builtin_sast_engine
from app.scanners.semgrep_runner import semgrep_runner
from app.scanners.trivy_runner import trivy_runner

class ScannerManager:
    """
    Unified manager orchestrating Semgrep, Trivy, and VulnPilot Builtin SAST Engine.
    """

    def scan_file_or_directory(self, target_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        all_vulns: List[Dict[str, Any]] = []
        files_scanned = 0

        if os.path.isfile(target_path):
            files_scanned = 1
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                code_content = f.read()
            rel_name = os.path.basename(target_path)
            builtin_results = builtin_sast_engine.scan_code(code_content, rel_name)
            all_vulns.extend(builtin_results)
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    if file.startswith(".") or file.endswith((".pyc", ".png", ".jpg", ".zip", ".exe")):
                        continue
                    files_scanned += 1
                    file_full = os.path.join(root, file)
                    rel_path = os.path.relpath(file_full, target_path)
                    try:
                        with open(file_full, "r", encoding="utf-8", errors="ignore") as f:
                            code = f.read()
                        res = builtin_sast_engine.scan_code(code, rel_path)
                        all_vulns.extend(res)
                    except Exception:
                        pass

        # Also attempt Semgrep and Trivy CLI if installed
        if semgrep_runner.is_available():
            sg_results = semgrep_runner.scan_path(target_path)
            all_vulns.extend(sg_results)

        if trivy_runner.is_available():
            tr_results = trivy_runner.scan_path(target_path)
            all_vulns.extend(tr_results)

        # Deduplicate results by line number and cwe_id
        deduped = self._deduplicate_vulnerabilities(all_vulns)
        metrics = self.calculate_metrics(deduped, max(files_scanned, 1))

        return deduped, metrics

    def scan_snippet(self, code_text: str, language: str = "python") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        filename = f"snippet.{'py' if 'py' in language else 'js'}"
        vulns = builtin_sast_engine.scan_code(code_text, filename)
        metrics = self.calculate_metrics(vulns, scanned_files_count=1)
        return vulns, metrics

    def _deduplicate_vulnerabilities(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for v in vulns:
            key = (v.get("file_path"), v.get("line_number"), v.get("cwe_id"))
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    def calculate_metrics(self, vulns: List[Dict[str, Any]], scanned_files_count: int) -> Dict[str, Any]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulns:
            sev = v.get("severity", "Low")
            counts[sev] = counts.get(sev, 0) + 1

        total = len(vulns)
        # Deduct score: Critical = -25, High = -15, Medium = -8, Low = -3
        penalty = (counts["Critical"] * 25) + (counts["High"] * 15) + (counts["Medium"] * 8) + (counts["Low"] * 3)
        score = max(0.0, float(100 - penalty))

        return {
            "total_vulnerabilities": total,
            "critical_count": counts["Critical"],
            "high_count": counts["High"],
            "medium_count": counts["Medium"],
            "low_count": counts["Low"],
            "security_score": score,
            "scanned_files_count": scanned_files_count
        }

scanner_manager = ScannerManager()
