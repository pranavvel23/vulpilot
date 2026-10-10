import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.scanners.builtin_sast import builtin_sast_engine
from app.scanners.manager import scanner_manager

client = TestClient(app)

class TestSQLInjectionScanner(unittest.TestCase):

    def setUp(self):
        self.vulnerable_code = (
            "import sqlite3\n\n"
            "user_input = input('Enter username: ')\n"
            "conn = sqlite3.connect('users.db')\n"
            "query = \"SELECT * FROM users WHERE username = '\" + user_input + \"'\"\n"
            "conn.execute(query)\n"
        )
        
        self.safe_code = (
            "import sqlite3\n\n"
            "user_input = input('Enter username: ')\n"
            "conn = sqlite3.connect('users.db')\n"
            "query = \"SELECT * FROM users WHERE username = ?\"\n"
            "conn.execute(query, (user_input,))\n"
        )

    def test_builtin_sast_detects_vulnerable_sqli(self):
        results = builtin_sast_engine.scan_code(self.vulnerable_code, "snippet.py")
        self.assertTrue(len(results) > 0, "Expected SAST scanner to detect SQL injection in vulnerable snippet")
        sqli_findings = [r for r in results if r["cwe_id"] == "CWE-89"]
        self.assertTrue(len(sqli_findings) > 0, "Expected CWE-89 SQL Injection finding")
        self.assertEqual(sqli_findings[0]["severity"], "Critical")

    def test_builtin_sast_ignores_safe_parameterized_query(self):
        results = builtin_sast_engine.scan_code(self.safe_code, "snippet.py")
        sqli_findings = [r for r in results if r["cwe_id"] == "CWE-89"]
        self.assertEqual(len(sqli_findings), 0, "Safe parameterized query must not trigger SQL Injection false positive")

    def test_scanner_manager_metrics(self):
        vulns, metrics = scanner_manager.scan_snippet(self.vulnerable_code, "python")
        self.assertTrue(metrics["total_vulnerabilities"] > 0)
        self.assertLess(metrics["security_score"], 100.0)

        safe_vulns, safe_metrics = scanner_manager.scan_snippet(self.safe_code, "python")
        self.assertEqual(safe_metrics["total_vulnerabilities"], 0)
        self.assertEqual(safe_metrics["security_score"], 100.0)

    def test_api_scan_snippet_vulnerable_endpoint(self):
        response = client.post("/api/scan/snippet", json={
            "project_name": "SQLi Test Audit",
            "language": "python",
            "code": self.vulnerable_code
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "completed")
        self.assertGreater(data["total_vulnerabilities"], 0)
        self.assertLess(data["security_score"], 100.0)
        
        sqli_vulns = [v for v in data["vulnerabilities"] if v["cwe_id"] == "CWE-89"]
        self.assertTrue(len(sqli_vulns) > 0, "API response must contain CWE-89 vulnerability item")

    def test_api_scan_snippet_safe_endpoint(self):
        response = client.post("/api/scan/snippet", json={
            "project_name": "Safe Parameterized Query Test",
            "language": "python",
            "code": self.safe_code
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["total_vulnerabilities"], 0)
        self.assertEqual(data["security_score"], 100.0)
        self.assertEqual(len(data["vulnerabilities"]), 0)

    def test_api_scan_upload_endpoint(self):
        files = {
            "file": ("vulnerable.py", self.vulnerable_code.encode("utf-8"), "text/x-python")
        }
        data = {
            "project_name": "Upload SQLi Audit"
        }
        response = client.post("/api/scan/upload", files=files, data=data)
        self.assertEqual(response.status_code, 200)
        res_json = response.json()
        self.assertEqual(res_json["status"], "completed")
        self.assertEqual(res_json["project_name"], "Upload SQLi Audit")
        self.assertGreater(res_json["total_vulnerabilities"], 0)
        sqli_vulns = [v for v in res_json["vulnerabilities"] if v["cwe_id"] == "CWE-89"]
        self.assertTrue(len(sqli_vulns) > 0, "Uploaded file must trigger CWE-89 SQL Injection finding")

    def test_cors_preflight_and_headers(self):
        # Check OPTIONS preflight request from deployed frontend origin
        headers = {
            "Origin": "https://vulpilot-frontend.onrender.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key, Content-Type"
        }
        response = client.options("/api/scan/upload", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), "https://vulpilot-frontend.onrender.com")

        # Check normal POST request headers from deployed frontend origin
        files = {
            "file": ("test.py", self.safe_code.encode("utf-8"), "text/x-python")
        }
        post_headers = {
            "Origin": "https://vulpilot-frontend.onrender.com"
        }
        post_response = client.post("/api/scan/upload", files=files, data={"project_name": "CORS Test"}, headers=post_headers)
        self.assertEqual(post_response.status_code, 200)
        self.assertEqual(post_response.headers.get("access-control-allow-origin"), "https://vulpilot-frontend.onrender.com")

if __name__ == "__main__":
    unittest.main()
