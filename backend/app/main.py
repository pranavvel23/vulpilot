import os
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.models.scan import Scan, Vulnerability, FixHistory
from app.schemas.scan import (
    ScanResponse, VulnerabilityResponse, ScanCreateSnippet,
    RescanRequest, RAGSearchRequest, OWASPItemResponse, ReportRequest
)
from app.ai.langgraph_workflow import langgraph_pipeline
from app.scanners.builtin_sast import builtin_sast_engine
from app.scanners.semgrep_runner import semgrep_runner
from app.scanners.trivy_runner import trivy_runner
from app.rag.vector_store import rag_vector_store
from app.reports.generator import report_generator
from app.utils.file_handler import save_uploaded_file
from app.utils.diff_utils import generate_unified_diff

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="AI-Powered Vulnerability Analysis and Remediation Assistant API"
)

# Allowed Origins for CORS configuration
allowed_origins = [
    "https://vulpilot-frontend.onrender.com",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    "https://vulpilot.onrender.com",
]

# Merge any additional origins from environment variable ALLOWED_ORIGINS
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    for origin in env_origins.split(","):
        cleaned = origin.strip()
        if cleaned and cleaned not in allowed_origins:
            allowed_origins.append(cleaned)

# Enable CORS for React Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "scanners": {
            "builtin_sast": True,
            "semgrep_cli": semgrep_runner.is_available(),
            "trivy_cli": trivy_runner.is_available()
        },
        "default_llm": settings.DEFAULT_LLM_PROVIDER,
        "has_gemini_key": bool(settings.GEMINI_API_KEY),
        "has_openai_key": bool(settings.OPENAI_API_KEY)
    }

@app.post("/api/scan/snippet", response_model=ScanResponse)
def scan_snippet(
    payload: ScanCreateSnippet,
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
    provider: Optional[str] = Header(None, alias="X-LLM-Provider"),
    db: Session = Depends(get_db)
):
    """Scan raw source code snippet using LangGraph workflow."""
    init_state = {
        "target_path_or_code": payload.code,
        "is_snippet": True,
        "language": payload.language,
        "project_name": payload.project_name or "Snippet Audit",
        "api_key": api_key or settings.GEMINI_API_KEY,
        "provider": provider or settings.DEFAULT_LLM_PROVIDER,
        "raw_vulnerabilities": [],
        "enriched_vulnerabilities": [],
        "metrics": {},
        "current_step": "Starting",
        "workflow_logs": []
    }

    final_state = langgraph_pipeline.invoke(init_state)
    metrics = final_state["metrics"]
    vulns_data = final_state["enriched_vulnerabilities"]

    # Save to SQLite Database
    scan_db = Scan(
        project_name=payload.project_name,
        scan_type="code_snippet",
        status="completed",
        total_vulnerabilities=metrics.get("total_vulnerabilities", 0),
        critical_count=metrics.get("critical_count", 0),
        high_count=metrics.get("high_count", 0),
        medium_count=metrics.get("medium_count", 0),
        low_count=metrics.get("low_count", 0),
        security_score=metrics.get("security_score", 100.0),
        scanned_files_count=1
    )
    db.add(scan_db)
    db.commit()
    db.refresh(scan_db)

    for v in vulns_data:
        v_db = Vulnerability(
            scan_id=scan_db.id,
            file_path=v.get("file_path", "snippet.py"),
            line_number=v.get("line_number", 1),
            end_line_number=v.get("end_line_number", 1),
            severity=v.get("severity", "Medium"),
            title=v.get("title", "Security Flaw"),
            cwe_id=v.get("cwe_id", "CWE-79"),
            owasp_category=v.get("owasp_category", "A03:2021-Injection"),
            description=v.get("description", ""),
            vulnerable_code=v.get("vulnerable_code", ""),
            secure_code_fix=v.get("secure_code_fix", ""),
            ai_explanation=v.get("ai_explanation", ""),
            tool_name=v.get("tool_name", "VulnPilot SAST Engine"),
            status="OPEN"
        )
        db.add(v_db)
    
    db.commit()
    db.refresh(scan_db)
    return scan_db

@app.post("/api/scan/upload", response_model=ScanResponse)
def scan_upload(
    file: UploadFile = File(...),
    project_name: Optional[str] = Form("Uploaded Project"),
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
    provider: Optional[str] = Header(None, alias="X-LLM-Provider"),
    db: Session = Depends(get_db)
):
    """Upload single file or ZIP project archive for security scan."""
    saved_path = save_uploaded_file(file)

    init_state = {
        "target_path_or_code": saved_path,
        "is_snippet": False,
        "language": "multi",
        "project_name": project_name or file.filename,
        "api_key": api_key or settings.GEMINI_API_KEY,
        "provider": provider or settings.DEFAULT_LLM_PROVIDER,
        "raw_vulnerabilities": [],
        "enriched_vulnerabilities": [],
        "metrics": {},
        "current_step": "Starting",
        "workflow_logs": []
    }

    final_state = langgraph_pipeline.invoke(init_state)
    metrics = final_state["metrics"]
    vulns_data = final_state["enriched_vulnerabilities"]

    scan_db = Scan(
        project_name=project_name or file.filename,
        scan_type="archive_upload" if file.filename.endswith(".zip") else "single_file",
        status="completed",
        total_vulnerabilities=metrics.get("total_vulnerabilities", 0),
        critical_count=metrics.get("critical_count", 0),
        high_count=metrics.get("high_count", 0),
        medium_count=metrics.get("medium_count", 0),
        low_count=metrics.get("low_count", 0),
        security_score=metrics.get("security_score", 100.0),
        scanned_files_count=metrics.get("scanned_files_count", 1)
    )
    db.add(scan_db)
    db.commit()
    db.refresh(scan_db)

    for v in vulns_data:
        v_db = Vulnerability(
            scan_id=scan_db.id,
            file_path=v.get("file_path", file.filename),
            line_number=v.get("line_number", 1),
            end_line_number=v.get("end_line_number", 1),
            severity=v.get("severity", "Medium"),
            title=v.get("title", "Security Finding"),
            cwe_id=v.get("cwe_id", "CWE-79"),
            owasp_category=v.get("owasp_category", "A03:2021-Injection"),
            description=v.get("description", ""),
            vulnerable_code=v.get("vulnerable_code", ""),
            secure_code_fix=v.get("secure_code_fix", ""),
            ai_explanation=v.get("ai_explanation", ""),
            tool_name=v.get("tool_name", "VulnPilot SAST Engine"),
            status="OPEN"
        )
        db.add(v_db)

    db.commit()
    db.refresh(scan_db)
    return scan_db

@app.get("/api/scans", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    """Retrieve all past scan records."""
    return db.query(Scan).order_by(Scan.created_at.desc()).all()

@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve a single scan details by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.post("/api/rescan")
def rescan_verification(payload: RescanRequest, db: Session = Depends(get_db)):
    """Rescan code to verify whether vulnerabilities have been resolved."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == payload.vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability record not found")

    ext = ".py" if vuln.file_path.endswith(".py") else ".js"
    rescan_vulns = builtin_sast_engine.scan_code(payload.updated_code, f"verify_{vuln.file_path}")

    # Check if the specific CWE vulnerability is still triggered
    is_still_vulnerable = any(v.get("cwe_id") == vuln.cwe_id for v in rescan_vulns)

    if not is_still_vulnerable:
        vuln.status = "RESOLVED"
        db.commit()
        verification_status = "PASSED"
        message = f"Verification PASSED! {vuln.cwe_id} vulnerability is successfully resolved."
    else:
        verification_status = "FAILED"
        message = f"Verification FAILED. {vuln.cwe_id} pattern was still detected in the updated code."

    # Record Fix History
    history = FixHistory(
        vulnerability_id=vuln.id,
        scan_id=vuln.scan_id,
        before_code=vuln.vulnerable_code,
        after_code=payload.updated_code,
        verification_status=verification_status
    )
    db.add(history)
    db.commit()

    diff_lines = generate_unified_diff(vuln.vulnerable_code, payload.updated_code)

    return {
        "vulnerability_id": vuln.id,
        "status": vuln.status,
        "verification_status": verification_status,
        "message": message,
        "remaining_vulnerabilities_count": len(rescan_vulns),
        "code_diff": diff_lines
    }

@app.get("/api/diff")
def get_diff(vulnerable_code: str, secure_code: str):
    """Generate line-by-line code diff."""
    return {"diff": generate_unified_diff(vulnerable_code, secure_code)}

@app.get("/api/rag/search", response_model=List[OWASPItemResponse])
def search_rag_kb(query: str = Query(..., min_length=2), top_k: int = 5):
    """Search OWASP & CWE RAG Knowledge base."""
    return rag_vector_store.search(query, top_k=top_k)

@app.post("/api/report")
def generate_report(payload: ReportRequest, db: Session = Depends(get_db)):
    """Generate downloadable security report (PDF, Markdown, HTML, JSON)."""
    scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_dict = {
        "id": scan.id,
        "project_name": scan.project_name,
        "created_at": str(scan.created_at),
        "security_score": scan.security_score,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "vulnerabilities": [
            {
                "title": v.title,
                "severity": v.severity,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "cwe_id": v.cwe_id,
                "owasp_category": v.owasp_category,
                "description": v.description,
                "vulnerable_code": v.vulnerable_code,
                "secure_code_fix": v.secure_code_fix,
                "ai_explanation": v.ai_explanation
            }
            for v in scan.vulnerabilities
        ]
    }

    fmt = payload.format.lower()
    file_basename = f"VulnPilot_Report_Scan_{scan.id}.{fmt}"
    out_file = os.path.join(settings.REPORTS_DIR, file_basename)

    if fmt == "pdf":
        report_generator.generate_pdf_report(scan_dict, out_file)
        return FileResponse(out_file, media_type="application/pdf", filename=file_basename)
    elif fmt == "markdown" or fmt == "md":
        content = report_generator.generate_markdown_report(scan_dict)
        return Response(content=content, media_type="text/markdown", headers={"Content-Disposition": f"attachment; filename={file_basename}"})
    elif fmt == "html":
        content = report_generator.generate_html_report(scan_dict)
        return Response(content=content, media_type="text/html", headers={"Content-Disposition": f"attachment; filename={file_basename}"})
    else:
        content = report_generator.generate_json_report(scan_dict)
        return Response(content=content, media_type="application/json", headers={"Content-Disposition": f"attachment; filename={file_basename}"})

@app.get("/api/sample-vulnerable-code")
def get_sample_code():
    """Returns preset vulnerable code samples for interactive testing."""
    return [
        {
            "id": "sqli_py",
            "name": "Python - SQL Injection & Hardcoded Secret",
            "language": "python",
            "code": """import sqlite3
import os

AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLESECRETKEY"
DB_PASSWORD = "SuperSecretPassword123!"

def get_user_profile(username, user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Unsafe dynamic string concatenation in SQL query
    query = f"SELECT id, username, email FROM users WHERE username = '{username}' OR id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def execute_command(cmd):
    # Unsafe OS command execution
    os.system("ping -c 1 " + cmd)
"""
        },
        {
            "id": "xss_cmd_js",
            "name": "Node.js - Command Injection & XSS",
            "language": "javascript",
            "code": """const express = require('express');
const { exec } = require('child_process');
const app = express();

const JWT_SECRET = "super_secret_jwt_token_key_998877";

app.get('/api/ping', (req, res) => {
    let host = req.query.host;
    // Command Injection flaw
    exec('ping -c 1 ' + host, (err, stdout, stderr) => {
        // Reflected XSS flaw
        res.send("<h1>Ping Result for " + host + "</h1><pre>" + stdout + "</pre>");
    });
});
"""
        },
        {
            "id": "php_deser",
            "name": "PHP - Unsafe Unserialize & System Call",
            "language": "php",
            "code": """<?php
$user_input = $_POST['data'];
// Insecure deserialization
$object = unserialize($user_input);

// Command execution
$command = $_GET['cmd'];
system("echo " . $command);
?>"""
        }
    ]
