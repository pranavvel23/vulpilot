from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class VulnerabilityBase(BaseModel):
    file_path: str
    line_number: int = 1
    end_line_number: int = 1
    severity: str
    title: str
    cwe_id: str
    owasp_category: str
    description: str
    vulnerable_code: str
    secure_code_fix: Optional[str] = None
    ai_explanation: Optional[str] = None
    tool_name: str = "VulnPilot SAST Engine"
    status: str = "OPEN"

class VulnerabilityCreate(VulnerabilityBase):
    pass

class VulnerabilityResponse(VulnerabilityBase):
    id: int
    scan_id: int

    class Config:
        from_attributes = True

class ScanCreateSnippet(BaseModel):
    project_name: str = "Code Snippet Scan"
    language: str = "python"
    code: str

class RescanRequest(BaseModel):
    vulnerability_id: int
    updated_code: str

class ScanResponse(BaseModel):
    id: int
    project_name: str
    scan_type: str
    status: str
    created_at: datetime
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    security_score: float
    scanned_files_count: int
    vulnerabilities: List[VulnerabilityResponse] = []

    class Config:
        from_attributes = True

class OWASPItemResponse(BaseModel):
    owasp_id: str
    cwe_id: str
    title: str
    description: str
    impact: str
    mitigation: str
    code_example_vulnerable: str
    code_example_secure: str
    similarity_score: Optional[float] = None

class RAGSearchRequest(BaseModel):
    query: str
    top_k: int = 5

class ReportRequest(BaseModel):
    scan_id: int
    format: str = "pdf" # pdf, markdown, json, html
