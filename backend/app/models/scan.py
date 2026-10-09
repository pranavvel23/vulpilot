import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, default="Untitled Scan")
    scan_type = Column(String, default="full_source") # code_snippet, zip_archive, multi_file
    status = Column(String, default="completed") # pending, scanning, completed, failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    security_score = Column(Float, default=100.0)
    scanned_files_count = Column(Integer, default=1)
    
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, default=1)
    end_line_number = Column(Integer, default=1)
    
    severity = Column(String, nullable=False) # Critical, High, Medium, Low
    title = Column(String, nullable=False)
    cwe_id = Column(String, default="CWE-79")
    owasp_category = Column(String, default="A03:2021-Injection")
    
    description = Column(Text, nullable=False)
    vulnerable_code = Column(Text, nullable=False)
    secure_code_fix = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    
    tool_name = Column(String, default="VulnPilot SAST Engine") # Semgrep, Trivy, VulnPilot SAST Engine
    status = Column(String, default="OPEN") # OPEN, RESOLVED, VERIFIED
    
    scan = relationship("Scan", back_populates="vulnerabilities")
    fix_histories = relationship("FixHistory", back_populates="vulnerability", cascade="all, delete-orphan")

class FixHistory(Base):
    __tablename__ = "fix_histories"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    before_code = Column(Text, nullable=False)
    after_code = Column(Text, nullable=False)
    verification_status = Column(String, default="PASSED") # PASSED, FAILED_REMAINING_VULNS
    
    vulnerability = relationship("Vulnerability", back_populates="fix_histories")
