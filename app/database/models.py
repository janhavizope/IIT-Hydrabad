from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.database.session import Base

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    package_name = Column(String, nullable=True)
    apk_hash = Column(String, nullable=True)
    risk_score = Column(Integer, default=0)
    verdict = Column(String, default="UNKNOWN")
    confidence = Column(Float, default=0.0)
    status = Column(String, default="PENDING") # PENDING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
    
    # Store the entire raw JSON report for easy nested retrieval
    raw_report = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    extracted_iocs = relationship("ExtractedIOC", back_populates="report", cascade="all, delete-orphan")
    dynamic_findings = relationship("DynamicFinding", back_populates="report", cascade="all, delete-orphan")

class ExtractedIOC(Base):
    __tablename__ = "extracted_iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String, ForeignKey("analysis_reports.id"))
    ioc_type = Column(String, nullable=False) # url, domain, ip, email, apikey
    value = Column(String, nullable=False)

    report = relationship("AnalysisReport", back_populates="extracted_iocs")

class DynamicFinding(Base):
    __tablename__ = "dynamic_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String, ForeignKey("analysis_reports.id"))
    log_type = Column(String, nullable=False) # behavior, network, file
    detail = Column(Text, nullable=False)

    report = relationship("AnalysisReport", back_populates="dynamic_findings")
