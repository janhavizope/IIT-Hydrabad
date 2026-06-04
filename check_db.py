import sys
import os

project_root = r"C:\Users\janhavi\OneDrive\Documents\IIT Hyderabad Hackathon\IIT Project"
sys.path.insert(0, project_root)

from app.database.session import SessionLocal
from app.database.models import AnalysisReport, DynamicFinding, ExtractedIOC

def check_db():
    db = SessionLocal()
    reports = db.query(AnalysisReport).order_by(AnalysisReport.created_at.desc()).limit(1).all()
    if not reports:
        print("No reports found.")
        return
        
    latest = reports[0]
    print(f"Latest Report ID: {latest.id}")
    
    findings = db.query(DynamicFinding).filter(DynamicFinding.report_id == latest.id).all()
    print(f"Dynamic Findings Count: {len(findings)}")
    for f in findings:
        print(f" - [{f.log_type}] {f.detail}")
        
    iocs = db.query(ExtractedIOC).filter(ExtractedIOC.report_id == latest.id).all()
    print(f"\nExtracted IOCs Count: {len(iocs)}")
    for ioc in iocs:
        print(f" - [{ioc.ioc_type}] {ioc.value}")

if __name__ == "__main__":
    check_db()
