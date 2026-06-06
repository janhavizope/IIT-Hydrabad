import asyncio
import sys
import os
project_root = r"C:\Users\janhavi\OneDrive\Documents\Projects\IIT Hyderabad Hackathon\IIT Project"
sys.path.insert(0, project_root)

from app.database.session import SessionLocal
from app.database.models import AnalysisReport
from app.routes.upload import process_apk_background
import uuid

def test_pipeline():
    db = SessionLocal()
    report_id = str(uuid.uuid4())
    apk_path = os.path.join(project_root, "sample_apks", "insecurebankv2.apk")
    
    import hashlib
    with open(apk_path, "rb") as f:
        apk_hash = hashlib.sha256(f.read()).hexdigest()
        
    report = AnalysisReport(id=report_id, filename="insecurebankv2.apk", apk_hash=apk_hash, status="PENDING")
    db.add(report)
    db.commit()
    db.refresh(report)
    
    print(f"Running pipeline for report {report_id}")
    process_apk_background(report.id, apk_path, apk_hash)
    print("Done")

if __name__ == "__main__":
    test_pipeline()
