import hashlib
from fastapi import APIRouter, File, HTTPException, UploadFile, status, BackgroundTasks, Depends
import shutil
import uuid
import os
from pathlib import Path
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import AnalysisReport
import threading

router = APIRouter()

UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"

# Global lock to prevent overlapping DB writes that cause RocksDB/Postgres contention
db_commit_lock = threading.Lock()

def process_apk_background(report_id: str, apk_path: str, apk_hash: str):
    from app.database.session import SessionLocal
    from app.core.pipeline import AnalysisPipeline
    
    db = SessionLocal()
    try:
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if not report:
            return
            
        with open(apk_path, "rb") as f:
            file_bytes = f.read()
            
        pipeline = AnalysisPipeline()
        result = pipeline.execute(file_bytes, apk_hash, apk_path)
        
        import logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        
        dynamic_analysis = result.get("dynamic_analysis", {})
        dynamic_iocs = dynamic_analysis.get("iocs", {})
        behavior_risk = dynamic_analysis.get("behavior_risk", {})
        evidence = behavior_risk.get("evidence", [])
        
        logger.info(f"--- DYNAMIC ANALYSIS LOGGING ---")
        logger.info(f"Has dynamic_analysis: {bool(dynamic_analysis)}")
        logger.info(f"dynamic_iocs count: {len(dynamic_iocs.get('urls', [])) + len(dynamic_iocs.get('ips', [])) + len(dynamic_iocs.get('domains', []))}")
        logger.info(f"behavior_risk keys: {list(behavior_risk.keys())}")
        logger.info(f"evidence count: {len(evidence)}")
        logger.info(f"dynamic_iocs contents: {dynamic_iocs}")
        logger.info(f"evidence contents: {evidence}")
        logger.info(f"--------------------------------")
        
        report.status = "COMPLETED"
        report.package_name = result.get("package_name")
        report.risk_score = result.get("final_verdict", {}).get("final_risk_score", 0)
        report.verdict = result.get("final_verdict", {}).get("verdict", "UNKNOWN")
        report.confidence = result.get("final_verdict", {}).get("confidence", 0.0)
        report.raw_report = result
        
        # Save IOCs
        static_iocs = ((result or {}).get("static_analysis") or {}).get("extracted_iocs") or {}
        from app.database.models import ExtractedIOC, DynamicFinding
        
        static_ioc_count = 0
        if isinstance(static_iocs, dict):
            for t, values in static_iocs.items():
                if isinstance(values, list):
                    for v in values:
                        db.add(ExtractedIOC(report_id=report.id, ioc_type=t, value=str(v)))
                        static_ioc_count += 1
        logger.info(f"Inserted {static_ioc_count} static IOCs. Sample payload: {static_iocs}")
                
        dynamic_ioc_count = 0
        if isinstance(dynamic_iocs, dict):
            for t, values in dynamic_iocs.items():
                if t in ["urls", "ips", "domains"] and isinstance(values, list):
                    for v in values:
                        db.add(ExtractedIOC(report_id=report.id, ioc_type=t, value=str(v)))
                        dynamic_ioc_count += 1
        logger.info(f"Inserted {dynamic_ioc_count} dynamic runtime IOCs. Sample payload: {dynamic_iocs}")
                    
        # Save Dynamic Findings
        dynamic_finding_count = 0
        if isinstance(evidence, list):
            for detail in evidence:
                db.add(DynamicFinding(report_id=report.id, log_type="behavior", detail=str(detail)))
                dynamic_finding_count += 1
            
        forensics_timeline = ((behavior_risk or {}).get("forensics") or {}).get("timeline", [])
        if isinstance(forensics_timeline, list):
            for entry in forensics_timeline:
                if isinstance(entry, dict):
                    event_type = entry.get("event_type", "unknown")
                    summary = entry.get("summary", "")
                    if summary:
                        db.add(DynamicFinding(report_id=report.id, log_type=event_type, detail=str(summary)))
                        dynamic_finding_count += 1
                        
        logger.info(f"Inserted {dynamic_finding_count} dynamic findings. Sample evidence payload: {evidence}")
                
        logger.info("Waiting for DB lock to commit results...")
        with db_commit_lock:
            logger.info("Acquired DB lock, committing transaction...")
            db.commit()
            logger.info("Transaction committed successfully.")
        
        # Post-commit verification
        actual_iocs = db.query(ExtractedIOC).filter(ExtractedIOC.report_id == report.id).count()
        actual_findings = db.query(DynamicFinding).filter(DynamicFinding.report_id == report.id).count()
        logger.info(f"Successfully committed all database insertions. Post-commit verification: ExtractedIOCs={actual_iocs}, DynamicFindings={actual_findings}.")
        
    except Exception as e:
        import traceback
        logger.error(f"Data insertion failed or pipeline crashed: {str(e)}")
        logger.error(traceback.format_exc())
        db.rollback() # Ensure rollback on failure before setting failure status
        report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
        if report:
            report.status = "FAILED"
            report.error_message = str(e)
            logger.info("Waiting for DB lock to commit failure status...")
            with db_commit_lock:
                db.commit()
    finally:
        db.close() # Properly manage session lifecycle
        # Clean up temporary APK file to prevent disk exhaustion
        if os.path.exists(apk_path):
            try:
                os.remove(apk_path)
                logger.info(f"Cleaned up temporary artifact: {apk_path}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up artifact {apk_path}: {cleanup_error}")


@router.post("/upload-apk")
async def upload_apk(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .apk files are allowed",
        )

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    secure_filename = f"{uuid.uuid4()}.apk"
    apk_path = UPLOADS_DIR / secure_filename
    
    with open(apk_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Compute hash synchronously so we can store it in DB immediately
    with open(apk_path, "rb") as buffer:
        apk_hash = hashlib.sha256(buffer.read()).hexdigest()

    report = AnalysisReport(filename=file.filename, apk_hash=apk_hash, status="PENDING")
    db.add(report)
    with db_commit_lock:
        db.commit()
    db.refresh(report)

    # Start the heavy pipeline in the background
    background_tasks.add_task(process_apk_background, report.id, str(apk_path), apk_hash)

    return {
        "message": "APK uploaded successfully. Analysis started.",
        "filename": file.filename,
        "report_id": report.id,
        "saved_path": str(apk_path)
    }
