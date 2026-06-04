from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import AnalysisReport

router = APIRouter()

@router.get("/reports")
def get_reports(db: Session = Depends(get_db)):
    reports = db.query(AnalysisReport).order_by(AnalysisReport.created_at.desc()).all()
    return [{
        "id": r.id,
        "filename": r.filename,
        "package_name": r.package_name,
        "apk_hash": r.apk_hash,
        "risk_score": r.risk_score,
        "verdict": r.verdict,
        "status": r.status,
        "created_at": r.created_at
    } for r in reports]

@router.get("/analyze-apk/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
        
    if report.status == "PENDING":
        # Keep returning pending structure
        return {
            "status": "PENDING",
            "message": "Analysis is currently running..."
        }
    
    if report.status == "FAILED":
        return {
            "status": "failed",
            "error_message": report.error_message or "Unknown pipeline failure"
        }
        
    # Inject report ID into the root of the raw report
    if report.raw_report:
        report.raw_report["id"] = report.id

    return report.raw_report
