# app/routes/reports.py

import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import AnalysisReport
from app.services.ai_report_generator import AIReportGenerator

logger = logging.getLogger(__name__)

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
        return {
            "status": "PENDING",
            "message": "Analysis is currently running..."
        }

    if report.status == "FAILED":
        return {
            "status": "failed",
            "error_message": report.error_message or "Unknown pipeline failure"
        }

    if report.raw_report:
        report.raw_report["id"] = report.id

    # Generate AI summary
    ai_summary = None
    try:
        if report.raw_report:
            ai_summary = AIReportGenerator(report.raw_report).generate()
            logger.info(f"AI summary generated for report_id={report_id}")
    except Exception as exc:
        logger.error(f"AI summary failed for report_id={report_id}: {exc}", exc_info=True)
        ai_summary = None

    return {
        **(report.raw_report or {}),
          "ai_summary": str(ai_summary),
    }