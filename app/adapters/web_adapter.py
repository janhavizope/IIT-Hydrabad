import os
import logging
import traceback
import threading
from app.database.session import SessionLocal
from app.database.models import AnalysisReport, ExtractedIOC, DynamicFinding
from app.core.engine import CoreAnalysisEngine
from app.core.models import AnalysisInput
from app.core.orchestrator import AnalysisOrchestrator

logger = logging.getLogger(__name__)

# Global lock to prevent overlapping DB writes that cause RocksDB/Postgres contention
db_commit_lock = threading.Lock()

class WebAdapter:
    @classmethod
    def analyze_file(cls, apk_path: str, apk_hash: str, report_id: str) -> dict:
        """Web Upload Adapter (Asynchronous background task). Handles DB writes."""
        logger.info(f"[WebAdapter] Starting analysis for file: {apk_path}")
        
        analysis_input = AnalysisInput(
            apk_path=apk_path,
            apk_hash=apk_hash,
            source="web_upload",
            trust_level="MEDIUM",
            execution_context="web_dashboard"
        )
        
        # Core execution via Orchestrator (Single Source of Truth)
        decision = AnalysisOrchestrator.analyze_apk(CoreAnalysisEngine._execute_internal, analysis_input)
        
        core_result = decision.model_dump()
        raw_report = core_result.pop("raw_report", None)
        
        # DB Side Effects strictly isolated to the Web Adapter
        if report_id and raw_report:
            db = SessionLocal()
            try:
                report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
                if report:
                    report.status = "COMPLETED"
                    report.package_name = raw_report.get("package_name")
                    report.risk_score = core_result["risk_score"]
                    report.verdict = core_result["verdict"]
                    report.confidence = core_result["confidence"]
                    report.raw_report = raw_report

                    # Save Static IOCs
                    static_iocs = (raw_report.get("static_analysis") or {}).get("extracted_iocs") or {}
                    if isinstance(static_iocs, dict):
                        for t, values in static_iocs.items():
                            if isinstance(values, list):
                                for v in values:
                                    db.add(ExtractedIOC(report_id=report.id, ioc_type=t, value=str(v)))

                    # Save Dynamic IOCs
                    dynamic_analysis = raw_report.get("dynamic_analysis", {})
                    dynamic_iocs = dynamic_analysis.get("iocs", {})
                    if isinstance(dynamic_iocs, dict):
                        for t, values in dynamic_iocs.items():
                            if t in ["urls", "ips", "domains"] and isinstance(values, list):
                                for v in values:
                                    db.add(ExtractedIOC(report_id=report.id, ioc_type=t, value=str(v)))

                    # Save Dynamic Findings
                    behavior_risk = dynamic_analysis.get("behavior_risk", {})
                    evidence = behavior_risk.get("evidence", [])
                    if isinstance(evidence, list):
                        for detail in evidence:
                            db.add(DynamicFinding(report_id=report.id, log_type="behavior", detail=str(detail)))

                    forensics_timeline = (behavior_risk.get("forensics") or {}).get("timeline", [])
                    if isinstance(forensics_timeline, list):
                        for entry in forensics_timeline:
                            if isinstance(entry, dict):
                                event_type = entry.get("event_type", "unknown")
                                entry_summary = entry.get("summary", "")
                                if entry_summary:
                                    db.add(DynamicFinding(report_id=report.id, log_type=event_type, detail=str(entry_summary)))

                    with db_commit_lock:
                        db.commit()
            except Exception as e:
                logger.error(f"[WebAdapter] DB Update error: {e}")
                logger.error(traceback.format_exc())
                db.rollback()
                report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
                if report:
                    report.status = "FAILED"
                    report.error_message = str(e)
                    with db_commit_lock:
                        db.commit()
            finally:
                db.close()

        try:
            if os.path.exists(apk_path):
                os.remove(apk_path)
        except Exception as ex:
            logger.error(f"[WebAdapter] Cleanup error: {ex}")
            
        return core_result
