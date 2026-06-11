import os
import uuid
import hashlib
import json
import logging
import shutil
from pathlib import Path

from app.core.engine import CoreAnalysisEngine
from app.core.models import AnalysisInput
from app.core.utils import get_domain_trust, download_apk, extract_apkm

logger = logging.getLogger(__name__)

UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

class ExtensionAdapter:
    @classmethod
    def analyze_url(cls, apk_url: str) -> dict:
        """Extension URL Adapter (Synchronous fast-path). Bypasses DB."""
        logger.info(f"[ExtensionAdapter] Starting analysis for URL: {apk_url}")
        
        if not apk_url.startswith(("http://", "https://")):
            return {
                "risk_score": 100,
                "confidence": 1.0,
                "verdict": "SUSPICIOUS",
                "decision_trace": [],
                "reasons": ["Invalid URL scheme detected. Only HTTP/HTTPS is allowed."],
                "trust_level": "LOW",
                "failure_type": "INVALID_FORMAT"
            }

        url_hash = hashlib.md5(apk_url.encode("utf-8")).hexdigest()
        cache_path = UPLOADS_DIR / f"{url_hash}_result.json"
        
        if cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    logger.info("[ExtensionAdapter] Using cached analysis result.")
                    return json.load(f)
            except Exception:
                pass

        apk_filename = f"{uuid.uuid4()}.apk"
        apk_path = UPLOADS_DIR / apk_filename

        source_trust = get_domain_trust(apk_url)
        
        # Reuse download code
        download_res = download_apk(apk_url, apk_path)
        if not download_res["success"]:
            return {
                "risk_score": 50,
                "confidence": 0.2,
                "verdict": "SUSPICIOUS",
                "decision_trace": [],
                "reasons": [download_res["error"], "Fallback static analysis used"],
                "trust_level": source_trust,
                "failure_type": download_res.get("failure_type", "NETWORK_ERROR")
            }

        actual_apk_path = str(apk_path)

        if download_res.get("is_apkm"):
            extract_dir = UPLOADS_DIR / f"{uuid.uuid4()}_extracted"
            extract_dir.mkdir(parents=True, exist_ok=True)
            extracted_base = extract_apkm(str(apk_path), extract_dir)
            if extracted_base:
                actual_apk_path = extracted_base
            else:
                return {
                    "risk_score": 60,
                    "confidence": 0.2,
                    "verdict": "SUSPICIOUS",
                    "decision_trace": [],
                    "reasons": ["APKM extraction failed. No base APK found.", "Fallback static analysis used"],
                    "trust_level": source_trust,
                    "failure_type": "INVALID_FORMAT"
                }

        # Calculate hash for pipeline
        with open(actual_apk_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        analysis_input = AnalysisInput(
            apk_path=actual_apk_path,
            apk_hash=file_hash,
            source=apk_url,
            trust_level=source_trust,
            execution_context="extension",
            is_apkm=download_res.get("is_apkm", False)
        )

        from app.core.orchestrator import AnalysisOrchestrator

        # Core Engine Execution via Orchestrator (Single Source of Truth)
        decision = AnalysisOrchestrator.analyze_apk(CoreAnalysisEngine._execute_internal, analysis_input)

        core_result = decision.model_dump()

        # Strip raw_report payload to ensure lightweight fast-path response
        core_result.pop("raw_report", None)

        if core_result.get("verdict") not in ["UNKNOWN"]:
            with open(cache_path, "w") as f:
                json.dump(core_result, f)

        try:
            if os.path.exists(apk_path):
                os.remove(apk_path)
            if download_res.get("is_apkm") and 'extract_dir' in locals():
                shutil.rmtree(extract_dir, ignore_errors=True)
        except Exception as ex:
            logger.error(f"[ExtensionAdapter] Cleanup error: {ex}")

        return core_result
