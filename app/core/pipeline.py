import copy
import os
import traceback

from app.core.logger import log_error, log_info
from app.services.apk_parser import APKParser
from app.services.deep_static_analyzer import DeepStaticAnalyzer
from app.services.risk_engine import RiskEngine


class AnalysisPipeline:
    """Pipeline orchestrator for APK analysis."""

    def __init__(self):
        self.cache = {}
        self.parser = APKParser()
        self.risk_engine = RiskEngine()
        self.deep_analyzer = DeepStaticAnalyzer()

    def _default_risk_analysis(self):
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "flags": [],
            "explanation": "No risky permissions detected",
        }

    def _default_deep_static_analysis(self):
        return {
            "suspicious_urls": [],
            "suspicious_apis": [],
            "crypto_usage": [],
            "obfuscation_signs": [],
            "risk_indicators_count": 0,
        }

    def _default_result(self):
        return {
            "package_name": "",
            "permissions": [],
            "main_activities": [],
            "deep_static_analysis": self._default_deep_static_analysis(),
            "risk_analysis": self._default_risk_analysis(),
            "status": "failed",
            "error_message": "",
            "confidence_score": 0.0,
        }

    def _terminate_with_failure(self, apk_hash: str, stage: str, message: str):
        log_info("PIPELINE_STAGE: pipeline_terminated")
        log_error(f"[PIPELINE ERROR] stage={stage} message={message}")

        result = self._default_result()
        result["status"] = "failed"
        result["error_message"] = message
        result["deep_static_analysis"] = {}
        result["risk_analysis"] = {}
        result["confidence_score"] = 0.0

        log_info("Final response assembled")
        log_info("FINAL_STATUS_DECISION: failed")

        self.cache[apk_hash] = copy.deepcopy(result)
        return result

    def execute(self, apk_bytes: bytes, apk_hash: str, apk_path: str = ""):
        """Execute the full analysis pipeline with caching."""
        log_info("APK received in pipeline")

        if apk_hash in self.cache:
            cached_result = copy.deepcopy(self.cache[apk_hash])
            log_info("Final response assembled")
            log_info(f"FINAL_STATUS_DECISION: {cached_result.get('status', 'failed')}")
            return cached_result

        if not os.path.exists(apk_path):
            return self._terminate_with_failure(
                apk_hash,
                "path_validation",
                f"apk file not found on server: {apk_path}",
            )

        analysis_success = False
        parsed_apk = None

        log_info("PIPELINE_STAGE: parsing_started")
        log_info("Starting APK parsing stage")

        try:
            parsed_apk = self.parser.parse(apk_bytes)
            if parsed_apk is None:
                raise RuntimeError("APK parsing returned None")

            parsed_apk.apk_path = apk_path
            parsed_apk.metadata["apk_hash"] = apk_hash
            analysis_success = True

            log_info("PIPELINE_STAGE: parsing_success")
            log_info("APK parsing completed")
        except Exception as e:
            log_info("PIPELINE_STAGE: parsing_failed")
            log_error(f"[PIPELINE ERROR] {repr(e)}")
            log_error(traceback.format_exc())
            return self._terminate_with_failure(apk_hash, "parsing", str(e))

        if not analysis_success or parsed_apk is None:
            return self._terminate_with_failure(
                apk_hash,
                "parsing",
                "parsing stage did not produce a valid analysis context",
            )

        result = self._default_result()
        result["package_name"] = parsed_apk.package_name
        result["permissions"] = parsed_apk.permissions
        result["main_activities"] = parsed_apk.main_activities

        log_info("Starting risk analysis")
        try:
            risk_result = self.risk_engine.calculate_risk(parsed_apk)
            if risk_result in ({}, None):
                raise RuntimeError("RiskEngine returned empty result")
            result["risk_analysis"] = risk_result
        except Exception as e:
            log_error(f"[PIPELINE ERROR] {repr(e)}")
            log_error(traceback.format_exc())
            return self._terminate_with_failure(apk_hash, "risk_engine", f"RiskEngine failed: {str(e)}")
        log_info("Risk analysis completed")

        log_info("Starting deep static analysis")
        try:
            deep_result = self.deep_analyzer.analyze(parsed_apk)
            if deep_result in ({}, None):
                raise RuntimeError("DeepStaticAnalyzer returned empty result")
            result["deep_static_analysis"] = deep_result
        except Exception as e:
            log_error(f"[PIPELINE ERROR] {repr(e)}")
            log_error(traceback.format_exc())
            return self._terminate_with_failure(
                apk_hash,
                "deep_static_analysis",
                f"DeepStaticAnalyzer failed: {str(e)}",
            )
        log_info("Deep static analysis completed")

        result["status"] = "success" if analysis_success else "failed"
        result["error_message"] = ""
        result["confidence_score"] = 1.0

        log_info("Final response assembled")
        log_info(f"FINAL_STATUS_DECISION: {result['status']}")

        self.cache[apk_hash] = copy.deepcopy(result)
        return result
