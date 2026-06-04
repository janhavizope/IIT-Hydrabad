from typing import Dict, Any
from app.services.apk_parser import APKParser
from app.services.static.static_analyzer import StaticAnalyzer
from app.services.dynamic.final_verdict_engine import FinalVerdictEngine
from app.services.dynamic.ioc_extractor import IOCExtractor
from app.services.sandbox_controller import SandboxController


class AnalysisPipeline:
    """
    FULL SECURITY PIPELINE (Integrated with Sandbox Controller)
    """

    def __init__(self):
        self.apk_parser = APKParser()
        self.static_analyzer = StaticAnalyzer()
        self.sandbox = SandboxController()
        self.ioc_extractor = IOCExtractor()
        self.verdict_engine = FinalVerdictEngine()

    def execute(self, file_bytes: bytes, apk_hash: str, apk_path: str) -> Dict[str, Any]:
        import logging
        import traceback
        logger = logging.getLogger(__name__)

        # Default standard output contract
        final_status = "SUCCESS"
        static_result = {}
        runtime_result = {
            "status": "FAILED",
            "logs": {"lines": []},
            "behavior_risk": {
                "risk_score": 0,
                "risk_level": "LOW",
                "evidence": [],
                "forensics": {}
            },
            "iocs": {
                "urls": [], "ips": [], "domains": [], "suspicious_strings": []
            }
        }
        final_verdict = {
            "verdict": "UNKNOWN",
            "final_risk_score": 0,
            "confidence": 0.0,
            "reasoning": [],
            "meta": {}
        }
        features = {
            "ioc_score": 0.0,
            "behavior_score": 0.0,
            "permission_risk": 0.0,
            "network_activity_score": 0.0,
            "attack_pattern_score": 0.0
        }
        
        context = None
        package_name = "unknown"
        permissions = []
        main_activities = []

        # =========================
        # 1. APK PARSE
        # =========================
        try:
            context = self.apk_parser.parse(file_bytes)
            if context is None:
                raise RuntimeError("APK parsing returned None")
            context.apk_path = apk_path
            if not hasattr(context, "metadata"):
                context.metadata = {}
            context.metadata["apk_hash"] = apk_hash
            
            package_name = context.package_name
            permissions = context.permissions
            if context.main_activities:
                main_activities = context.main_activities
        except Exception as e:
            logger.error(f"APK parsing failed: {e}\n{traceback.format_exc()}")
            final_status = "FAILED"

        # =========================
        # 2. STATIC ANALYSIS
        # =========================
        if context:
            try:
                static_res = self.static_analyzer.analyze(context)
                if static_res:
                    static_result = static_res
            except Exception as e:
                logger.error(f"Static analysis failed: {e}\n{traceback.format_exc()}")
                final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status

        # =========================
        # 3. DYNAMIC ANALYSIS (SANDBOX / EMULATOR)
        # =========================
        if context:
            try:
                main_activity = main_activities[0] if main_activities else ""
                runtime_res = self.sandbox.run_dynamic_session(
                    apk_path=apk_path,
                    package_name=package_name,
                    activity=main_activity,
                    duration=30
                )
                if runtime_res:
                    # Merge results to guarantee contract
                    for key, val in runtime_res.items():
                        if key == "status":
                            if val == "partial":
                                runtime_result["status"] = "PARTIAL_SUCCESS"
                            elif val == "success":
                                runtime_result["status"] = "SUCCESS"
                            else:
                                runtime_result["status"] = "FAILED"
                        elif key == "behavior_risk" and not val:
                            pass # Keep default
                        else:
                            runtime_result[key] = val
                    
                    if runtime_result["status"] == "FAILED":
                        final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status
                    elif runtime_result["status"] == "PARTIAL_SUCCESS":
                        final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status
                else:
                    final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status
            except Exception as e:
                logger.error(f"Dynamic analysis crashed: {e}\n{traceback.format_exc()}")
                final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status

        # =========================
        # 4. IOC EXTRACTION
        # =========================
        try:
            extracted_iocs = self.ioc_extractor.extract(runtime_result)
            if extracted_iocs:
                runtime_result["iocs"] = extracted_iocs
        except Exception as e:
            logger.error(f"IOC extraction crashed: {e}\n{traceback.format_exc()}")
            final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status

        # Log IOC and Evidence counts
        iocs = runtime_result.get("iocs", {})
        ioc_count = len(iocs.get('urls', [])) + len(iocs.get('ips', [])) + len(iocs.get('domains', []))
        evidence_count = len(runtime_result.get("behavior_risk", {}).get("evidence", []))
        logger.info(f"Pipeline Dynamic Extraction - IOCs: {ioc_count}, Evidence: {evidence_count}")

        # =========================
        # 5. FINAL VERDICT ENGINE
        # =========================
        try:
            verdict_res = self.verdict_engine.compute(
                static_result=static_result,
                runtime_result=runtime_result
            )
            if verdict_res:
                final_verdict = verdict_res
        except Exception as e:
            logger.error(f"Final verdict engine crashed: {e}\n{traceback.format_exc()}")
            final_status = "PARTIAL_SUCCESS" if final_status == "SUCCESS" else final_status
            final_verdict["reasoning"].append(f"Verdict engine failed: {str(e)}")

        # =========================
        # 6. FEATURE EXTRACTION & NORMALIZATION (ML READY)
        # =========================
        def normalize(val: float, max_val: float) -> float:
            return round(min(max(val / max_val, 0.0), 1.0), 4)

        # IOC density
        ioc_score = normalize(ioc_count, 20.0) # Assume 20+ IOCs is max
        # Evidence count
        behavior_score = normalize(evidence_count, 15.0) # Assume 15+ evidences is max
        
        # Permission risk
        dangerous_perms = [p for p in permissions if any(x in p.upper() for x in ["SMS", "LOCATION", "CONTACTS", "STORAGE", "CAMERA", "RECORD_AUDIO", "INTERNET", "PHONE_STATE"])]
        permission_risk = normalize(len(dangerous_perms), 10.0)
        
        # Network Activity score
        network_activity_score = normalize(len(iocs.get('domains', [])) + len(iocs.get('urls', [])), 10.0)
        
        # Attack pattern score
        runtime_patterns = runtime_result.get("behavior_risk", {}).get("attack_patterns", [])
        static_patterns = static_result.get("attack_patterns", [])
        total_patterns = len(set(runtime_patterns + static_patterns))
        attack_pattern_score = normalize(total_patterns, 5.0)

        features = {
            "ioc_score": ioc_score,
            "behavior_score": behavior_score,
            "permission_risk": permission_risk,
            "network_activity_score": network_activity_score,
            "attack_pattern_score": attack_pattern_score
        }

        # Frida Signal Stability Representation
        frida_server = runtime_result.get("frida_server_status", {})
        if frida_server.get("frida_ps_connectivity") and frida_server.get("success"):
            frida_state = "FULL"
        elif frida_server.get("success"):
            frida_state = "PARTIAL"
        else:
            frida_state = "FAILED"
            
        if "metadata" not in runtime_result:
            runtime_result["metadata"] = {}
        runtime_result["metadata"]["frida_state"] = frida_state

        confidence_score = float(final_verdict.get("confidence", 0.0))

        # =========================
        # 7. RESPONSE (Fixed Schema)
        # =========================
        # Ensure final status reflects partial successes correctly
        if final_status == "FAILED" and (static_result or evidence_count > 0 or ioc_count > 0):
            final_status = "PARTIAL_SUCCESS"

        return {
            "final_status": final_status,
            "confidence_score": confidence_score,
            "features": features,
            "static_analysis": static_result,
            "dynamic_analysis": runtime_result,
            "iocs": iocs,
            "behavior_risk": runtime_result.get("behavior_risk", {}),
            
            # Optional passthrough context
            "apk_hash": apk_hash,
            "package_name": package_name,
            "final_verdict": final_verdict
        }
