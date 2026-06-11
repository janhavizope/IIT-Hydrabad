import logging
import traceback
from app.core.pipeline import AnalysisPipeline
from app.core.models import AnalysisInput, DecisionSchema, DecisionTraceItem
from app.core.confidence import calculate_confidence

logger = logging.getLogger(__name__)

class CoreAnalysisEngine:
    @staticmethod
    def _execute_internal(analysis_input: AnalysisInput) -> DecisionSchema:
        """Internal execution engine. Must be called via Orchestrator."""
        try:
            with open(analysis_input.apk_path, "rb") as f:
                file_bytes = f.read()

            pipeline = AnalysisPipeline()
            result = pipeline.execute(
                file_bytes, 
                analysis_input.apk_hash, 
                analysis_input.apk_path,
                execution_context=analysis_input.execution_context
            )

            # Stage 1: Feature Extraction
            dynamic_analysis = result.get("dynamic_analysis", {})
            dynamic_iocs = dynamic_analysis.get("iocs", {})
            behavior_risk = dynamic_analysis.get("behavior_risk", {})
            evidence = behavior_risk.get("evidence", [])
            static_analysis = result.get("static_analysis", {})

            # Stage 2: Feature Normalization
            normalized_features = {
                "has_dangerous_perms": False,
                "dangerous_perms_list": [],
                "has_suspicious_apis": False,
                "has_attack_patterns": False,
                "attack_pattern": None,
                "critical_signature_matched": False,
                "has_dynamic_evidence": False,
                "evidence_list": []
            }
            
            if isinstance(static_analysis, dict):
                perms = static_analysis.get("permissions", [])
                dangerous_perms = [p for p in perms if isinstance(p, str) and ("android.permission.READ_" in p or "SEND_SMS" in p or "INSTALL_PACKAGES" in p)]
                if dangerous_perms:
                    normalized_features["has_dangerous_perms"] = True
                    normalized_features["dangerous_perms_list"] = dangerous_perms[:3]
                
                api_usage = static_analysis.get("api_usage", {})
                if api_usage:
                    normalized_features["has_suspicious_apis"] = True
                
                static_patterns = static_analysis.get("attack_patterns", [])
                if static_patterns:
                    normalized_features["has_attack_patterns"] = True
                    normalized_features["attack_pattern"] = static_patterns[0]
                    if "malware" in static_patterns[0].lower() or "c2" in static_patterns[0].lower() or "spyware" in static_patterns[0].lower():
                        normalized_features["critical_signature_matched"] = True
            
            if evidence:
                normalized_features["has_dynamic_evidence"] = True
                normalized_features["evidence_list"] = evidence[:2]

            # Stage 3: Rule Evaluation & Conflict Resolution
            decision_trace = []
            score = 0
            is_critical_override = False
            
            if normalized_features["critical_signature_matched"]:
                is_critical_override = True
                score = 100
                decision_trace.append(DecisionTraceItem(
                    rule_id="R999",
                    feature_triggered=f"CRITICAL Signature Match: {normalized_features['attack_pattern']}",
                    score_impact=100
                ))
            else:
                if normalized_features["has_dangerous_perms"]:
                    score += 15
                    decision_trace.append(DecisionTraceItem(
                        rule_id="R001",
                        feature_triggered=f"Dangerous Permissions: {', '.join(normalized_features['dangerous_perms_list'])}",
                        score_impact=15
                    ))
                if normalized_features["has_suspicious_apis"]:
                    score += 20
                    decision_trace.append(DecisionTraceItem(
                        rule_id="R002",
                        feature_triggered="Code Reflection / Cryptography APIs",
                        score_impact=20
                    ))
                if normalized_features["has_attack_patterns"]:
                    score += 30
                    decision_trace.append(DecisionTraceItem(
                        rule_id="R003",
                        feature_triggered=f"Attack Pattern: {normalized_features['attack_pattern']}",
                        score_impact=30
                    ))
                if normalized_features["has_dynamic_evidence"]:
                    score += 25
                    decision_trace.append(DecisionTraceItem(
                        rule_id="R004",
                        feature_triggered=f"Dynamic Evidence: {normalized_features['evidence_list'][0]}",
                        score_impact=25
                    ))
                if analysis_input.trust_level == "LOW":
                    score += 35
                    decision_trace.append(DecisionTraceItem(
                        rule_id="R005",
                        feature_triggered="LOW Domain Trust",
                        score_impact=35
                    ))

            # Stage 4: Risk Scoring & Classification
            risk_score = min(score, 100)
            if risk_score <= 30:
                verdict = "SAFE"
            elif risk_score <= 70:
                verdict = "SUSPICIOUS"
            else:
                verdict = "MALICIOUS"
                
            # Confidence Math
            confidence = calculate_confidence(
                analysis_input, 
                normalized_features, 
                decision_trace, 
                dynamic_analysis, 
                static_analysis,
                is_critical_override
            )

            # Stage 5: Explanation Generation
            reasons = [dt.feature_triggered for dt in decision_trace]
            if not reasons:
                reasons = ["No specific malicious indicators found."]

            result["ai_summary"] = "Deterministic analysis completed."

            return DecisionSchema(
                risk_score=float(risk_score),
                confidence=float(confidence),
                verdict=verdict,
                decision_trace=decision_trace,
                reasons=reasons,
                trust_level=analysis_input.trust_level,
                failure_type=None,
                raw_report=result
            )

        except Exception as e:
            logger.error(f"[CoreEngine] Pipeline error: {e}")
            logger.error(traceback.format_exc())
            return DecisionSchema(
                risk_score=60.0,
                confidence=0.1,
                verdict="SUSPICIOUS",
                decision_trace=[
                    DecisionTraceItem(rule_id="E999", feature_triggered=f"Pipeline Error: {e}", score_impact=60)
                ],
                reasons=[str(e), "Pipeline analysis failed (fallback to suspicious)."],
                trust_level=analysis_input.trust_level,
                failure_type="PIPELINE_ERROR",
                raw_report=None
            )
