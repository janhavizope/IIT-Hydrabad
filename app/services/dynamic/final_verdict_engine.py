"""
Final Verdict Engine - PRODUCTION FIXED VERSION
Fixes:
- IOC structure mismatch
- dynamic + static fusion consistency
- safe type handling
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


# =========================
# WEIGHTS
# =========================
WEIGHT_DYNAMIC = 0.50
WEIGHT_STATIC = 0.35
WEIGHT_IOC = 0.15


# =========================
# THRESHOLDS
# =========================
MALWARE_THRESHOLD = 75
SUSPICIOUS_THRESHOLD = 40

MALWARE_SCORE_THRESHOLD = MALWARE_THRESHOLD
SAFE_SCORE_THRESHOLD = SUSPICIOUS_THRESHOLD
COMMAND_CONTROL_CONFIDENCE_THRESHOLD = 0.6



# =========================
# UTILS
# =========================
def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_get(obj, key, default=0):
    try:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return default
    except:
        return default


def _safe_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    return []


# =========================
# IOC SCORE ENGINE (FIXED)
# =========================
def _extract_ioc_score(iocs: Any) -> int:
    """
    SAFE IOC scoring — handles dict/list/None
    """

    if not isinstance(iocs, dict):
        return 0

    domains = _safe_list(iocs.get("domains"))
    ips = _safe_list(iocs.get("ips"))
    urls = _safe_list(iocs.get("urls"))
    strings = _safe_list(iocs.get("suspicious_strings"))

    score = (
        len(domains) * 20 +
        len(ips) * 25 +
        len(urls) * 15 +
        len(strings) * 10
    )

    return min(score, 100)


def _ioc_present(iocs: Any) -> bool:
    if not isinstance(iocs, dict):
        return False

    return bool(
        iocs.get("domains") or
        iocs.get("ips") or
        iocs.get("urls") or
        iocs.get("suspicious_strings")
    )





# =========================
# CONFIDENCE MODEL
# =========================
def _confidence(score: int, patterns: List[str], ioc_flag: bool, behavior_boost: float = 0.0) -> float:
    base = score / 100

    pattern_factor = min(len(patterns) * 0.05, 0.2)
    ioc_factor = 0.12 if ioc_flag else 0.0
    behavior_factor = min(behavior_boost / 100.0, 0.3)

    noise = 0.05 if 40 <= score <= 70 else 0.0

    conf = base + pattern_factor + ioc_factor + behavior_factor - noise

    return round(max(0.1, min(conf, 0.98)), 2)


# =========================
# VERDICT ENGINE
# =========================
def _verdict(score: int, patterns: List[str], confidence: float) -> str:

    patterns = patterns or []

    if score >= MALWARE_THRESHOLD:
        return "MALWARE"

    if "COMMAND_CONTROL_BEHAVIOR" in patterns and confidence > 0.6:
        return "MALWARE"

    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"

    return "SAFE"


# =========================
# MAIN ENGINE
# =========================
class FinalVerdictEngine:

    def compute(self, static_result: Dict[str, Any] = None, runtime_result: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        # Handle cases where keyword args are used, or it's called with (threat_intelligence, static_analysis)
        threat_intelligence = kwargs.get("threat_intelligence")
        static_analysis = kwargs.get("static_analysis")
        
        # If threat_intelligence is provided, it is actually the runtime_result
        if threat_intelligence is not None:
            runtime_result = threat_intelligence
            
        # If static_analysis is provided, it is actually the static_result
        if static_analysis is not None:
            static_result = static_analysis

        # Handle positional swap compatibility: compute(threat_intelligence, static_analysis)
        if isinstance(static_result, dict) and "static_risk_score" not in static_result:
            if isinstance(runtime_result, dict) and "static_risk_score" in runtime_result:
                static_result, runtime_result = runtime_result, static_result

        static_result = static_result or {}
        runtime_result = runtime_result or {}

        # -------------------------
        # STAGE VALIDATION
        # -------------------------
        raw_logs = runtime_result.get("raw_logs", "")
        if isinstance(raw_logs, str):
            raw_logs = raw_logs.strip()
        else:
            raw_logs = ""
            
        network_data = runtime_result.get("network", {})
        has_network_events = False
        if isinstance(network_data, dict):
            has_network_events = bool(
                network_data.get("active_connections") or
                network_data.get("dns_queries") or
                network_data.get("urls") or
                network_data.get("ips")
            )
            
        dynamic_success = bool(raw_logs) or has_network_events

        # -------------------------
        # DYNAMIC & STATIC EXTRACTION
        # -------------------------
        static_score = _safe_get(static_result, "static_risk_score", 0)
        static_patterns = static_result.get("attack_patterns", []) or []
        static_success = isinstance(static_result, dict) and bool(static_result)
        
        dynamic_score = _safe_get(runtime_result, "dynamic_risk_score", 0) or _safe_get(runtime_result, "risk_score", 0)
        runtime_patterns = runtime_result.get("attack_patterns", []) or []

        # -------------------------
        # IOC EXTRACTION (FIXED)
        # -------------------------
        iocs = runtime_result.get("iocs")
        if not isinstance(iocs, dict):
            forensics = runtime_result.get("forensics") or {}
            iocs = forensics.get("iocs") or {}
        if not isinstance(iocs, dict):
            iocs = {}

        ioc_score = _extract_ioc_score(iocs)
        ioc_flag = _ioc_present(iocs)
        ioc_success = ioc_flag

        # -------------------------
        # DYNAMIC VALIDATION EXTENSION
        # -------------------------
        event_counts = runtime_result.get("event_counts", {})
        has_events = False
        if isinstance(event_counts, dict):
            has_events = any(v > 0 for v in event_counts.values() if isinstance(v, int))
            
        dynamic_success = dynamic_success or has_events

        # -------------------------
        # WEIGHT NORMALIZATION
        # -------------------------
        weights = {"dynamic": WEIGHT_DYNAMIC, "static": WEIGHT_STATIC, "ioc": WEIGHT_IOC}
        
        if not dynamic_success:
            weights["dynamic"] = 0.0
            dynamic_score = 0
            
        if not static_success:
            weights["static"] = 0.0
            static_score = 0
            
        if not ioc_success:
            weights["ioc"] = 0.0
            ioc_score = 0
            
        total_weight = sum(weights.values())
        if total_weight > 0:
            norm_dynamic = weights["dynamic"] / total_weight
            norm_static = weights["static"] / total_weight
            norm_ioc = weights["ioc"] / total_weight
        else:
            norm_dynamic = norm_static = norm_ioc = 0.0

        # -------------------------
        # FINAL RISK FUSION
        # -------------------------
        if dynamic_success:
            patterns = list(set(_safe_list(static_patterns) + _safe_list(runtime_patterns)))
        else:
            # Ensure no behavioral inference without runtime evidence
            patterns = list(set(_safe_list(static_patterns)))

        # Compute base fused score
        base_fused_score = (
            (dynamic_score * norm_dynamic) +
            (static_score * norm_static) +
            (ioc_score * norm_ioc)
        )
        
        # -------------------------
        # BEHAVIORAL WEIGHTING LAYER
        # -------------------------
        behavior_boost = 0
        explainability_trace = [f"Base Fused Score: {int(base_fused_score)}"]
        
        if dynamic_success:
            # Evidence Count
            evidence = runtime_result.get("evidence", [])
            evidence_count = len(evidence) if isinstance(evidence, list) else 0
            if evidence_count > 0:
                boost = min(evidence_count * 2, 10)
                behavior_boost += boost
                explainability_trace.append(f"+{boost} risk for {evidence_count} runtime evidence signals")

            # IOC Count
            domains = _safe_list(iocs.get("domains"))
            ips = _safe_list(iocs.get("ips"))
            urls = _safe_list(iocs.get("urls"))
            total_iocs = len(domains) + len(ips) + len(urls)
            if total_iocs > 0:
                boost = min(total_iocs * 3, 15)
                behavior_boost += boost
                explainability_trace.append(f"+{boost} risk for {total_iocs} active network IOCs")

            # Attack Patterns
            for pattern in runtime_patterns:
                if pattern in ["COMMAND_CONTROL_BEHAVIOR", "DATA_EXFILTRATION_PATTERN", "PRIVILEGE_ESCALATION_ATTEMPT"]:
                    behavior_boost += 20
                    explainability_trace.append(f"+20 risk for confirmed attack chain: {pattern}")
                else:
                    behavior_boost += 10
                    explainability_trace.append(f"+10 risk for behavioral pattern: {pattern}")
                    
            # Correlation Logic
            suspicious_strings = _safe_list(iocs.get("suspicious_strings"))
            has_sms = "SMS_BEHAVIOR" in suspicious_strings or (isinstance(event_counts, dict) and event_counts.get("sensitive_data", 0) > 0)
            has_network = "NETWORK_ACTIVITY" in suspicious_strings or (isinstance(event_counts, dict) and event_counts.get("network", 0) > 0) or total_iocs > 0
            has_file = "FILE_ACCESS" in suspicious_strings or (isinstance(event_counts, dict) and event_counts.get("file_access", 0) > 0)
            
            # Additional signals from permissions if available
            permissions = [p.lower() for p in _safe_list(static_result.get("permissions"))]
            has_contacts = any("contact" in p for p in permissions)
            has_external_storage = any("external_storage" in p for p in permissions)

            if has_sms and has_contacts and has_network:
                behavior_boost += 25
                explainability_trace.append("+25 risk for behavioral correlation: SMS + Contacts + Network Access (Potential spyware exfiltration)")

            if has_file and has_external_storage and has_network:
                behavior_boost += 15
                explainability_trace.append("+15 risk for behavioral correlation: File Access + External Storage + Network Activity")

        # Apply normalization: SAFE apps remain low unless anomalies exist
        fused_score = base_fused_score
        if behavior_boost > 0:
            if fused_score < 20: 
                # Dampen boost for otherwise safe apps unless critical chains are confirmed
                if any(p in runtime_patterns for p in ["COMMAND_CONTROL_BEHAVIOR", "DATA_EXFILTRATION_PATTERN", "PRIVILEGE_ESCALATION_ATTEMPT"]):
                    fused_score += behavior_boost
                else:
                    fused_score += (behavior_boost * 0.5) 
            else:
                fused_score += behavior_boost

        final_score = int(fused_score)
        final_score = max(0, min(100, final_score))
        explainability_trace.append(f"Final Normalized Score: {final_score}")

        confidence = _confidence(final_score, patterns, ioc_flag, behavior_boost)
        
        if not dynamic_success:
            # Reduce confidence score accordingly due to lack of dynamic data
            confidence = max(0.1, round(confidence * 0.5, 2))

        verdict = _verdict(final_score, patterns, confidence)
        
        reasoning = [
            f"Risk: {final_score}/100",
            f"Confidence: {confidence}" + (" (Reduced due to missing/failed dynamic analysis)" if not dynamic_success else ""),
            f"IOC score: {ioc_score}" + (" (No runtime evidence)" if not dynamic_success and not ioc_success else ""),
            f"Patterns: {patterns if patterns else 'NONE'}"
        ]
        
        reasoning.extend(["--- Behavioral Trace ---"] + explainability_trace)
        
        meta = {
            "timestamp": _utc(),
            "ioc_score": ioc_score,
            "ioc_present": ioc_flag,
            "pattern_count": len(patterns),
            "dynamic_successful": dynamic_success
        }
        
        signal_weights = {
            "dynamic": norm_dynamic,
            "static": norm_static,
            "ioc": norm_ioc
        }

        return {
            "verdict": verdict,
            "final_risk_score": final_score,
            "confidence": confidence,
            "signal_weights": signal_weights,
            "reasoning": reasoning,
            "meta": meta
        }


def build_final_verdict(threat_intelligence: Dict[str, Any], static_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
    return FinalVerdictEngine().compute(
        static_result=static_analysis,
        runtime_result=threat_intelligence
    )


    