from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import traceback
from pathlib import Path

from app.services.apk_parser import APKParser
from app.services.core.decision_trace_engine import DecisionTraceEngine
from app.services.core.malware_assessment_engine import assess_apk_analysis
from app.services.deep_static_analyzer import DeepStaticAnalyzer
from app.services.dynamic.attack_chain_validator import validate_attack_chains
from app.services.dynamic.final_verdict_engine import build_final_verdict
from app.services.dynamic.fp_reduction_engine import apply_to_threat_intelligence
from app.services.dynamic.visualization_builder import build_visualization_data
from app.services.risk_engine import RiskEngine
from app.services.sandbox_controller import SandboxController
from app.services.static.static_analysis_contract import build_canonical_from_pipeline_result


# =========================
# PATH FIX (IMPORTANT)
# =========================
def resolve_apk_path(path: str) -> str:
    p = Path(path).expanduser().resolve()

    if p.exists():
        return str(p)

    raise FileNotFoundError(
        f"APK NOT FOUND.\nGiven: {path}\nResolved: {p}\n"
        "Fix: pass FULL absolute path OR move APK inside project folder."
    )


# =========================
# STATIC ANALYSIS
# =========================
def run_static_analysis(apk_path: str) -> dict:
    apk_path = resolve_apk_path(apk_path)

    file_bytes = Path(apk_path).read_bytes()
    apk_hash = hashlib.sha256(file_bytes).hexdigest()

    parser = APKParser()
    risk_engine = RiskEngine()
    deep_analyzer = DeepStaticAnalyzer()

    parsed = parser.parse(file_bytes)

    if not parsed:
        raise RuntimeError("APK parsing failed")

    parsed.apk_path = apk_path
    parsed.metadata["apk_hash"] = apk_hash

    risk_result = risk_engine.calculate_risk(parsed)
    deep_result = deep_analyzer.analyze(parsed)

    return {
        "status": "success",
        "package_name": parsed.package_name,
        "permissions": parsed.permissions,
        "main_activities": parsed.main_activities,
        "risk_analysis": risk_result,
        "deep_static_analysis": deep_result,
        "apk_hash": apk_hash,
    }


# =========================
# THREAT INTELLIGENCE BUILDER
# =========================
def build_threat_intelligence(dynamic_result: dict) -> dict:
    log_analysis = dynamic_result.get("log_analysis") or {}
    behavior = dynamic_result.get("behavior_risk") or log_analysis.get("behavior_risk") or {}

    return {
        **behavior,
        "package_name": dynamic_result.get("package_name", ""),
        "session_state": dynamic_result.get("session_state", {}),
        "dynamic_session": {
            "success": dynamic_result.get("success", False),
            "status": dynamic_result.get("status"),
            "error": dynamic_result.get("error"),
        },
    }


def empty_threat(package_name: str, reason: str) -> dict:
    return {
        "package_name": package_name,
        "risk_score": 0,
        "risk_level": "SAFE",
        "attack_patterns": [],
        "evidence": [],
        "forensics": {"timeline": [], "iocs": {}},
        "dynamic_session": {"success": False, "reason": reason},
    }


# =========================
# FINAL PIPELINE
# =========================
def run_full_analysis(apk_path: str, enable_dynamic: bool = True, duration: int = 10) -> dict:
    static_result = run_static_analysis(apk_path)
    static_canonical = build_canonical_from_pipeline_result(static_result)

    package_name = static_result.get("package_name", "")
    activity = (static_result.get("main_activities") or [""])[0]

    sandbox = SandboxController()
    dynamic_result = None
    threat = None

    if enable_dynamic:
        dynamic_result = sandbox.run_dynamic_session(
            apk_path=resolve_apk_path(apk_path),
            package_name=package_name,
            activity=activity,
            duration=duration,
        )

        if dynamic_result.get("success"):
            threat = build_threat_intelligence(dynamic_result)

            events = (dynamic_result.get("log_analysis") or {}).get("events") or []
            validation = validate_attack_chains(events)

            threat = apply_to_threat_intelligence(
                threat,
                validation,
                static_canonical,
            )
        else:
            threat = empty_threat(package_name, "dynamic failed")
    else:
        threat = empty_threat(package_name, "dynamic disabled")

    final_verdict = build_final_verdict(threat, static_canonical)
    visualization = build_visualization_data(threat)

    decision_trace = DecisionTraceEngine.build(
        static_canonical,
        threat,
        final_verdict,
    )

    assessment = assess_apk_analysis(
        static_result,
        threat_intelligence=threat,
        events=(dynamic_result or {}).get("log_analysis", {}).get("events", []),
        package_name=package_name,
    )

    return {
        "apk_path": apk_path,
        "malware_assessment": assessment,
        "threat_intelligence": threat,
        "final_verdict": final_verdict,
        "visualization": visualization,
        "decision_trace": decision_trace,
    }


# =========================
# CLI
# =========================
def main():
    print("\n=== APK SECURITY ANALYZER ===\n")

    parser = argparse.ArgumentParser()
    parser.add_argument("apk_path", nargs="?")
    parser.add_argument("--no-dynamic", action="store_true")
    parser.add_argument("--duration", type=int, default=10)
    args = parser.parse_args()

    apk_path = args.apk_path or input("Enter APK path: ").strip()

    try:
        result = run_full_analysis(
            apk_path,
            enable_dynamic=not args.no_dynamic,
            duration=args.duration,
        )
    except Exception as e:
        print("\nERROR:\n", str(e))
        traceback.print_exc()
        sys.exit(1)

    assessment = result["malware_assessment"]

    print("\n================ FINAL RESULT ================\n")
    print(json.dumps(assessment, indent=2, default=str))

    print("\n================ SUMMARY ================\n")
    print("Risk Score:", assessment.get("risk_score", 0))
    print("Classification:", assessment.get("classification", "UNKNOWN"))

    print("\n================ DONE ================\n")


if __name__ == "__main__":
    main()
    