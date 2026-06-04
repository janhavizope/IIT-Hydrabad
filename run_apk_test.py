"""
CLI runner for full APK analysis (static + dynamic + verdict).

Uses existing backend services directly — not AnalysisPipeline (pipeline module
may be empty or static-only). Mirrors the API route flow and dynamic engines.
"""

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


def _run_static_analysis(apk_path: str) -> dict:
    """Static analysis via APKParser, RiskEngine, and DeepStaticAnalyzer."""
    apk_path = str(Path(apk_path).resolve())
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    file_bytes = Path(apk_path).read_bytes()
    apk_hash = hashlib.sha256(file_bytes).hexdigest()

    parser = APKParser()
    risk_engine = RiskEngine()
    deep_analyzer = DeepStaticAnalyzer()

    parsed = parser.parse(file_bytes)
    if parsed is None:
        raise RuntimeError("APK parsing returned None")

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


def _static_analysis_for_verdict(static_result: dict) -> dict:
    """Canonical static payload for fusion / decision-trace engines."""
    return build_canonical_from_pipeline_result(static_result)


def _threat_intelligence_from_dynamic(dynamic_result: dict) -> dict:
    """Flatten sandbox session output into threat_intelligence payload."""
    log_analysis = dynamic_result.get("log_analysis") or {}
    behavior = (
        dynamic_result.get("behavior_risk")
        or log_analysis.get("behavior_risk")
        or {}
    )

    threat_intelligence = dict(behavior)
    threat_intelligence.setdefault("package_name", dynamic_result.get("package_name") or "")
    threat_intelligence["session_state"] = dynamic_result.get("session_state") or log_analysis.get(
        "session_state", {}
    )
    if log_analysis.get("intelligence_summary"):
        threat_intelligence["intelligence_summary"] = log_analysis["intelligence_summary"]
    threat_intelligence["dynamic_session"] = {
        "success": dynamic_result.get("success", False),
        "status": dynamic_result.get("status"),
        "session_id": dynamic_result.get("session_id"),
        "failed_step": dynamic_result.get("failed_step"),
        "error": dynamic_result.get("error"),
        "error_type": dynamic_result.get("error_type"),
    }
    return threat_intelligence


def _empty_threat_intelligence(package_name: str = "", reason: str = "") -> dict:
    return {
        "package_name": package_name,
        "risk_score": 0,
        "risk_level": "LOW",
        "attack_patterns": [],
        "evidence": [],
        "forensics": {"timeline": [], "iocs": {}},
        "threat_classification": {},
        "dynamic_session": {"success": False, "skipped": True, "reason": reason},
    }


def run_full_analysis(
    apk_path: str,
    *,
    enable_dynamic: bool = True,
    dynamic_duration: int = 10,
    username: str | None = None,
    password: str | None = None,
) -> dict:
    """
    Run static analysis, optional dynamic sandbox session, and fusion engines.
    """
    static_result = _run_static_analysis(apk_path)
    static_for_verdict = _static_analysis_for_verdict(static_result)

    package_name = static_result.get("package_name") or ""
    activities = static_result.get("main_activities") or []
    activity = next(iter(activities)) if activities else ""

    threat_intelligence: dict
    dynamic_result: dict | None = None

    if enable_dynamic:
        sandbox = SandboxController()
        dynamic_result = sandbox.run_dynamic_session(
            apk_path=str(Path(apk_path).resolve()),
            package_name=package_name,
            activity=activity,
            duration=dynamic_duration,
            username=username,
            password=password,
        )
        if dynamic_result.get("success"):
            threat_intelligence = _threat_intelligence_from_dynamic(dynamic_result)
            events = (dynamic_result.get("log_analysis") or {}).get("events") or []
            validation = validate_attack_chains(events)
            threat_intelligence = apply_to_threat_intelligence(
                threat_intelligence,
                validation,
                static_for_verdict,
            )
        else:
            threat_intelligence = _empty_threat_intelligence(
                package_name,
                reason=dynamic_result.get("error") or "dynamic analysis failed",
            )
            threat_intelligence["dynamic_session"] = {
                "success": False,
                "status": dynamic_result.get("status"),
                "failed_step": dynamic_result.get("failed_step"),
                "error": dynamic_result.get("error"),
                "error_type": dynamic_result.get("error_type"),
            }
    else:
        threat_intelligence = _empty_threat_intelligence(package_name, reason="disabled by flag")

    final_verdict = build_final_verdict(threat_intelligence, static_for_verdict)
    visualization_data = build_visualization_data(threat_intelligence)
    decision_trace = DecisionTraceEngine.build(
        static_for_verdict,
        threat_intelligence,
        final_verdict,
    )

    events = []
    if dynamic_result and dynamic_result.get("success"):
        events = (dynamic_result.get("log_analysis") or {}).get("events") or []

    # Pass raw static_result so manifest permissions list is explicit (no inference)
    assessment_static = {**static_result, **static_for_verdict}
    malware_assessment = assess_apk_analysis(
        assessment_static,
        threat_intelligence=threat_intelligence,
        events=events,
        package_name=package_name,
    )

    return {
        "apk_path": str(Path(apk_path).resolve()),
        "malware_assessment": malware_assessment,
        "static_analysis": static_result,
        "static_for_verdict": static_for_verdict,
        "dynamic_result": dynamic_result,
        "threat_intelligence": threat_intelligence,
        "final_verdict": final_verdict,
        "visualization_data": visualization_data,
        "decision_trace": decision_trace,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run full APK analysis pipeline")
    parser.add_argument(
        "apk_path",
        nargs="?",
        help="Path to the .apk file (prompted if omitted)",
    )
    parser.add_argument(
        "--no-dynamic",
        action="store_true",
        help="Skip dynamic sandbox / logcat analysis",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Logcat collection duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--username",
        type=str,
        default="admin",
        help="Sample username for ADB login interaction",
    )
    parser.add_argument(
        "--password",
        type=str,
        default="password",
        help="Sample password for ADB login interaction",
    )
    return parser.parse_args()


def main() -> None:
    print("\n=== APK ANALYSIS TEST RUNNER ===\n")

    args = _parse_args()
    apk_path = (args.apk_path or "").strip()
    if not apk_path:
        apk_path = input("Enter APK path: ").strip()

    if not apk_path:
        print("No APK path provided. Exiting.")
        sys.exit(1)

    print(f"\nAPK: {apk_path}")
    print(f"Dynamic analysis: {'off' if args.no_dynamic else 'on'}")
    print("\nRunning analysis... please wait\n")

    try:
        result = run_full_analysis(
            apk_path,
            enable_dynamic=not args.no_dynamic,
            dynamic_duration=args.duration,
            username=args.username,
            password=args.password,
        )
    except Exception as exc:
        print("\nERROR OCCURRED:\n", str(exc))
        traceback.print_exc()
        sys.exit(1)

    threat = result.get("threat_intelligence", {})
    forensics = threat.get("forensics", {})
    behavior = result.get("threat_intelligence", {}).get("behavior_risk", {})

    print("\n================ MALWARE ASSESSMENT (STRICT JSON) ================\n")
    print(json.dumps(result.get("malware_assessment", {}), indent=2, default=str))

    print("\n================ DETAILED DYNAMIC REPORT ================\n")
    
    print("--- Fused Final Risk Score ---")
    fused_score = result.get("malware_assessment", {}).get("risk_score", 0)
    print(f"Score: {fused_score}/100")
    print(f"Level: {threat.get('risk_level', 'LOW')}")
    
    print("\n--- Suspicious Actions Detected ---")
    patterns = threat.get("attack_patterns", [])
    if patterns:
        for p in patterns:
            print(f" - {p}")
    else:
        print(" - None")
        
    print("\n--- Evidence Used for Classification ---")
    evidence = threat.get("evidence", [])
    if evidence:
        for e in evidence:
            print(f" - {e}")
    else:
        print(" - None")

    print("\n--- IOC Summary ---")
    iocs = forensics.get("iocs", {})
    print(json.dumps(iocs, indent=2, default=str))

    print("\n--- Runtime Timeline ---")
    timeline = forensics.get("timeline", [])
    if timeline:
        for t in timeline:
            print(f"[{t.get('time')}] {t.get('event_type').upper()}: {t.get('summary')}")
    else:
        print("No runtime events recorded.")

    print("\n========================================\n")


if __name__ == "__main__":
    main()
