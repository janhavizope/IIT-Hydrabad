import os
import sys
import json

project_root = r"C:\Users\janhavi\OneDrive\Documents\IIT Hyderabad Hackathon\IIT Project"
sys.path.insert(0, project_root)

from app.services.sandbox_controller import SandboxController

def run_test():
    controller = SandboxController()
    
    apk_path = os.path.join(project_root, "sample_apks", "insecurebankv2.apk")
    package_name = "com.android.insecurebankv2"
    activity = "com.android.insecurebankv2.LoginActivity"
    
    print(f"Starting dynamic session for {package_name}...")
    
    # Real dynamic session without synthetic events
    result = controller.run_dynamic_session(
        apk_path=apk_path,
        package_name=package_name,
        activity=activity,
        duration=45,
    )
    
    if not result.get("success"):
        print(f"Session failed: {result.get('error')}")
        return
        
    print("\n=== Session Completed ===")
    forensics = result.get("forensics", {})
    iocs = forensics.get("iocs", {})
    
    print("\nExtracted IOCs:")
    print(json.dumps(iocs, indent=2))
    
    print("\nBehavior Risk Summary:")
    risk = result.get("behavior_risk", {})
    print(f"Risk Score: {risk.get('risk_score')}")
    print(f"Risk Level: {risk.get('risk_level')}")
    print("Event Counts:", risk.get("event_counts"))
    
    print("\nIntelligence Summary:")
    print(result.get("intelligence_summary", {}).get("summary"))
    
    print("\nScreenshot saved dynamically during run by SandboxController.")

    # Save raw frida events to reports/frida_raw_events.json
    events = result.get("log_analysis", {}).get("events", [])
    frida_events = [e for e in events if e.get("tag") == "Frida-Instr"]
    
    reports_dir = os.path.join(project_root, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, "frida_raw_events.json")
    with open(report_path, "w") as f:
        json.dump(frida_events, f, indent=2)
    print(f"\nRaw Frida events saved to: {report_path}")

if __name__ == "__main__":
    run_test()
