import os
import sys
import json
import time

project_root = r"C:\Users\janhavi\OneDrive\Documents\IIT Hyderabad Hackathon\IIT Project"
sys.path.insert(0, project_root)

from app.services.sandbox_controller import SandboxController

def run_validation():
    controller = SandboxController()
    
    apk_path = os.path.join(project_root, "sample_apks", "insecurebankv2.apk")
    package_name = "com.android.insecurebankv2"
    activity = "com.android.insecurebankv2.LoginActivity"
    
    print(f"Starting dynamic session for {package_name} to validate Frida execution...")
    result = controller.run_dynamic_session(
        apk_path=apk_path,
        package_name=package_name,
        activity=activity,
        duration=25,
    )
    
    if not result.get("success"):
        print(f"Session failed: {result.get('error')}")
        return
        
    print("\n=== Validation Report ===")
    
    # 1. Frida-Server Status
    status = result.get("frida_server_status", {})
    deployment_success = status.get('success', False)
    
    print(f"Frida-Server Deployed: {deployment_success}")
    print(f"Frida Version: {status.get('version', 'N/A')}")
    print(f"Architecture: {status.get('architecture', 'N/A')}")
    print(f"Frida-Server PID: {status.get('pid', 'N/A')}")
    print(f"Startup Stable: {status.get('startup_stable', False)}")
    print(f"frida-ps Connectivity: {status.get('frida_ps_connectivity', False)}")
    print(f"Final Deployment Status: {'SUCCESS' if deployment_success else 'FAILED'}")
    
    # 2. Attached Package
    print(f"\nAttached Package: {package_name}")
    
    # 3. Validation Commands Results
    validation_results = result.get("validation_results")
    if validation_results:
        print("\n=== Validation Commands ===")
        if "error" in validation_results:
            print(f"Validation Error: {validation_results['error']}")
        else:
            print("[frida-ps -U]")
            ps_out = validation_results.get("frida_ps", "")
            # Print first 5 lines of ps output to avoid clutter
            print("\n".join(ps_out.splitlines()[:5]) + ("\n..." if len(ps_out.splitlines()) > 5 else ""))
            
            print("\n[frida -U -n InsecureBankv2]")
            print(validation_results.get("frida_attach", "").strip())
            err = validation_results.get("frida_attach_error", "").strip()
            if err:
                print(f"Error: {err}")
                
    instr_success = result.get("frida_instrumentation", False)
    
    # Do not mark instrumentation as operational unless all validation steps pass.
    if not status.get("startup_stable", False) or not status.get("frida_ps_connectivity", False) or not deployment_success:
        instr_success = False
    if validation_results and "error" in validation_results:
        instr_success = False
    if validation_results and validation_results.get("frida_attach_error", "").strip():
        instr_success = False
        
    print(f"\nInstrumentation Successful: {instr_success}")
    
    # 3. Hook Counts
    events = result.get("log_analysis", {}).get("events", [])
    frida_events = [e for e in events if e.get("tag") == "Frida-Instr"]
    
    hook_counts = {}
    db_events = []
    net_events = []
    cp_events = []
    
    for e in frida_events:
        evt_type = e.get("event_type", "unknown")
        hook_counts[evt_type] = hook_counts.get(evt_type, 0) + 1
        
        if evt_type == "database_access":
            db_events.append(e.get("message"))
        elif evt_type == "network":
            net_events.append(e.get("message"))
        elif evt_type in ("sensitive_data", "content_provider"):
            cp_events.append(e.get("message"))
            
    print("\n=== Hook Execution Counts ===")
    for evt, count in hook_counts.items():
        print(f" - {evt}: {count}")
    if not hook_counts:
        print(" - No hooks triggered (0 counts)")
        
    print("\n=== Captured Database Events ===")
    for msg in db_events[:5]: print(f"  {msg}")
    
    print("\n=== Captured Network Events ===")
    for msg in net_events[:5]: print(f"  {msg}")
        
    print("\n=== Captured Content Provider Events ===")
    for msg in cp_events[:5]: print(f"  {msg}")
    
    print("\n=== Sample Raw Frida Events ===")
    print(json.dumps(frida_events[:3], indent=2))
    
    print("\nValidation complete.")

if __name__ == "__main__":
    run_validation()
