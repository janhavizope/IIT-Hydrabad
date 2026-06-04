import os
import sys
import time
import subprocess
from app.services.sandbox_controller import get_adb_path, run_adb_safe, SandboxController

def collect_crash_logs():
    os.makedirs("reports", exist_ok=True)
    report_path = "reports/frida_crash_report.txt"
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=== ADB PS ===\n")
        res = subprocess.run([get_adb_path(), "shell", "ps", "-A"], capture_output=True, text=True, errors="replace")
        f.write(res.stdout)
        
        f.write("\n=== ADB LOGCAT ===\n")
        res = subprocess.run([get_adb_path(), "shell", "logcat", "-d"], capture_output=True, text=True, errors="replace")
        f.write(res.stdout)
        
        f.write("\n=== ADB DMESG ===\n")
        res = subprocess.run([get_adb_path(), "shell", "dmesg"], capture_output=True, text=True, errors="replace")
        f.write(res.stdout)
        
        f.write("\n=== FRIDA SERVER VERSION ===\n")
        res = subprocess.run([get_adb_path(), "shell", "/data/local/tmp/frida-server", "--version"], capture_output=True, text=True, errors="replace")
        f.write(res.stdout)
        f.write(res.stderr)
        
    print(f"Crash logs saved to {report_path}")

def validate_frida():
    controller = SandboxController()
    
    # Push frida server manually for testing or just use deploy_frida_server
    print("[*] Deploying frida-server...")
    status = controller.deploy_frida_server()
    
    print(f"Status: {status}")
    if not status.get("startup_stable", True) or not status.get("success", False):
        print("[-] Frida-server deployment or stability check failed. Collecting crash logs...")
        collect_crash_logs()
    else:
        print("[+] Frida-server deployed and stable.")

if __name__ == "__main__":
    validate_frida()
