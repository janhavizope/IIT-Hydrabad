import os
import sys

project_root = r"C:\Users\janhavi\OneDrive\Documents\IIT Hyderabad Hackathon\IIT Project"
sys.path.insert(0, project_root)

from app.services.dynamic.forensics import _is_plausible_domain, extract_iocs

def run_tests():
    print("=== Testing Domain Exclusions ===")
    
    # These should be excluded
    exclusions = [
        "android.content",
        "com.android.vending",
        "com.google.android.gms",
        "looper.main",
        "handler.message",
        "binder.thread",
        "providers.contacts",
        "insecurebankv2.loginactivity",
        "insecurebankv2.dotransfer",
        "MainActivity.java",
        "com.example.app.MyActivity",
        "com.example.MyService",
        "MyContentProvider",
        "MyBroadcastReceiver",
        "localhost",
        "example.com",
    ]
    
    # These should be included
    inclusions = [
        "google.com",
        "api.github.com",
        "malicious-domain.net",
        "192.168.1.1", # Extract IOCs processes IPs separately but let's check realistic domains
    ]
    
    passed = True
    
    for domain in exclusions:
        if _is_plausible_domain(domain):
            print(f"FAIL: Expected '{domain}' to be excluded, but it was INCLUDED.")
            passed = False
        else:
            print(f"PASS: '{domain}' is excluded.")
            
    for domain in inclusions:
        if not _is_plausible_domain(domain):
            print(f"FAIL: Expected '{domain}' to be included, but it was EXCLUDED.")
            passed = False
        else:
            print(f"PASS: '{domain}' is included.")
            
    print("\n=== Testing extract_iocs ===")
    
    mock_events = [
        {"message": "Connecting to https://insecurebankv2.com/api", "tag": "Net"},
        {"message": "Querying providers.contacts for data", "tag": "DB"},
        {"message": "Starting insecurebankv2.loginactivity now", "tag": "Activity"},
        {"message": "Downloaded from http://malware.org/payload.apk", "tag": "Download"},
        {"message": "Contacting IP 8.8.8.8", "tag": "Net"},
        {"message": "com.google.android.gms returned error", "tag": "Error"},
        {"message": "Starting service insecurebankv2.MyService", "tag": "Service"},
    ]
    
    iocs = extract_iocs(mock_events)
    print("Extracted Domains:", iocs.get("domains"))
    print("Extracted URLs:", iocs.get("urls"))
    print("Extracted IPs:", iocs.get("ips"))
    
    expected_domains = ["insecurebankv2.com", "malware.org"]
    if sorted(iocs.get("domains", [])) != sorted(expected_domains):
        print(f"FAIL: Extracted domains {iocs.get('domains')} do not match expected {expected_domains}")
        passed = False
    else:
        print("PASS: Extracted domains match exactly expected genuine domains.")
        
    expected_ips = ["8.8.8.8"]
    if iocs.get("ips", []) != expected_ips:
        print(f"FAIL: Extracted IPs {iocs.get('ips')} do not match expected {expected_ips}")
        passed = False
    else:
        print("PASS: Extracted IPs match exactly expected genuine IPs.")
        
    if passed:
        print("\nALL IOC VALIDATION TESTS PASSED")
    else:
        print("\nSOME TESTS FAILED")

if __name__ == "__main__":
    run_tests()
