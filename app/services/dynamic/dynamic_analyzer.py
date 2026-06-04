import re
from typing import Dict, Any, List


class DynamicAnalyzer:
    """
    REALISTIC Dynamic Analysis Engine (Hackathon-grade MVP)

    - Simulates runtime behavior signals
    - Extracts network + system activity
    - Produces IOC-ready structured output
    """

    def __init__(self):
        self.url_pattern = re.compile(r"https?://[^\s]+")
        self.ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def analyze(self, context) -> Dict[str, Any]:
        """
        context: APK context from parser
        """

        package = getattr(context, "package_name", "")

        # -----------------------------
        # SIMULATED BEHAVIOR EVENTS
        # (Replace later with Frida / emulator logs)
        # -----------------------------
        events = [
            "ACCESS_NETWORK_CALL: LoginActivity -> /api/login",
            "SEND_SMS_TRIGGER: suspicious SMS permission usage",
            "FILE_ACCESS: reading /sdcard/user_data.txt",
            "NETWORK_REQUEST: http://malicious.example.com/auth",
            "NETWORK_REQUEST: https://api.bank-login-secure.com/session",
            "IP_CONNECTION: 192.168.43.10 outbound connection detected"
        ]

        # -----------------------------
        # EXTRACT NETWORK SIGNALS
        # -----------------------------
        raw_text = " ".join(events)

        urls = self.url_pattern.findall(raw_text)
        ips = self.ip_pattern.findall(raw_text)

        # -----------------------------
        # ATTACK BEHAVIOR CLASSIFICATION
        # -----------------------------
        attack_patterns: List[str] = []

        if "SEND_SMS_TRIGGER" in raw_text:
            attack_patterns.append("SMS_ABUSE_BEHAVIOR")

        if "FILE_ACCESS" in raw_text:
            attack_patterns.append("SENSITIVE_FILE_ACCESS")

        if urls:
            attack_patterns.append("NETWORK_DATA_EXFILTRATION")

        if ips:
            attack_patterns.append("DIRECT_IP_COMMUNICATION")

        # -----------------------------
        # DYNAMIC RISK SCORING
        # -----------------------------
        risk_score = 0

        risk_score += len(urls) * 15
        risk_score += len(ips) * 20
        risk_score += len(events) * 3
        risk_score += len(attack_patterns) * 10

        risk_score = min(100, risk_score)

        # -----------------------------
        # FINAL OUTPUT
        # -----------------------------
        return {
            "package_name": package,
            "dynamic_risk_score": risk_score,

            "behaviors": events,

            "network": {
                "urls": urls,
                "ips": ips
            },

            "attack_patterns": attack_patterns,

            "summary": f"Detected {len(events)} runtime events"
        }
    
    