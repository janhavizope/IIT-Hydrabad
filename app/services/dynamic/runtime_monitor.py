import re
import subprocess
import json
from typing import Dict, Any, List


class RuntimeMonitor:
    """
    REAL Dynamic Runtime Monitor (FIXED PROFESSIONAL VERSION)

    Fixes:
    - removes fake network assumption
    - improves real adb signal capture
    - ensures IOC has actual runtime data source
    """

    def __init__(self):
        self.url_regex = re.compile(r"https?://[^\s\"'<>]+")
        self.ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # =========================
    # MAIN ENTRY
    # =========================
    def analyze(self, context) -> Dict[str, Any]:

        if isinstance(context, str):
            package = context
        else:
            package = getattr(context, "package_name", "") or ""

        # =========================
        # 1. REAL LOGCAPTURE
        # =========================
        logs = self._get_logcat(package)

        # =========================
        # 2. REAL NETWORK SNAPSHOT (ADB BASED)
        # =========================
        network_data = self._get_network_snapshot()

        # =========================
        # 3. BUILD ANALYSIS TEXT
        # =========================
        combined_text = logs + " " + json.dumps(network_data)

        urls = self.url_regex.findall(combined_text)
        ips = self.ip_regex.findall(combined_text)
        domains = self._extract_domains(urls)

        # =========================
        # 4. BEHAVIOR DETECTION (REAL INPUT ONLY)
        # =========================
        behaviors = self._extract_behaviors(logs, network_data)

        # =========================
        # 5. ATTACK PATTERNS
        # =========================
        attack_patterns = self._detect_patterns(urls, ips, logs, network_data)

        # =========================
        # 6. RISK SCORE
        # =========================
        risk_score = self._calculate_risk(urls, ips, behaviors, attack_patterns)

        # =========================
        # 7. IOC STRUCTURE (NOW REAL SOURCE)
        # =========================
        iocs = {
            "urls": list(set(urls)),
            "ips": list(set(ips)),
            "domains": list(set(domains)),
            "dns_queries": network_data.get("dns_queries", []),
            "active_connections": network_data.get("active_connections", [])
        }

        return {
            "package_name": package,
            "dynamic_risk_score": risk_score,
            "behaviors": behaviors,
            "network": iocs,
            "attack_patterns": attack_patterns,
            "raw_logs": logs
        }

    # =========================
    # LOGCAT (REAL FIXED)
    # =========================
    def _get_logcat(self, package: str) -> str:
        try:
            output = subprocess.check_output(
                ["adb", "logcat", "-d"],
                stderr=subprocess.DEVNULL
            )
            return output.decode(errors="ignore")
        except Exception:
            return ""

    # =========================
    # NETWORK SNAPSHOT (FIXED REAL SIGNAL ATTEMPT)
    # =========================
    def _get_network_snapshot(self) -> Dict[str, Any]:
        """
        REALISTIC upgrade:
        Uses adb shell commands instead of fake empty structure
        """

        try:
            netstat = subprocess.check_output(
                ["adb", "shell", "netstat"],
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")

            dns = subprocess.check_output(
                ["adb", "shell", "getprop", "net.dns1"],
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")

            return {
                "netstat": netstat,
                "dns_queries": [dns.strip()] if dns else [],
                "active_connections": self._extract_connections(netstat)
            }

        except Exception:
            return {
                "netstat": "",
                "dns_queries": [],
                "active_connections": []
            }

    # =========================
    # CONNECTION EXTRACTION
    # =========================
    def _extract_connections(self, netstat_output: str) -> List[str]:
        connections = []
        for line in netstat_output.splitlines():
            if "ESTABLISHED" in line or "tcp" in line.lower():
                connections.append(line.strip())
        return connections

    # =========================
    # DOMAIN EXTRACTION
    # =========================
    def _extract_domains(self, urls: List[str]) -> List[str]:
        domains = []
        for url in urls:
            try:
                domains.append(url.split("//")[-1].split("/")[0])
            except:
                continue
        return list(set(domains))

    # =========================
    # BEHAVIOR DETECTION (IMPROVED)
    # =========================
    def _extract_behaviors(self, logs: str, network_data: dict) -> List[str]:

        behaviors = []

        if "SMS" in logs:
            behaviors.append("SMS_ACTIVITY")

        if "ContentResolver" in logs:
            behaviors.append("CONTACT_ACCESS")

        if "Location" in logs:
            behaviors.append("LOCATION_TRACKING")

        if network_data.get("netstat"):
            behaviors.append("NETWORK_ACTIVITY")

        return behaviors

    # =========================
    # ATTACK PATTERN DETECTION (IMPROVED)
    # =========================
    def _detect_patterns(self, urls, ips, logs, network_data):

        patterns = []

        if urls:
            patterns.append("NETWORK_DATA_EXFILTRATION")

        if ips:
            patterns.append("DIRECT_IP_COMMUNICATION")

        if "send" in logs.lower() and "sms" in logs.lower():
            patterns.append("SMS_ABUSE_BEHAVIOR")

        if network_data.get("active_connections"):
            patterns.append("ACTIVE_NETWORK_BEHAVIOR")

        return patterns

    # =========================
    # RISK SCORING (STABLE)
    # =========================
    def _calculate_risk(self, urls, ips, behaviors, patterns):

        score = 0
        score += len(urls) * 20
        score += len(ips) * 25
        score += len(behaviors) * 10
        score += len(patterns) * 15

        return min(100, score)