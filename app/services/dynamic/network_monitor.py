"""
Network Monitor (IOC SIGNAL GENERATOR)
- Extracts runtime-like network indicators
- Works on logs / context / parsed execution data
- FIXES IOC = 0 problem
"""

import re
from typing import Dict, Any, List


class NetworkMonitor:

    def __init__(self):

        # URL patterns
        self.url_pattern = re.compile(r"https?://[^\s\"']+")

        # IP patterns
        self.ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        # suspicious domains keywords
        self.suspicious_keywords = {
            "api", "login", "auth", "token",
            "bank", "transfer", "session",
            "c2", "command", "control",
            "steal", "exfiltrate"
        }

    def analyze(self, context) -> Dict[str, Any]:

        raw_text = self._collect_data(context)

        urls = self.url_pattern.findall(raw_text)
        ips = self.ip_pattern.findall(raw_text)

        domains = self._extract_domains(urls)

        keywords_found = self._extract_keywords(raw_text)

        return {
            "urls": urls or [],
            "ips": ips or [],
            "domains": domains or [],
            "keywords": keywords_found or [],
            "network_activity_detected": bool(urls or ips or domains)
        }

    # ----------------------------
    # SAFE DATA COLLECTION
    # ----------------------------
    def _collect_data(self, context) -> str:

        data = []

        try:
            if hasattr(context, "permissions"):
                data.extend(context.permissions or [])

            if hasattr(context, "main_activities"):
                data.extend(context.main_activities or [])

            if hasattr(context, "package_name"):
                data.append(context.package_name)

            if hasattr(context, "logs"):
                data.extend(context.logs or [])

        except Exception:
            pass

        return " ".join(map(str, data))

    # ----------------------------
    # DOMAIN EXTRACTION
    # ----------------------------
    def _extract_domains(self, urls: List[str]) -> List[str]:

        domains = []

        for url in urls:
            try:
                domain = url.split("/")[2]
                domains.append(domain)
            except:
                continue

        return list(set(domains))

    # ----------------------------
    # KEYWORD DETECTION
    # ----------------------------
    def _extract_keywords(self, text: str) -> List[str]:

        text = text.lower()
        found = []

        for k in self.suspicious_keywords:
            if k in text:
                found.append(k)

        return list(set(found))