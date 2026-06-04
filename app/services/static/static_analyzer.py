import re
from app.services.static.static_analysis_contract import normalize_static_analysis

class StaticAnalyzer:
    """
    Static APK Analysis Engine with IOC Extraction
    """
    def __init__(self):
        self.url_pattern = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
        self.ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self.email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        self.apikey_pattern = re.compile(r"(?i)(?:api_key|apikey|sk_live|sk_test|AIza[0-9A-Za-z-_]{35})")

    def analyze(self, context):
        """
        Perform static analysis on APK context
        """
        permissions = getattr(context, "permissions", []) or []
        package_name = getattr(context, "package_name", "") or ""
        strings = getattr(context, "strings", []) or []

        dangerous_permissions = self._get_dangerous_permissions(permissions)
        risk_score = self._calculate_risk_score(dangerous_permissions)
        
        # Extract IOCs
        iocs = self._extract_iocs(strings)

        result = {
            "schema_version": 1,
            "package_name": package_name,
            "static_risk_score": risk_score,

            "permissions": {
                "all": permissions,
                "dangerous": dangerous_permissions
            },

            "manifest_analysis": {
                "exported_components": [],
                "risk_flags": dangerous_permissions
            },

            "attack_patterns": self._detect_patterns(dangerous_permissions),

            "suspicious_indicators": {
                "suspicious_apis": [],
                "hardcoded_urls": iocs["urls"],
                "crypto_usage": [],
                "obfuscation_signs": []
            },
            
            "extracted_iocs": iocs,

            "summary": [
                f"Static risk score {risk_score}/100"
            ]
        }

        return normalize_static_analysis(result)

    def _extract_iocs(self, strings):
        urls = set()
        ips = set()
        emails = set()
        apikeys = set()

        for s in strings[:50000]: 
            try:
                text = s if isinstance(s, str) else s.decode('utf-8', errors='ignore')
                if len(text) > 1000: continue 
                
                urls.update(self.url_pattern.findall(text))
                ips.update(self.ip_pattern.findall(text))
                emails.update(self.email_pattern.findall(text))
                apikeys.update(self.apikey_pattern.findall(text))
            except:
                pass
                
        def is_internal(ip):
            return ip == "127.0.0.1" or ip == "0.0.0.0" or ip.startswith("10.") or ip.startswith("192.168.")
            
        return {
            "urls": list(urls)[:100],
            "ips": [i for i in ips if not is_internal(i)][:100],
            "emails": list(emails)[:50],
            "apikeys": list(apikeys)[:20]
        }

    def _get_dangerous_permissions(self, permissions):
        risky = [
            "SEND_SMS",
            "READ_CALL_LOG",
            "READ_CONTACTS",
            "READ_PHONE_STATE",
            "ACCESS_COARSE_LOCATION",
            "WRITE_EXTERNAL_STORAGE",
            "READ_EXTERNAL_STORAGE"
        ]

        return [p for p in permissions if any(r in p for r in risky)]

    def _calculate_risk_score(self, dangerous_permissions):
        return min(100, len(dangerous_permissions) * 10)

    def _detect_patterns(self, dangerous_permissions):
        patterns = []

        joined = " ".join(dangerous_permissions)

        if "SEND_SMS" in joined:
            patterns.append("DATA_EXFILTRATION_PATTERN")

        if "READ_CONTACTS" in joined:
            patterns.append("PRIVILEGE_ESCALATION_ATTEMPT")

        if "READ_PHONE_STATE" in joined:
            patterns.append("COMMAND_CONTROL_BEHAVIOR")

        return patterns
