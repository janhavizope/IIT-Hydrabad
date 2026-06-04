import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class IOCExtractor:
    """
    REAL IOC EXTRACTION ENGINE (FIXED)

    Input: runtime_result
    Output: normalized IOC structure for final verdict engine
    """

    def __init__(self):
        self.domain_pattern = re.compile(r"https?://([a-zA-Z0-9.-]+)")
        # Extended regex patterns for IOCs
        self.url_pattern = re.compile(r"https?://[^\s\"\'<>]+")
        self.ip_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
        self.bare_domain_pattern = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))\b")

    def extract(self, runtime_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract IOCs from dynamic analysis runtime_result safely.
        """
        if not isinstance(runtime_result, dict):
            return self._empty()

        def safe_list(val) -> List[str]:
            if isinstance(val, (list, set, tuple)):
                return [str(item) for item in val if item is not None]
            if isinstance(val, str):
                return [val]
            return []

        # Start with forensics if available
        forensics_iocs = runtime_result.get("forensics", {}).get("iocs", {})
        urls = safe_list(forensics_iocs.get("urls"))
        ips = safe_list(forensics_iocs.get("ips"))
        domains = safe_list(forensics_iocs.get("domains"))
        suspicious_strings = safe_list(forensics_iocs.get("suspicious_strings"))

        # Fallback to older format
        network = runtime_result.get("network")
        if isinstance(network, dict):
            urls.extend(safe_list(network.get("urls")))
            ips.extend(safe_list(network.get("ips")))
            domains.extend(safe_list(network.get("domains")))

        # Get logs and evidence for fallback parsing
        logs_obj = runtime_result.get("logs")
        log_lines = []
        if isinstance(logs_obj, dict):
            log_lines = logs_obj.get("lines", [])
        elif isinstance(logs_obj, list):
            log_lines = logs_obj
        elif isinstance(logs_obj, str):
            log_lines = logs_obj.splitlines()

        raw_logs = runtime_result.get("raw_logs")
        if isinstance(raw_logs, str) and raw_logs:
            log_lines.extend(raw_logs.splitlines())

        evidence = safe_list(runtime_result.get("evidence", []))
        behaviors = safe_list(runtime_result.get("behaviors", []))

        # Log raw logcat size before parsing
        logger.info(f"IOCExtractor: Parsing {len(log_lines)} raw log lines and {len(evidence)} evidence strings")

        # Ensure dynamic_iocs is never empty if evidence exists
        if evidence:
            suspicious_strings.extend(evidence)

        text_sources = log_lines + evidence + behaviors

        for line in text_sources:
            if not isinstance(line, str):
                continue
            
            # Extract URLs
            for match in self.url_pattern.findall(line):
                urls.append(match)
            
            # Extract domains from http/s URLs
            for match in self.domain_pattern.findall(line):
                domains.append(match)
                
            # Extract bare domains
            for match in self.bare_domain_pattern.findall(line):
                domains.append(match)
            
            # Extract IPs
            for match in self.ip_pattern.findall(line):
                ips.append(match)

            # Extra signals from behaviors/logs
            line_lower = line.lower()
            if "sms" in line_lower:
                suspicious_strings.append("SMS_BEHAVIOR")
            if "login" in line_lower:
                suspicious_strings.append("AUTH_ACTIVITY")
            if "file" in line_lower:
                suspicious_strings.append("FILE_ACCESS")
            if "network" in line_lower:
                suspicious_strings.append("NETWORK_ACTIVITY")

        # Clean and filter
        # Clean and filter
        def is_system_domain(d: str) -> bool:
            d_lower = d.lower()
            return any(x in d_lower for x in ["google.com", "gstatic.com", "android.com", "googleapis.com", "gvt1.com"])
            
        def is_internal_ip(i: str) -> bool:
            return i == "127.0.0.1" or i == "10.0.2.2" or i.startswith("192.168.")
            
        def is_noisy_string(s: str) -> bool:
            s_lower = s.lower()
            blacklist = [
                "activitymanager", "binder", "android.", "com.google.", 
                "system_server", "zygote", "looper", "choreographer",
                "strictmode", "viewrootimpl", "dalvik", "art", "zygote64"
            ]
            return any(x in s_lower for x in blacklist)

        raw_urls_count = len(urls)
        raw_ips_count = len(ips)
        raw_domains_count = len(domains)
        raw_suspicious_count = len(suspicious_strings)

        final_urls = [u for u in sorted(list(set(urls))) if not is_system_domain(u)]
        final_ips = [i for i in sorted(list(set(ips))) if not is_internal_ip(i)]
        final_domains = [d for d in sorted(list(set(domains))) if not is_system_domain(d) and not is_noisy_string(d)]
        final_suspicious_strings = [s for s in sorted(list(set(suspicious_strings))) if not is_noisy_string(s)]

        # Log regex matches count per IOC type
        logger.info(f"IOCExtractor Raw Extracted: {raw_urls_count} URLs, {raw_ips_count} IPs, {raw_domains_count} Domains, {raw_suspicious_count} Suspicious Strings")
        # Log final IOC output before DB insertion (after filtering)
        logger.info(f"IOCExtractor Filtered Final Output - URLs: {len(final_urls)}, IPs: {len(final_ips)}, Domains: {len(final_domains)}, Suspicious Strings: {len(final_suspicious_strings)}")
        logger.info(f"Noise Filter removed: {raw_urls_count - len(final_urls)} URLs, {raw_ips_count - len(final_ips)} IPs, {raw_domains_count - len(final_domains)} Domains, {raw_suspicious_count - len(final_suspicious_strings)} Suspicious Strings")

        return {
            "urls": final_urls,
            "ips": final_ips,
            "domains": final_domains,
            "suspicious_strings": final_suspicious_strings
        }

    def _empty(self) -> Dict[str, List[str]]:
        return {
            "urls": [],
            "ips": [],
            "domains": [],
            "suspicious_strings": []
        }
