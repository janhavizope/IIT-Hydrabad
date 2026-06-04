from __future__ import annotations

import re

from app.models.analysis_context import AnalysisContext


class DeepStaticAnalyzer:
    """Simple static APK analyzer for suspicious patterns."""

    def analyze(self, context: AnalysisContext):
        """Analyze a shared lightweight context and return suspicious pattern matches."""
        result = {
            "suspicious_urls": [],
            "suspicious_apis": [],
            "crypto_usage": [],
            "obfuscation_signs": [],
            "risk_indicators_count": 0,
        }

        extracted_text = self._collect_context_text(context)

        result["suspicious_urls"] = self._find_suspicious_urls(extracted_text)
        result["suspicious_apis"] = self._find_keywords(
            extracted_text,
            ["DexClassLoader", "Class.forName", "Runtime.exec", "TelephonyManager", "SmsManager"],
        )
        result["crypto_usage"] = self._find_keywords(extracted_text, ["Cipher", "MessageDigest"])
        result["obfuscation_signs"] = self._find_keywords(extracted_text, ["base64", "decode", "encrypt", "xor"])
        result["risk_indicators_count"] = self._count_indicators(result)

        return result

    def _collect_context_text(self, context: AnalysisContext):
        collected = []

        collected.extend(self._normalize_values(getattr(context, "strings", []) or []))
        collected.extend(self._normalize_values(getattr(context, "package_name", "") or ""))
        collected.extend(self._normalize_values(getattr(context, "permissions", []) or []))
        collected.extend(self._normalize_values(getattr(context, "main_activities", []) or []))
        collected.extend(self._normalize_values(getattr(context, "metadata", {}) or {}))

        return self._unique_list(collected)

    def _find_suspicious_urls(self, text_items: list[str]):
        matches = []
        url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        for item in text_items:
            matches.extend(url_pattern.findall(item))
            matches.extend(ip_pattern.findall(item))

        return self._unique_list(matches)

    def _find_keywords(self, text_items: list[str], keywords: list[str]):
        matches = []
        lowered_keywords = {keyword.lower(): keyword for keyword in keywords}

        for item in text_items:
            lower_item = item.lower()
            for keyword_lower, keyword_original in lowered_keywords.items():
                if keyword_lower in lower_item:
                    matches.append(keyword_original)

        return self._unique_list(matches)

    def _count_indicators(self, result: dict):
        return len(result["suspicious_urls"]) + len(result["suspicious_apis"]) + len(result["crypto_usage"]) + len(result["obfuscation_signs"])

    def _normalize_values(self, value):
        if value is None:
            return []

        if isinstance(value, bytes):
            try:
                return [value.decode("utf-8", errors="ignore")]
            except Exception:
                return []

        if isinstance(value, str):
            return [value]

        if isinstance(value, dict):
            collected = []
            for key, item in value.items():
                collected.extend(self._normalize_values(key))
                collected.extend(self._normalize_values(item))
            return collected

        if isinstance(value, (list, tuple, set)):
            collected = []
            for item in value:
                collected.extend(self._normalize_values(item))
            return collected

        return [str(value)]

    def _unique_list(self, items: list[str]):
        unique_items = []
        seen = set()

        for item in items:
            cleaned = str(item).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                unique_items.append(cleaned)

        return unique_items
