"""
Four-tier IOC classification with deduplication and deterministic ordering.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from app.services.core.assessment.constants import (
    DOMAIN_PATTERN,
    HIGH_IOC_VOLUME_THRESHOLD,
    IP_PATTERN,
    MALICIOUS_IOC_KEYWORDS,
    OBFUSCATION_MARKERS,
    PRIVATE_IP_PREFIXES,
    SECRET_PATTERNS,
    TRUSTED_DOMAIN_PREFIXES,
    URL_PATTERN,
)


def ioc_signature(ioc_type: str, value: str) -> str:
    """Stable signature for deduplication."""
    raw = f"{ioc_type}:{value.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_trusted_domain(host: str) -> bool:
    lowered = host.strip().lower().rstrip(".")
    if lowered in ("localhost", "android", "example.com"):
        return True
    return any(lowered.startswith(p) for p in TRUSTED_DOMAIN_PREFIXES)


def _is_private_ip(ip: str) -> bool:
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return True
    return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)


def _has_malicious_keyword(value: str) -> bool:
    lowered = value.lower()
    return any(kw in lowered for kw in MALICIOUS_IOC_KEYWORDS)


def _is_obfuscated_host(host: str) -> bool:
    lowered = host.lower()
    if len(lowered) > 48:
        return True
    if lowered.count("-") > 4:
        return True
    if re.search(r"\d{4,}", lowered):
        return True
    consonants = sum(1 for c in lowered if c.isalpha() and c not in "aeiou")
    if len(lowered) > 12 and consonants / max(len(lowered), 1) > 0.75:
        return True
    return False


def classify_domain(host: str) -> str:
    lowered = host.strip().lower()
    if _is_trusted_domain(lowered):
        return "TRUSTED"
    if _has_malicious_keyword(lowered):
        return "MALICIOUS"
    if _is_obfuscated_host(lowered):
        return "SUSPICIOUS"
    return "NEUTRAL"


def classify_string(text: str) -> str:
    if _has_malicious_keyword(text):
        return "MALICIOUS"
    if any(p.search(text) for p in SECRET_PATTERNS):
        return "SUSPICIOUS"
    if any(m in text.lower() for m in OBFUSCATION_MARKERS):
        return "SUSPICIOUS"
    return "NEUTRAL"


def classify_ip(ip: str) -> str:
    if _is_private_ip(ip):
        return "TRUSTED"
    return "NEUTRAL"


def _sort_tiers(tiers: dict[str, list[dict[str, str]]]) -> dict[str, list[dict[str, str]]]:
    for tier in ("TRUSTED", "NEUTRAL", "SUSPICIOUS", "MALICIOUS"):
        items = tiers.get(tier) or []
        items.sort(key=lambda x: (x.get("value", "").lower(), x.get("type", "")))
        tiers[tier] = items
    return tiers


def _extract_iocs_from_events(
    events: list[dict[str, Any]],
    add: Any,
) -> None:
    for event in events or []:
        message = str(event.get("message") or "")
        for url in URL_PATTERN.findall(message):
            host_match = re.search(r"https?://([^/\s:?#]+)", url, re.I)
            host = host_match.group(1).lower() if host_match else ""
            if not host:
                continue
            tier = classify_domain(host)
            if tier in ("SUSPICIOUS", "MALICIOUS"):
                add(tier, "url", url, "log_event")
            elif tier == "NEUTRAL":
                add("NEUTRAL", "url", url, "log_event")

        for domain in DOMAIN_PATTERN.findall(message):
            if not _is_trusted_domain(domain):
                add(classify_domain(domain), "domain", domain, "log_event")

        for ip in IP_PATTERN.findall(message):
            tier = classify_ip(ip)
            if tier == "NEUTRAL":
                add("NEUTRAL", "ip", ip, "log_event")


def ioc_metadata(tiers: dict[str, list[dict[str, str]]]) -> dict[str, Any]:
    total = sum(len(tiers.get(t) or []) for t in ("TRUSTED", "NEUTRAL", "SUSPICIOUS", "MALICIOUS"))
    return {
        "total_count": total,
        "high_volume": total > HIGH_IOC_VOLUME_THRESHOLD,
        "scoreable_count": len(tiers.get("SUSPICIOUS") or []) + len(tiers.get("MALICIOUS") or []),
    }


def categorize_iocs(
    raw_iocs: dict[str, Any] | None,
    filtered_events: list[dict[str, Any]] | None = None,
    static_urls: list[str] | None = None,
    ioc_events: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """
    Classify IOCs into tiers. TRUSTED/NEUTRAL never affect scoring.

    Deduplicates by hash(signature); output tiers sorted alphabetically by value.
    ioc_events may include APP_EVENT + SYSTEM_ABUSE log lines.
    """
    raw_iocs = raw_iocs or {}
    tiers: dict[str, list[dict[str, str]]] = {
        "TRUSTED": [],
        "NEUTRAL": [],
        "SUSPICIOUS": [],
        "MALICIOUS": [],
    }
    seen_hashes: set[str] = set()

    def add(tier: str, ioc_type: str, value: str, source: str) -> None:
        value = value.strip()
        if not value:
            return
        sig = ioc_signature(ioc_type, value)
        if sig in seen_hashes:
            return
        seen_hashes.add(sig)
        tiers[tier].append({"type": ioc_type, "value": value, "source": source})

    for domain in raw_iocs.get("domains") or []:
        host = str(domain).strip().lower()
        add(classify_domain(host), "domain", host, "forensics")

    for ip in raw_iocs.get("ips") or []:
        ip_str = str(ip).strip()
        add(classify_ip(ip_str), "ip", ip_str, "forensics")

    for url in list(raw_iocs.get("urls") or []) + list(static_urls or []):
        url_str = str(url).strip()
        if not url_str:
            continue
        host_match = re.search(r"https?://([^/\s:?#]+)", url_str, re.I)
        host = host_match.group(1).lower() if host_match else ""
        if host:
            tier = classify_domain(host)
            if tier == "TRUSTED":
                add("TRUSTED", "url", url_str, "static")
            else:
                add(tier, "url", url_str, "static")
        else:
            add("NEUTRAL", "url", url_str, "static")

    for raw_string in raw_iocs.get("suspicious_strings") or []:
        text = str(raw_string).strip()
        if text:
            add(classify_string(text), "string", text[:200], "forensics")

    log_events = ioc_events if ioc_events is not None else filtered_events
    _extract_iocs_from_events(log_events or [], add)

    return _sort_tiers(tiers)


def ioc_distribution(tiers: dict[str, list[dict[str, str]]]) -> dict[str, int]:
    return {tier: len(tiers.get(tier) or []) for tier in ("TRUSTED", "NEUTRAL", "SUSPICIOUS", "MALICIOUS")}


def ioc_entropy(tiers: dict[str, list[dict[str, str]]]) -> float:
    """Normalized Shannon entropy across tiers (0–1)."""
    import math

    counts = [len(tiers.get(t) or []) for t in ("TRUSTED", "NEUTRAL", "SUSPICIOUS", "MALICIOUS")]
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    max_entropy = math.log2(4)
    return entropy / max_entropy if max_entropy else 0.0
