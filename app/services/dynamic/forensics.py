"""
Forensic timeline reconstruction and IOC extraction (deterministic).
"""

from __future__ import annotations

import re
from typing import Any

_URL_DOMAIN_PATTERN = re.compile(r"https?://([^/\s:?#]+)", re.IGNORECASE)
_BARE_DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))\b",
)
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
)
_SUSPICIOUS_KEYWORDS = (
    "login",
    "auth",
    "token",
    "bank",
    "password",
    "credential",
    "oauth",
    "session",
    "apikey",
    "secret",
    "pin",
    "otp",
    "wallet",
    "transfer",
)

_NETWORK_BURST_GROUP_MIN = 3


def _timeline_time(event: dict[str, Any], index: int) -> str:
    timestamp = (event.get("timestamp") or "").strip()
    if timestamp:
        return timestamp
    return f"event-{index + 1}"


def _summarize_group(event_type: str, count: int, tag: str, sample_message: str) -> str:
    tag = tag or "unknown"
    message = (sample_message or "").strip()
    if len(message) > 100:
        message = message[:97] + "..."

    if event_type == "network" and count >= _NETWORK_BURST_GROUP_MIN:
        return f"Network burst detected ({count} requests in short interval)"

    if event_type == "network":
        if message:
            return f"Network activity via {tag}: {message}"
        return f"Network activity observed ({tag})"

    if event_type == "permission":
        if message:
            return f"Permission-related action ({tag}): {message}"
        return f"Permission-related action from {tag}"

    if event_type == "error":
        if message:
            return f"Runtime error ({tag}): {message}"
        return f"Runtime error logged by {tag}"

    if event_type == "activity":
        if message:
            return f"Activity lifecycle event ({tag}): {message}"
        return f"Activity lifecycle event from {tag}"

    if event_type == "system":
        if message:
            return f"System event ({tag}): {message}"
        return f"System event from {tag}"

    if count > 1:
        return f"{event_type} events grouped ({count}x) from {tag}"
    if message:
        return f"{event_type} event ({tag}): {message}"
    return f"{event_type} event from {tag}"


def build_timeline(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    """
    Build a chronological, human-readable forensic timeline.

    Consecutive events with the same type and tag are grouped into one entry.
    """
    timeline: list[dict[str, str]] = []
    if not events:
        return timeline

    group_type = ""
    group_tag = ""
    group_count = 0
    group_start_time = ""
    group_sample_message = ""

    def flush_group() -> None:
        if group_count <= 0:
            return
        timeline.append(
            {
                "time": group_start_time,
                "event_type": group_type,
                "summary": _summarize_group(group_type, group_count, group_tag, group_sample_message),
            }
        )

    for index, event in enumerate(events):
        event_type = (event.get("event_type") or "unknown").lower()
        tag = (event.get("tag") or "unknown").strip()
        group_key = (event_type, tag)

        if group_count == 0:
            group_type = event_type
            group_tag = tag
            group_count = 1
            group_start_time = _timeline_time(event, index)
            group_sample_message = event.get("message") or ""
            continue

        current_key = (group_type, group_tag)
        if current_key == group_key:
            group_count += 1
            continue

        flush_group()
        group_type = event_type
        group_tag = tag
        group_count = 1
        group_start_time = _timeline_time(event, index)
        group_sample_message = event.get("message") or ""

    flush_group()
    return timeline


def _is_plausible_domain(value: str) -> bool:
    lowered = value.lower()
    if lowered in ("localhost", "android", "example.com"):
        return False
    if "." not in lowered:
        return False
    return True


def _is_plausible_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def extract_iocs(events: list[dict[str, Any]]) -> dict[str, list[str]]:
    """
    Extract indicators of compromise from parsed log events.
    """
    domains: list[str] = []
    ips: list[str] = []
    suspicious_strings: list[str] = []

    for event in events:
        message = event.get("message") or ""
        tag = event.get("tag") or ""
        combined = f"{tag} {message}"

        for match in _URL_DOMAIN_PATTERN.findall(message):
            host = match.strip().lower()
            if _is_plausible_domain(host) and host not in domains:
                domains.append(host)

        for match in _BARE_DOMAIN_PATTERN.findall(message):
            host = match.strip().lower()
            if _is_plausible_domain(host) and host not in domains:
                domains.append(host)

        for match in _IPV4_PATTERN.findall(message):
            if _is_plausible_ip(match) and match not in ips:
                if match not in ("127.0.0.1", "0.0.0.0"):
                    ips.append(match)

        lowered = combined.lower()
        for keyword in _SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                indicator = f"{keyword}: {message.strip()[:120]}" if message.strip() else keyword
                if indicator not in suspicious_strings:
                    suspicious_strings.append(indicator)

    return {
        "domains": domains,
        "ips": ips,
        "suspicious_strings": suspicious_strings,
    }
