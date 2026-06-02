"""
Threat narrative generator — presentation layer only (no scoring changes).
"""

from __future__ import annotations

from typing import Any

_PATTERN_NARRATIVES: dict[str, str] = {
    "DATA_EXFILTRATION_PATTERN": (
        "Observed permission grant followed by repeated outbound network activity."
    ),
    "PRIVILEGE_ESCALATION_ATTEMPT": (
        "Permission and error events formed a privilege-escalation style sequence."
    ),
    "COMMAND_CONTROL_BEHAVIOR": (
        "Sustained back-to-back network communications suggest command-and-control style behavior."
    ),
}


def _has_permission_signal(threat_intelligence: dict[str, Any]) -> bool:
    evidence = threat_intelligence.get("evidence") or []
    patterns = threat_intelligence.get("attack_patterns") or []
    timeline = (threat_intelligence.get("forensics") or {}).get("timeline") or []

    if any("permission" in str(item).lower() for item in evidence):
        return True
    if "DATA_EXFILTRATION_PATTERN" in patterns or "PRIVILEGE_ESCALATION_ATTEMPT" in patterns:
        return True
    return any(entry.get("event_type") == "permission" for entry in timeline)


def _has_network_spike_signal(threat_intelligence: dict[str, Any]) -> bool:
    evidence = threat_intelligence.get("evidence") or []
    patterns = threat_intelligence.get("attack_patterns") or []
    timeline = (threat_intelligence.get("forensics") or {}).get("timeline") or []

    if any("network burst" in str(item).lower() for item in evidence):
        return True
    if any("network" in str(item).lower() for item in evidence):
        if "DATA_EXFILTRATION_PATTERN" in patterns or "COMMAND_CONTROL_BEHAVIOR" in patterns:
            return True
    return any(
        "network burst" in str(entry.get("summary", "")).lower()
        for entry in timeline
    )


def _timeline_highlights(timeline: list[dict[str, Any]], limit: int = 2) -> list[str]:
    highlights: list[str] = []
    for entry in timeline:
        summary = (entry.get("summary") or "").strip()
        if not summary:
            continue
        time_label = entry.get("time") or "unknown-time"
        highlights.append(f"At {time_label}: {summary}")
        if len(highlights) >= limit:
            break
    return highlights


def build_threat_story(threat_intelligence: dict[str, Any]) -> dict[str, list[str]]:
    """
    Convert structured threat intelligence into a human-readable attack narrative.

    Derived only from existing fields (attack_patterns, timeline, evidence, risk_level).
    """
    narrative: list[str] = []
    attack_patterns = list(threat_intelligence.get("attack_patterns") or [])
    evidence = list(threat_intelligence.get("evidence") or [])
    risk_level = str(threat_intelligence.get("risk_level") or "LOW").upper()
    risk_score = int(threat_intelligence.get("risk_score") or 0)
    forensics = threat_intelligence.get("forensics") or {}
    timeline = list(forensics.get("timeline") or [])
    threat_classification = threat_intelligence.get("threat_classification") or {}
    threat_type = threat_classification.get("threat_type")

    narrative.append("App installation initiated in sandbox environment.")

    if _has_permission_signal(threat_intelligence):
        narrative.append("Sensitive permissions requested without user interaction.")

    if _has_network_spike_signal(threat_intelligence):
        narrative.append("Network activity spike detected shortly after permission grant.")

    for pattern in attack_patterns:
        line = _PATTERN_NARRATIVES.get(pattern)
        if line and line not in narrative:
            narrative.append(line)

    for highlight in _timeline_highlights(timeline):
        if highlight not in narrative:
            narrative.append(highlight)

    for item in evidence[:2]:
        if item not in narrative:
            narrative.append(f"Supporting indicator: {item}")

    if threat_type and threat_type not in ("Benign / Low Threat",):
        narrative.append(f"Behavior classified as {threat_type} based on coordinated indicators.")
    else:
        narrative.append(
            f"Behavior classified as {risk_level} risk (score {risk_score}/100) due to coordinated pattern."
        )

    if risk_level == "HIGH" and not any("HIGH risk" in line for line in narrative):
        narrative.append("Overall session posture assessed as HIGH risk for potential malware activity.")
    elif risk_level == "MEDIUM":
        narrative.append("Overall session posture assessed as MEDIUM risk requiring further review.")

    return {"narrative": narrative}
