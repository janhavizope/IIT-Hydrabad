"""
Visualization data builder — dashboard presentation layer only.

Reads threat_intelligence fields as-is. Does not compute risk scores or
modify analysis/forensics logic.
"""

from __future__ import annotations

from typing import Any

TIMELINE_PREVIEW_LIMIT = 8

_ALLOWED_FLOW_TYPES = frozenset({"permission", "network", "error", "system", "fusion"})

_EVENT_TYPE_TO_FLOW_TYPE: dict[str, str] = {
    "permission": "permission",
    "network": "network",
    "error": "error",
    "system": "system",
    "activity": "system",
}

_PATTERN_ATTACK_STEPS: dict[str, str] = {
    "DATA_EXFILTRATION_PATTERN": "Data exfiltration pattern detected in session",
    "PRIVILEGE_ESCALATION_ATTEMPT": "Privilege escalation attempt detected in session",
    "COMMAND_CONTROL_BEHAVIOR": "Command-and-control style network behavior detected",
}


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _event_summary(threat_intelligence: dict[str, Any]) -> dict[str, int]:
    session_state = _safe_dict(threat_intelligence.get("session_state"))
    counts = _safe_dict(session_state.get("event_counts"))

    if counts:
        return {
            "activity_count": int(counts.get("activity") or 0),
            "network_count": int(counts.get("network") or 0),
            "permission_count": int(counts.get("permission") or 0),
            "error_count": int(counts.get("error") or 0),
        }

    timeline = _safe_list(_safe_dict(threat_intelligence.get("forensics")).get("timeline"))
    summary = {
        "activity_count": 0,
        "network_count": 0,
        "permission_count": 0,
        "error_count": 0,
    }
    type_to_field = {
        "activity": "activity_count",
        "network": "network_count",
        "permission": "permission_count",
        "error": "error_count",
    }

    for entry in timeline:
        if not isinstance(entry, dict):
            continue
        field = type_to_field.get((entry.get("event_type") or "").lower())
        if field:
            summary[field] += 1

    return summary


def _normalize_flow_type(event_type: str) -> str | None:
    mapped = _EVENT_TYPE_TO_FLOW_TYPE.get((event_type or "").lower())
    if mapped in _ALLOWED_FLOW_TYPES:
        return mapped
    return None


def _build_attack_flow(threat_intelligence: dict[str, Any]) -> list[dict[str, str]]:
    flow: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    timeline = _safe_list(_safe_dict(threat_intelligence.get("forensics")).get("timeline"))
    for entry in timeline:
        if not isinstance(entry, dict):
            continue

        flow_type = _normalize_flow_type(str(entry.get("event_type") or ""))
        if not flow_type:
            continue

        step = str(entry.get("summary") or "").strip()
        if not step:
            event_type = (entry.get("event_type") or "unknown").lower()
            step = f"{event_type} event observed"

        key = (step, flow_type)
        if key in seen:
            continue
        seen.add(key)
        flow.append({"step": step, "type": flow_type})

    for pattern in _safe_list(threat_intelligence.get("attack_patterns")):
        pattern_name = str(pattern or "").strip()
        if not pattern_name:
            continue

        step = _PATTERN_ATTACK_STEPS.get(
            pattern_name,
            pattern_name.replace("_", " ").strip().capitalize(),
        )
        key = (step, "fusion")
        if key in seen:
            continue
        seen.add(key)
        flow.append({"step": step, "type": "fusion"})

    return flow


def _timeline_preview(threat_intelligence: dict[str, Any]) -> list[dict[str, str]]:
    timeline = _safe_list(_safe_dict(threat_intelligence.get("forensics")).get("timeline"))
    preview: list[dict[str, str]] = []

    for entry in timeline[:TIMELINE_PREVIEW_LIMIT]:
        if not isinstance(entry, dict):
            continue
        preview.append(
            {
                "event_type": str(entry.get("event_type") or "unknown"),
                "summary": str(entry.get("summary") or ""),
            }
        )

    return preview


def _ioc_summary(threat_intelligence: dict[str, Any]) -> dict[str, int]:
    iocs = _safe_dict(_safe_dict(threat_intelligence.get("forensics")).get("iocs"))
    return {
        "domain_count": len(_safe_list(iocs.get("domains"))),
        "ip_count": len(_safe_list(iocs.get("ips"))),
        "suspicious_string_count": len(_safe_list(iocs.get("suspicious_strings"))),
    }


def build_visualization_data(threat_intelligence: dict[str, Any] | None) -> dict[str, Any]:
    """
    Transform threat intelligence into a dashboard-friendly visualization payload.

    Presentation only: reads existing fields, never recomputes risk scores.
    """
    threat_intelligence = _safe_dict(threat_intelligence)

    return {
        "risk_overview": {
            "risk_score": int(threat_intelligence.get("risk_score") or 0),
            "risk_level": str(threat_intelligence.get("risk_level") or "LOW"),
        },
        "event_summary": _event_summary(threat_intelligence),
        "attack_flow": _build_attack_flow(threat_intelligence),
        "timeline_preview": _timeline_preview(threat_intelligence),
        "ioc_summary": _ioc_summary(threat_intelligence),
    }
