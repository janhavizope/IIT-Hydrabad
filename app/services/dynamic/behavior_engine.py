"""
Explainable malware behavior classification engine (deterministic, rule-based).
"""

from __future__ import annotations

import math
import re
from typing import Any

from app.services.dynamic.forensics import build_timeline, extract_iocs

EVENT_WEIGHTS: dict[str, int] = {
    "activity": 5,
    "network": 10,
    "permission": 20,
    "error": 15,
    "system": 2,
}

SCORED_EVENT_TYPES = tuple(EVENT_WEIGHTS.keys())
MAX_RISK_SCORE = 100
MAX_PATTERN_DIVISOR = 3

NETWORK_BURST_THRESHOLD = 5
NETWORK_BURST_BONUS = 15
PERMISSION_ABUSE_THRESHOLD = 3
PERMISSION_ABUSE_BONUS = 10
CRASH_LOOP_THRESHOLD = 2
CRASH_LOOP_BONUS = 10

RISK_LOW_MAX = 30
RISK_MEDIUM_MAX = 60

TEMPORAL_RECENT_COUNT = 5
TEMPORAL_RECENT_MULTIPLIER = 1.5
TEMPORAL_OLDER_MULTIPLIER = 1.0

PATTERN_EVIDENCE_MAP: dict[str, str] = {
    "DATA_EXFILTRATION_PATTERN": "Multiple network events detected after permission grant",
    "PRIVILEGE_ESCALATION_ATTEMPT": (
        "Permission activity followed by runtime error and renewed permission requests"
    ),
    "COMMAND_CONTROL_BEHAVIOR": "Sustained consecutive network communications detected",
}

FLAG_EVIDENCE_MAP: dict[str, str] = {
    "PERMISSION_ABUSE": "Sensitive permissions triggered without visible user action",
    "CRASH_LOOP": "Repeated error/fatal logs detected in short time window",
    "NETWORK_BURST": "Network event burst exceeds normal application baseline",
}

_DOMAIN_PATTERN = re.compile(r"https?://([^/\s:?#]+)", re.IGNORECASE)


def _event_signature(event: dict[str, Any]) -> tuple[str, str]:
    tag = (event.get("tag") or "").strip()
    message = (event.get("message") or "").strip()
    return tag, message


def _deduplicate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for event in events:
        signature = _event_signature(event)
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(event)
    return unique


def _event_type_sequence(events: list[dict[str, Any]]) -> list[str]:
    return [(event.get("event_type") or "unknown").lower() for event in events]


def extract_network_domains(events: list[dict[str, Any]]) -> list[str]:
    """Extract hostnames from network-related log messages."""
    domains: list[str] = []
    for event in events:
        if (event.get("event_type") or "").lower() != "network":
            continue
        message = event.get("message") or ""
        for match in _DOMAIN_PATTERN.findall(message):
            host = match.strip().lower()
            if host and host not in domains:
                domains.append(host)
    return domains


def _sample_log_evidence(events: list[dict[str, Any]], event_type: str, limit: int = 2) -> list[str]:
    samples: list[str] = []
    for event in events:
        if (event.get("event_type") or "").lower() != event_type:
            continue
        tag = event.get("tag") or "unknown"
        message = (event.get("message") or "").strip()
        if len(message) > 140:
            message = message[:137] + "..."
        samples.append(f"Log sample [{tag}]: {message}")
        if len(samples) >= limit:
            break
    return samples


def detect_attack_chain(events: list[dict[str, Any]]) -> list[str]:
    """Detect ordered attack-chain patterns in parsed session events."""
    types = _event_type_sequence(events)
    detected: list[str] = []

    for index in range(len(types) - 2):
        first, second, third = types[index], types[index + 1], types[index + 2]

        if first == "permission" and second == "network" and third == "network":
            detected.append("DATA_EXFILTRATION_PATTERN")

        if first == "permission" and second == "error" and third == "permission":
            detected.append("PRIVILEGE_ESCALATION_ATTEMPT")

        if first == "network" and second == "network" and third == "network":
            detected.append("COMMAND_CONTROL_BEHAVIOR")

    return list(dict.fromkeys(detected))


def build_evidence(
    events: list[dict[str, Any]],
    attack_patterns: list[str],
    risk_output: dict[str, Any],
) -> dict[str, list[str]]:
    """
    Map attack patterns and risk flags to human-readable supporting evidence.
    """
    evidence: list[str] = []
    flags = set(risk_output.get("flags") or [])
    event_counts = risk_output.get("event_counts") or {}

    for pattern in attack_patterns:
        mapped = PATTERN_EVIDENCE_MAP.get(pattern)
        if mapped:
            evidence.append(mapped)

        if pattern == "DATA_EXFILTRATION_PATTERN":
            evidence.extend(_sample_log_evidence(events, "permission", limit=1))
            evidence.extend(_sample_log_evidence(events, "network", limit=2))
        elif pattern == "PRIVILEGE_ESCALATION_ATTEMPT":
            evidence.extend(_sample_log_evidence(events, "permission", limit=1))
            evidence.extend(_sample_log_evidence(events, "error", limit=1))
        elif pattern == "COMMAND_CONTROL_BEHAVIOR":
            evidence.extend(_sample_log_evidence(events, "network", limit=3))

    for flag, mapped in FLAG_EVIDENCE_MAP.items():
        if flag in flags and mapped not in evidence:
            evidence.append(mapped)

    if "CRASH_LOOP" in flags:
        evidence.extend(_sample_log_evidence(events, "error", limit=2))

    if "PERMISSION_ABUSE" in flags:
        evidence.extend(_sample_log_evidence(events, "permission", limit=2))

    if "NETWORK_BURST" in flags:
        network_count = int(event_counts.get("network", 0))
        evidence.append(f"Observed {network_count} unique network-related log events in session")

    domains = extract_network_domains(events)
    for domain in domains[:3]:
        evidence.append(f"Network endpoint observed in logs: {domain}")

    return {"evidence": list(dict.fromkeys(evidence))}


def _burst_intensity(risk_output: dict[str, Any]) -> float:
    """Normalized burst intensity from network volume and burst flags."""
    flags = set(risk_output.get("flags") or [])
    event_counts = risk_output.get("event_counts") or {}
    network_count = int(event_counts.get("network", 0))

    if "NETWORK_BURST" not in flags:
        if network_count <= 0:
            return 0.0
        return min(network_count / float(NETWORK_BURST_THRESHOLD), 0.5)

    overflow = max(network_count - NETWORK_BURST_THRESHOLD, 0)
    return min(0.5 + (overflow / 10.0), 1.0)


def compute_confidence(
    risk_output: dict[str, Any],
    patterns: list[str],
    cross_session_boost: float = 0.0,
) -> float:
    """
    Derive normalized confidence (0.0-1.0) from risk score, patterns, and burst intensity.
    """
    risk_norm = min(max(int(risk_output.get("risk_score", 0)) / float(MAX_RISK_SCORE), 0.0), 1.0)
    pattern_factor = min(len(patterns) / float(MAX_PATTERN_DIVISOR), 1.0)
    burst_factor = _burst_intensity(risk_output)

    confidence = (0.5 * risk_norm) + (0.3 * pattern_factor) + (0.2 * burst_factor)
    confidence = min(1.0, confidence + min(max(cross_session_boost, 0.0), 0.05))
    return round(confidence, 3)


def classify_threat(
    risk_output: dict[str, Any],
    patterns: list[str],
    supporting_evidence: list[str] | None = None,
    cross_session_boost: float = 0.0,
) -> dict[str, Any]:
    """Classify malware threat type with derived confidence and evidence."""
    flags = set(risk_output.get("flags") or [])
    pattern_set = set(patterns)
    event_counts = risk_output.get("event_counts") or {}
    reasoning: list[str] = []

    network_count = int(event_counts.get("network", 0))
    system_count = int(event_counts.get("system", 0))
    threat_type = "Benign / Low Threat"

    if "NETWORK_BURST" in flags and "DATA_EXFILTRATION_PATTERN" in pattern_set:
        threat_type = "Spyware"
        reasoning.append("Network burst aligned with permission-to-network exfiltration chain")

    elif "PERMISSION_ABUSE" in flags and network_count > 0:
        threat_type = "Banking Trojan"
        reasoning.append("Permission abuse combined with outbound network activity")

    elif "CRASH_LOOP" in flags and system_count > 0:
        threat_type = "Stability Exploit Malware"
        reasoning.append("Crash loop with correlated system-level fault events")

    elif "NETWORK_BURST" in flags:
        threat_type = "Adware / Tracking SDK"
        reasoning.append("Network burst without privilege-escalation or exfiltration chain")

    elif pattern_set:
        threat_type = "Suspicious Behavioral Malware"
        reasoning.append(f"Attack chain indicators present: {', '.join(sorted(pattern_set))}")

    elif risk_output.get("risk_level") == "HIGH":
        threat_type = "Unclassified High-Risk Behavior"
        reasoning.append("High composite behavioral risk without a specific malware family signature")

    else:
        reasoning.append("Insufficient deterministic indicators for a specific malware class")

    confidence = compute_confidence(risk_output, patterns, cross_session_boost)
    if cross_session_boost > 0:
        reasoning.append(f"Cross-session recurrence increased confidence by {cross_session_boost:.2f}")

    return {
        "threat_type": threat_type,
        "confidence": confidence,
        "reasoning": reasoning,
        "supporting_evidence": list(supporting_evidence or []),
    }


def _risk_level_from_score(risk_score: int) -> str:
    if risk_score <= RISK_LOW_MAX:
        return "LOW"
    if risk_score <= RISK_MEDIUM_MAX:
        return "MEDIUM"
    return "HIGH"


def _temporal_weight(event_index: int, total_scored_events: int) -> float:
    if total_scored_events <= TEMPORAL_RECENT_COUNT:
        return TEMPORAL_RECENT_MULTIPLIER
    recent_start = total_scored_events - TEMPORAL_RECENT_COUNT
    if event_index >= recent_start:
        return TEMPORAL_RECENT_MULTIPLIER
    return TEMPORAL_OLDER_MULTIPLIER


def _score_events_with_temporal_weight(scored_events: list[dict[str, Any]]) -> int:
    total = len(scored_events)
    score = 0.0
    for index, event in enumerate(scored_events):
        event_type = (event.get("event_type") or "unknown").lower()
        base_weight = EVENT_WEIGHTS.get(event_type, 0)
        multiplier = _temporal_weight(index, total)
        score += base_weight * multiplier
    return int(min(math.floor(score), MAX_RISK_SCORE))


class BehaviorEngine:
    """Explainable malware behavior classification engine (MVP+++)."""

    def analyze(
        self,
        events: list[dict[str, Any]],
        cross_session_boost: float = 0.0,
    ) -> dict[str, Any]:
        """Score events, detect chains, build evidence, and classify threats."""
        deduped_events = _deduplicate_events(events)
        seen_signatures: set[tuple[str, str]] = {_event_signature(event) for event in deduped_events}

        scored_events = [
            event
            for event in deduped_events
            if (event.get("event_type") or "unknown").lower() in EVENT_WEIGHTS
        ]

        event_counts = {event_type: 0 for event_type in SCORED_EVENT_TYPES}
        for event in scored_events:
            event_type = (event.get("event_type") or "unknown").lower()
            event_counts[event_type] += 1

        flags: list[str] = []
        risk_score = _score_events_with_temporal_weight(scored_events)

        if event_counts["permission"] > 0:
            flags.append("permission_events_detected")
        if event_counts["network"] > 0:
            flags.append("network_activity_detected")
        if event_counts["error"] > 0:
            flags.append("runtime_errors_detected")
        if event_counts["activity"] > 0:
            flags.append("activity_lifecycle_events_detected")
        if event_counts["system"] > 0:
            flags.append("system_events_detected")

        if event_counts["network"] > NETWORK_BURST_THRESHOLD:
            risk_score += NETWORK_BURST_BONUS
            flags.append("NETWORK_BURST")

        if event_counts["permission"] > PERMISSION_ABUSE_THRESHOLD:
            risk_score += PERMISSION_ABUSE_BONUS
            flags.append("PERMISSION_ABUSE")

        if event_counts["error"] >= CRASH_LOOP_THRESHOLD:
            risk_score += CRASH_LOOP_BONUS
            flags.append("CRASH_LOOP")

        risk_score = min(risk_score, MAX_RISK_SCORE)
        risk_level = _risk_level_from_score(risk_score)
        attack_patterns = detect_attack_chain(deduped_events)

        risk_output = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flags": flags,
            "event_counts": event_counts,
            "deduplicated_event_count": len(deduped_events),
            "raw_event_count": len(events),
            "dedupe_signatures": [f"{tag}|{message}" for tag, message in sorted(seen_signatures)],
            "network_domains": extract_network_domains(deduped_events),
            "temporal_weighting": {
                "recent_event_count": min(TEMPORAL_RECENT_COUNT, len(scored_events)),
                "recent_multiplier": TEMPORAL_RECENT_MULTIPLIER,
                "older_multiplier": TEMPORAL_OLDER_MULTIPLIER,
            },
        }

        evidence_bundle = build_evidence(deduped_events, attack_patterns, risk_output)
        evidence_list = evidence_bundle.get("evidence", [])

        threat_classification = classify_threat(
            risk_output,
            attack_patterns,
            supporting_evidence=evidence_list,
            cross_session_boost=cross_session_boost,
        )

        forensics = {
            "timeline": build_timeline(deduped_events),
            "iocs": extract_iocs(deduped_events),
        }

        return {
            **risk_output,
            "attack_patterns": attack_patterns,
            "threat_classification": threat_classification,
            "evidence": evidence_list,
            "forensics": forensics,
        }

    def generate_summary(
        self,
        events: list[dict[str, Any]],
        risk_output: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a rule-based security intelligence summary (no AI/LLM)."""
        event_counts = risk_output.get("event_counts") or {}
        flags = risk_output.get("flags") or []
        risk_level = risk_output.get("risk_level", "LOW")
        risk_score = risk_output.get("risk_score", 0)
        threat = risk_output.get("threat_classification") or {}
        attack_patterns = risk_output.get("attack_patterns") or []
        evidence = risk_output.get("evidence") or []

        permission_count = int(event_counts.get("permission", 0))
        network_count = int(event_counts.get("network", 0))
        error_count = int(event_counts.get("error", 0))
        activity_count = int(event_counts.get("activity", 0))

        permission_high = permission_count >= 2 or "PERMISSION_ABUSE" in flags
        network_high = network_count >= 3 or "NETWORK_BURST" in flags
        errors_high = error_count >= 2 or "CRASH_LOOP" in flags

        top_risks: list[str] = []
        attack_surface: list[str] = []

        if permission_high:
            top_risks.append("Sensitive permission abuse possible")
            attack_surface.append("permissions")

        if network_high and permission_high:
            top_risks.append("Data exfiltration risk")
            attack_surface.append("network_exfiltration")
        elif network_high:
            top_risks.append("Elevated outbound network activity")
            attack_surface.append("network")

        if errors_high:
            top_risks.append("Stability / crash exploitation risk")
            attack_surface.append("runtime_errors")

        if activity_count > 0:
            attack_surface.append("activity_lifecycle")

        if attack_patterns:
            top_risks.append("Attack chain detected: " + ", ".join(attack_patterns))

        confidence = threat.get("confidence", 0.0)
        if threat.get("threat_type"):
            top_risks.append(
                f"Threat classification: {threat['threat_type']} "
                f"(confidence {confidence:.2f})"
            )

        if evidence:
            top_risks.append(f"{len(evidence)} supporting evidence item(s) recorded")

        if "NETWORK_BURST" in flags and "Data exfiltration risk" not in top_risks:
            top_risks.append("Network burst pattern detected")

        if not top_risks:
            if risk_level == "HIGH":
                top_risks.append("High composite behavioral risk score")
            elif risk_level == "MEDIUM":
                top_risks.append("Moderate behavioral anomalies detected")
            else:
                top_risks.append("No significant malware indicators in session logs")

        attack_surface = list(dict.fromkeys(attack_surface))

        summary_parts = [
            f"Dynamic session risk: {risk_level} (score {risk_score}/100).",
            f"Unique events analyzed: {risk_output.get('deduplicated_event_count', len(events))}.",
        ]
        if top_risks:
            summary_parts.append("Primary concerns: " + "; ".join(top_risks) + ".")
        else:
            summary_parts.append("No primary threat patterns identified.")

        return {
            "summary": " ".join(summary_parts),
            "top_risks": top_risks,
            "attack_surface": attack_surface,
        }
