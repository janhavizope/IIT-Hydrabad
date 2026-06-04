"""
Deterministic attack-chain validation and false-positive signal detection.

Uses variable-length windows (3–6 events), composite scoring, and calibrated
confidence adjustment. Does not modify behavior_engine or forensics.
"""

from __future__ import annotations

import re
from typing import Any

SENSITIVE_API_KEYWORDS = (
    "telephony",
    "smsmanager",
    "sms",
    "runtime.exec",
    "processbuilder",
    "dexclassloader",
    "class.forname",
    "method.invoke",
    "crypto",
    "cipher",
    "secret",
    "password",
    "credential",
    "token",
    "oauth",
    "getdeviceid",
    "getsubscriberid",
)

SYSTEM_APP_MARKERS = (
    "com.google",
    "com.android.",
    "android.gms",
    "gms.",
    "system_server",
    "systemui",
    "googleplay",
    "firebase",
)

LOGIN_SESSION_MARKERS = (
    "login",
    "signin",
    "sign in",
    "session",
    "authenticate",
    "auth token",
)

TELEMETRY_SYNC_MARKERS = (
    "sync",
    "telemetry",
    "analytics",
    "firebase",
    "gms",
    "jobscheduler",
    "workmanager",
    "push",
)

_DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))\b",
)
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
)

MIN_CHAIN_LEN = 3
MAX_CHAIN_LEN = 6
MALICIOUS_SCORE_THRESHOLD = 6
SYSTEM_ACTIVITY_DOMINANCE_RATIO = 0.60
NOISE_RESISTANCE_SYSTEM_RATIO = 0.70
BENIGN_BEHAVIOR_CONFIDENCE_THRESHOLD = 6
BENIGN_CONFIDENCE_PENALTY = 0.2
MIN_SESSION_EVENTS = 3

SCORE_PERMISSION = 2
SCORE_NETWORK = 2
SCORE_IOC = 3
SCORE_SENSITIVE_API = 3
SCORE_SYSTEM_DOMINANCE_PENALTY = 2

CONFIDENCE_MIN = -0.3
CONFIDENCE_MAX = 0.3


def _normalize_events(events: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        normalized.append(
            {
                "timestamp": str(event.get("timestamp") or ""),
                "event_type": str(event.get("event_type") or "unknown").lower(),
                "tag": str(event.get("tag") or ""),
                "message": str(event.get("message") or ""),
            }
        )
    return normalized


def _event_text(event: dict[str, Any]) -> str:
    return f"{event.get('tag', '')} {event.get('message', '')}".lower()


def _has_sensitive_api_signal(events: list[dict[str, Any]]) -> bool:
    return any(
        any(keyword in _event_text(event) for keyword in SENSITIVE_API_KEYWORDS)
        for event in events
    )


def _has_ioc_signal(events: list[dict[str, Any]]) -> bool:
    for event in events:
        text = f"{event.get('tag', '')} {event.get('message', '')}"
        ip_match = _IPV4_PATTERN.search(text)
        if ip_match and ip_match.group(0) not in ("127.0.0.1", "0.0.0.0"):
            return True
        for match in _DOMAIN_PATTERN.findall(text):
            host = match.lower()
            if host not in ("localhost", "android", "example.com") and "." in host:
                return True
    return False


def _chain_has_permission_and_network(events: list[dict[str, Any]]) -> bool:
    types = {event.get("event_type") for event in events}
    return "permission" in types and "network" in types


def _system_activity_ratio(events: list[dict[str, Any]]) -> float:
    if not events:
        return 0.0
    dominant = sum(
        1 for event in events if event.get("event_type") in ("system", "activity")
    )
    return dominant / len(events)


def _is_system_activity_dominant(events: list[dict[str, Any]]) -> bool:
    return _system_activity_ratio(events) > SYSTEM_ACTIVITY_DOMINANCE_RATIO


def _chain_entropy(events: list[dict[str, Any]]) -> float:
    """Normalized diversity of event types in the window (0.0–1.0)."""
    if not events:
        return 0.0
    types = [event.get("event_type", "unknown") for event in events]
    unique = len(set(types))
    return round(min(unique / len(types), 1.0), 3)


def _signal_density(events: list[dict[str, Any]]) -> float:
    """Share of permission + network events in the window."""
    if not events:
        return 0.0
    signal_count = sum(
        1 for event in events if event.get("event_type") in ("permission", "network")
    )
    return round(signal_count / len(events), 3)


def _compute_malicious_score(events: list[dict[str, Any]]) -> int:
    permission_count = sum(1 for e in events if e.get("event_type") == "permission")
    network_count = sum(1 for e in events if e.get("event_type") == "network")

    score = (permission_count * SCORE_PERMISSION) + (network_count * SCORE_NETWORK)
    if _has_ioc_signal(events):
        score += SCORE_IOC
    if _has_sensitive_api_signal(events):
        score += SCORE_SENSITIVE_API
    if _is_system_activity_dominant(events):
        score -= SCORE_SYSTEM_DOMINANCE_PENALTY
    return score


def _compute_benign_behavior_score(events: list[dict[str, Any]]) -> int:
    """
    Session/window benign behavior score (max 8 from core signals).

    +2 login/session flow
    +2 system/activity dominance
    +2 no IOC in scope
    +2 no sensitive API usage
    """
    score = 0
    combined = " ".join(_event_text(event) for event in events)

    if any(marker in combined for marker in LOGIN_SESSION_MARKERS):
        score += 2

    if _system_activity_ratio(events) > SYSTEM_ACTIVITY_DOMINANCE_RATIO:
        score += 2

    if not _has_ioc_signal(events):
        score += 2

    if not _has_sensitive_api_signal(events):
        score += 2

    return score


def _compute_benign_score(events: list[dict[str, Any]], all_events: list[dict[str, Any]]) -> int:
    """Chain-level benign score = behavior score plus contextual noise heuristics."""
    score = _compute_benign_behavior_score(events)

    if _is_system_app_network_only(events):
        score += 3
    if _is_activity_manager_only(events):
        score += 2
    if _is_telemetry_sync_pattern(events):
        score += 2
    if len(all_events) < MIN_SESSION_EVENTS:
        score += 2
    if _is_login_session_flow(events):
        score += 1
    return score


def _is_system_app_network_only(events: list[dict[str, Any]]) -> bool:
    network_events = [e for e in events if e.get("event_type") == "network"]
    if not network_events:
        return False
    return all(
        any(marker in _event_text(event) for marker in SYSTEM_APP_MARKERS)
        for event in network_events
    )


def _is_login_session_flow(events: list[dict[str, Any]]) -> bool:
    combined = " ".join(_event_text(event) for event in events)
    has_login = any(marker in combined for marker in LOGIN_SESSION_MARKERS)
    has_escalation = any(event.get("event_type") == "error" for event in events) or (
        sum(1 for event in events if event.get("event_type") == "permission") >= 2
    )
    return has_login and not has_escalation and not _chain_has_permission_and_network(events)


def _is_activity_manager_only(events: list[dict[str, Any]]) -> bool:
    if not events:
        return False
    return all(
        "activitymanager" in _event_text(event) or event.get("event_type") == "activity"
        for event in events
    )


def _is_telemetry_sync_pattern(events: list[dict[str, Any]]) -> bool:
    combined = " ".join(_event_text(event) for event in events)
    return any(marker in combined for marker in TELEMETRY_SYNC_MARKERS)


def _should_reject_chain(events: list[dict[str, Any]], all_events: list[dict[str, Any]]) -> tuple[bool, str]:
    if len(events) < MIN_CHAIN_LEN:
        return True, "chain_shorter_than_minimum"
    if _is_system_app_network_only(events):
        return True, "system_app_network_noise"
    if _is_login_session_flow(events):
        return True, "benign_login_session_flow"
    if len(all_events) < MIN_SESSION_EVENTS:
        return True, "session_too_short_for_chain_context"
    return False, ""


def _infer_pattern_label(events: list[dict[str, Any]]) -> str:
    types = [event.get("event_type", "unknown") for event in events]
    if len(types) >= 3:
        triple = tuple(types[:3])
        if triple == ("permission", "network", "network"):
            return "DATA_EXFILTRATION_PATTERN"
        if triple == ("permission", "error", "permission"):
            return "PRIVILEGE_ESCALATION_ATTEMPT"
        if triple == ("network", "network", "network"):
            return "COMMAND_CONTROL_BEHAVIOR"
    if _chain_has_permission_and_network(events):
        return "PERMISSION_NETWORK_SEQUENCE"
    return "VARIABLE_LENGTH_CHAIN"


def _detect_variable_chains(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Slide variable-length windows (3–6) and score each candidate chain."""
    chains: list[dict[str, Any]] = []
    seen_windows: set[tuple[int, int]] = set()
    total = len(events)

    for length in range(MIN_CHAIN_LEN, min(MAX_CHAIN_LEN, total) + 1):
        for start in range(0, total - length + 1):
            if (start, length) in seen_windows:
                continue
            seen_windows.add((start, length))

            window_events = events[start : start + length]
            if not _chain_has_permission_and_network(window_events):
                continue

            malicious_score = _compute_malicious_score(window_events)
            benign_score = _compute_benign_score(window_events, events)

            chains.append(
                {
                    "pattern": _infer_pattern_label(window_events),
                    "start_index": start,
                    "length": length,
                    "event_types": [e.get("event_type", "unknown") for e in window_events],
                    "events": window_events,
                    "malicious_score": malicious_score,
                    "benign_score": benign_score,
                    "chain_entropy": _chain_entropy(window_events),
                    "signal_density": _signal_density(window_events),
                }
            )

    chains.sort(key=lambda item: item.get("malicious_score", 0), reverse=True)
    return chains


def _clamp_confidence_adjustment(value: float) -> float:
    return max(CONFIDENCE_MIN, min(CONFIDENCE_MAX, round(value, 3)))


def _session_reason_flags(all_events: list[dict[str, Any]]) -> list[str]:
    flags: list[str] = []
    if len(all_events) < MIN_SESSION_EVENTS:
        flags.append("SESSION_TOO_SHORT")
        return flags

    if _is_system_activity_dominant(all_events):
        flags.append("SYSTEM_NOISE")

    activity_manager_hits = sum(
        1 for event in all_events if "activitymanager" in _event_text(event)
    )
    if all_events and activity_manager_hits / len(all_events) >= 0.5:
        flags.append("ACTIVITY_MANAGER_NOISE")

    if _is_telemetry_sync_pattern(all_events):
        flags.append("TELEMETRY_SYSTEM_BEHAVIOR")

    return flags


def _derive_confidence_adjustment(
    valid_chains: list[dict[str, Any]],
    rejected_chains: list[dict[str, Any]],
    total_events: int,
    session_benign_behavior_score: int,
    reason_flags: list[str],
) -> float:
    malicious_score = sum(int(chain.get("malicious_score") or 0) for chain in valid_chains)
    benign_score = sum(int(chain.get("benign_score") or 0) for chain in rejected_chains)

    if not valid_chains and rejected_chains:
        benign_score += 2 * len(rejected_chains)

    raw = (malicious_score - benign_score) / max(1, total_events)

    if session_benign_behavior_score >= BENIGN_BEHAVIOR_CONFIDENCE_THRESHOLD:
        raw -= BENIGN_CONFIDENCE_PENALTY
        if "BENIGN_CONFIDENCE_BOOST" not in reason_flags:
            reason_flags.append("BENIGN_CONFIDENCE_BOOST")

    return _clamp_confidence_adjustment(raw)


def validate_attack_chains(events: list[dict[str, Any]] | None) -> dict[str, Any]:
    """
    Validate variable-length attack chains and return calibrated confidence delta.
    """
    normalized_events = _normalize_events(events)
    total_events = len(normalized_events)
    detected = _detect_variable_chains(normalized_events)

    valid_chains: list[dict[str, Any]] = []
    rejected_chains: list[dict[str, Any]] = []
    reason_flags: list[str] = _session_reason_flags(normalized_events)
    session_benign_behavior_score = _compute_benign_behavior_score(normalized_events)

    if not detected:
        if "NO_ATTACK_CHAIN_DETECTED" not in reason_flags:
            reason_flags.append("NO_ATTACK_CHAIN_DETECTED")
        return {
            "valid_chains": valid_chains,
            "rejected_chains": rejected_chains,
            "confidence_adjustment": _derive_confidence_adjustment(
                valid_chains,
                rejected_chains,
                total_events,
                session_benign_behavior_score,
                reason_flags,
            ),
            "reason_flags": reason_flags,
            "malicious_score_total": 0,
            "benign_score_total": 0,
            "benign_behavior_score": session_benign_behavior_score,
        }

    for chain in detected:
        window_events = chain.get("events") or []
        pattern = chain.get("pattern", "VARIABLE_LENGTH_CHAIN")
        malicious_score = int(chain.get("malicious_score") or 0)
        benign_score = int(chain.get("benign_score") or 0)

        reject, reject_reason = _should_reject_chain(window_events, normalized_events)
        if reject:
            rejected_chains.append(
                {
                    "pattern": pattern,
                    "reason": reject_reason,
                    "malicious_score": malicious_score,
                    "benign_score": benign_score,
                    "event_types": chain.get("event_types", []),
                    "start_index": chain.get("start_index", 0),
                    "length": chain.get("length", len(window_events)),
                    "chain_entropy": chain.get("chain_entropy", 0.0),
                    "signal_density": chain.get("signal_density", 0.0),
                }
            )
            continue

        if _chain_has_permission_and_network(window_events) and malicious_score >= MALICIOUS_SCORE_THRESHOLD:
            strength = (
                "strong"
                if malicious_score >= MALICIOUS_SCORE_THRESHOLD + 3
                or chain.get("signal_density", 0) >= 0.6
                else "weak"
            )
            valid_chains.append(
                {
                    "pattern": pattern,
                    "strength": strength,
                    "malicious_score": malicious_score,
                    "benign_score": benign_score,
                    "event_types": chain.get("event_types", []),
                    "start_index": chain.get("start_index", 0),
                    "length": chain.get("length", len(window_events)),
                    "chain_entropy": chain.get("chain_entropy", 0.0),
                    "signal_density": chain.get("signal_density", 0.0),
                    "reason": "permission_network_score_threshold_met",
                }
            )
            if strength == "strong" and "STRONG_MALICIOUS_CHAIN" not in reason_flags:
                reason_flags.append("STRONG_MALICIOUS_CHAIN")
            elif "WEAK_SUSPICIOUS_CHAIN" not in reason_flags:
                reason_flags.append("WEAK_SUSPICIOUS_CHAIN")
        else:
            rejected_chains.append(
                {
                    "pattern": pattern,
                    "reason": "score_below_threshold_or_missing_core_signals",
                    "malicious_score": malicious_score,
                    "benign_score": benign_score,
                    "event_types": chain.get("event_types", []),
                    "start_index": chain.get("start_index", 0),
                    "length": chain.get("length", len(window_events)),
                    "chain_entropy": chain.get("chain_entropy", 0.0),
                    "signal_density": chain.get("signal_density", 0.0),
                }
            )

    if len(rejected_chains) > len(valid_chains) and not valid_chains:
        if "CLEAR_FALSE_POSITIVE" not in reason_flags:
            reason_flags.append("CLEAR_FALSE_POSITIVE")

    malicious_total = sum(int(c.get("malicious_score") or 0) for c in valid_chains)
    benign_total = sum(int(c.get("benign_score") or 0) for c in rejected_chains)

    return {
        "valid_chains": valid_chains,
        "rejected_chains": rejected_chains,
        "confidence_adjustment": _derive_confidence_adjustment(
            valid_chains,
            rejected_chains,
            total_events,
            session_benign_behavior_score,
            reason_flags,
        ),
        "reason_flags": reason_flags,
        "malicious_score_total": malicious_total,
        "benign_score_total": benign_total,
        "benign_behavior_score": session_benign_behavior_score,
    }
