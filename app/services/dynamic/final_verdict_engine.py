"""
Final verdict engine — deterministic fusion of static and dynamic security signals.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.static.static_analysis_contract import normalize_static_analysis

WEIGHT_DYNAMIC = 0.60
WEIGHT_STATIC = 0.25
WEIGHT_IOC = 0.15

MALWARE_SCORE_THRESHOLD = 70
SAFE_SCORE_THRESHOLD = 30
COMMAND_CONTROL_CONFIDENCE_THRESHOLD = 0.7

MAJOR_ATTACK_PATTERNS = {
    "DATA_EXFILTRATION_PATTERN",
    "COMMAND_CONTROL_BEHAVIOR",
    "PRIVILEGE_ESCALATION_ATTEMPT",
}

# Conflict resolution thresholds
STATIC_LOW_CONFLICT = 40
DYNAMIC_HIGH_CONFLICT = 70
IOC_UNDERWEIGHTED_RISK_MAX = 50
BENIGN_HIGH_CONFLICT = 0.75
RISK_HIGH_BENIGN_CONFLICT = 70

CONFLICT_CONFIDENCE_PENALTY = 0.15
IOC_CONFIDENCE_BOOST = 0.10
BENIGN_RISK_REDUCTION_FACTOR = 0.85
CONSISTENCY_PENALTY_PER_CONFLICT = 0.2

REPUTATION_EMA_OLD = 0.8
REPUTATION_EMA_NEW = 0.2
REPUTATION_BENIGN_RISK_MAX = 40
REPUTATION_BENIGN_MIN_RUNS = 3
REPUTATION_PATTERN_FREQ_THRESHOLD = 3
REPUTATION_IOC_FREQ_THRESHOLD = 2
REPUTATION_BENIGN_CONFIDENCE_DELTA = -0.10
REPUTATION_PATTERN_CONFIDENCE_DELTA = 0.10
REPUTATION_IOC_RISK_DELTA = 5

TRACKED_REPUTATION_PATTERNS = (
    "DATA_EXFILTRATION_PATTERN",
    "COMMAND_CONTROL_BEHAVIOR",
    "NETWORK_BURST",
)

GLOBAL_REPUTATION_CACHE: dict[str, dict[str, Any]] = {
    "packages": {},
    "iocs": {},
    "patterns": {},
}


def _utc_timestamp_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_package_name(threat_intelligence: dict[str, Any]) -> str:
    for key in ("package_name",):
        value = threat_intelligence.get(key)
        if value:
            return str(value)
    summary = threat_intelligence.get("intelligence_summary") or {}
    if isinstance(summary, dict) and summary.get("package_name"):
        return str(summary["package_name"])
    session_state = threat_intelligence.get("session_state") or {}
    if session_state.get("package_name"):
        return str(session_state["package_name"])
    return "unknown"


def _extract_ioc_keys(threat_intelligence: dict[str, Any]) -> list[str]:
    iocs = (threat_intelligence.get("forensics") or {}).get("iocs") or {}
    keys: list[str] = []
    for domain in iocs.get("domains") or []:
        keys.append(f"domain:{str(domain).lower()}")
    for ip in iocs.get("ips") or []:
        keys.append(f"ip:{ip}")
    return keys


def _extract_tracked_patterns(threat_intelligence: dict[str, Any]) -> list[str]:
    found: list[str] = []
    attack_patterns = set(threat_intelligence.get("attack_patterns") or [])
    for pattern in TRACKED_REPUTATION_PATTERNS:
        if pattern in attack_patterns:
            found.append(pattern)

    flags = set(threat_intelligence.get("flags") or [])
    threat_flags = set((threat_intelligence.get("threat_classification") or {}).get("flags") or [])
    session_flags = set(
        str(item)
        for item in (threat_intelligence.get("session_state") or {}).get("flags", [])
    )
    all_flags = flags | threat_flags | session_flags
    if "NETWORK_BURST" in all_flags and "NETWORK_BURST" not in found:
        found.append("NETWORK_BURST")

    evidence_text = " ".join(str(item) for item in (threat_intelligence.get("evidence") or [])).upper()
    if "NETWORK_BURST" in evidence_text and "NETWORK_BURST" not in found:
        found.append("NETWORK_BURST")

    return found


def update_global_reputation(package_name: str, threat_intelligence: dict[str, Any]) -> None:
    """Update in-memory cross-session reputation from the current analysis run."""
    threat_intelligence = threat_intelligence or {}
    package_name = package_name or "unknown"
    timestamp = _utc_timestamp_label()

    current_risk = float(threat_intelligence.get("risk_score") or 0)
    threat_classification = threat_intelligence.get("threat_classification") or {}
    try:
        current_confidence = float(threat_classification.get("confidence") or 0.0)
    except (TypeError, ValueError):
        current_confidence = 0.0

    packages = GLOBAL_REPUTATION_CACHE["packages"]
    existing = packages.get(package_name)
    if existing:
        packages[package_name] = {
            "avg_risk_score": round(
                (existing["avg_risk_score"] * REPUTATION_EMA_OLD) + (current_risk * REPUTATION_EMA_NEW),
                3,
            ),
            "avg_confidence": round(
                (existing["avg_confidence"] * REPUTATION_EMA_OLD)
                + (current_confidence * REPUTATION_EMA_NEW),
                3,
            ),
            "occurrence_count": int(existing.get("occurrence_count") or 0) + 1,
            "last_seen": timestamp,
        }
    else:
        packages[package_name] = {
            "avg_risk_score": round(current_risk, 3),
            "avg_confidence": round(current_confidence, 3),
            "occurrence_count": 1,
            "last_seen": timestamp,
        }

    ioc_store = GLOBAL_REPUTATION_CACHE["iocs"]
    for ioc_key in _extract_ioc_keys(threat_intelligence):
        entry = ioc_store.get(ioc_key, {"count": 0, "last_seen": ""})
        ioc_store[ioc_key] = {
            "count": int(entry.get("count") or 0) + 1,
            "last_seen": timestamp,
        }

    pattern_store = GLOBAL_REPUTATION_CACHE["patterns"]
    for pattern in _extract_tracked_patterns(threat_intelligence):
        entry = pattern_store.get(pattern, {"frequency": 0, "last_seen": ""})
        pattern_store[pattern] = {
            "frequency": int(entry.get("frequency") or 0) + 1,
            "last_seen": timestamp,
        }


def get_reputation_adjustment(
    package_name: str,
    threat_intelligence: dict[str, Any],
) -> dict[str, Any]:
    """
    Deterministic reputation influence from prior sessions (in-memory cache).
    """
    package_name = package_name or "unknown"
    threat_intelligence = threat_intelligence or {}

    confidence_delta = 0.0
    risk_delta = 0
    notes: list[str] = []

    package_stats = GLOBAL_REPUTATION_CACHE["packages"].get(package_name) or {}
    occurrence_count = int(package_stats.get("occurrence_count") or 0)
    avg_risk = float(package_stats.get("avg_risk_score") or 0.0)

    if occurrence_count >= REPUTATION_BENIGN_MIN_RUNS and avg_risk < REPUTATION_BENIGN_RISK_MAX:
        confidence_delta += REPUTATION_BENIGN_CONFIDENCE_DELTA
        notes.append(
            f"Historically benign package profile (avg risk {avg_risk:.0f}, {occurrence_count} runs)."
        )

    pattern_store = GLOBAL_REPUTATION_CACHE["patterns"]
    for pattern in _extract_tracked_patterns(threat_intelligence):
        frequency = int((pattern_store.get(pattern) or {}).get("frequency") or 0)
        if frequency >= REPUTATION_PATTERN_FREQ_THRESHOLD:
            confidence_delta += REPUTATION_PATTERN_CONFIDENCE_DELTA
            notes.append(f"Repeated suspicious pattern {pattern} (frequency={frequency}).")
            break

    ioc_store = GLOBAL_REPUTATION_CACHE["iocs"]
    for ioc_key in _extract_ioc_keys(threat_intelligence):
        count = int((ioc_store.get(ioc_key) or {}).get("count") or 0)
        if count >= REPUTATION_IOC_FREQ_THRESHOLD:
            risk_delta += REPUTATION_IOC_RISK_DELTA
            notes.append(f"Recurring IOC {ioc_key} (count={count}).")
            break

    return {
        "confidence_delta": round(confidence_delta, 3),
        "risk_delta": risk_delta,
        "notes": notes,
    }


def _build_global_reputation_snapshot(
    package_name: str,
    threat_intelligence: dict[str, Any],
) -> dict[str, Any]:
    package_stats = dict(GLOBAL_REPUTATION_CACHE["packages"].get(package_name) or {})
    ioc_stats = {
        key: dict(GLOBAL_REPUTATION_CACHE["iocs"][key])
        for key in _extract_ioc_keys(threat_intelligence)
        if key in GLOBAL_REPUTATION_CACHE["iocs"]
    }
    pattern_stats = {
        pattern: dict(GLOBAL_REPUTATION_CACHE["patterns"][pattern])
        for pattern in _extract_tracked_patterns(threat_intelligence)
        if pattern in GLOBAL_REPUTATION_CACHE["patterns"]
    }
    return {
        "package_stats": package_stats,
        "ioc_stats": ioc_stats,
        "pattern_stats": pattern_stats,
    }


def reset_global_reputation_cache() -> None:
    """Clear in-memory reputation cache (useful for tests)."""
    GLOBAL_REPUTATION_CACHE["packages"].clear()
    GLOBAL_REPUTATION_CACHE["iocs"].clear()
    GLOBAL_REPUTATION_CACHE["patterns"].clear()


def _ioc_risk_score(threat_intelligence: dict[str, Any] | None) -> int:
    """Derive a 0-100 IOC risk score from forensics indicators."""
    if not threat_intelligence:
        return 0

    forensics = threat_intelligence.get("forensics") or {}
    iocs = forensics.get("iocs") or {}

    domain_count = len(iocs.get("domains") or [])
    ip_count = len(iocs.get("ips") or [])
    suspicious_count = len(iocs.get("suspicious_strings") or [])

    if domain_count == 0 and ip_count == 0 and suspicious_count == 0:
        return 0

    score = (domain_count * 12) + (ip_count * 15) + (suspicious_count * 8)
    return min(score, 100)


def _has_iocs(threat_intelligence: dict[str, Any] | None) -> bool:
    if not threat_intelligence:
        return False

    iocs = (threat_intelligence.get("forensics") or {}).get("iocs") or {}
    return bool(
        (iocs.get("domains") or [])
        or (iocs.get("ips") or [])
        or (iocs.get("suspicious_strings") or [])
    )


def _has_crash_loop_signal(threat_intelligence: dict[str, Any] | None) -> bool:
    if not threat_intelligence:
        return False

    evidence = threat_intelligence.get("evidence") or []
    evidence_text = " ".join(str(item) for item in evidence).upper()
    if "CRASH_LOOP" in evidence_text or "REPEATED ERROR" in evidence_text:
        return True

    flags_text = str((threat_intelligence.get("threat_classification") or {}).get("reasoning", ""))
    return "CRASH" in evidence_text or "crash" in flags_text.lower()


def _is_crash_loop_only(
    attack_patterns: list[str],
    threat_intelligence: dict[str, Any] | None,
) -> bool:
    if not _has_crash_loop_signal(threat_intelligence):
        return False

    if any(pattern in MAJOR_ATTACK_PATTERNS for pattern in attack_patterns):
        return False

    return True


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _weighted_benign_score(threat_intelligence: dict[str, Any]) -> float:
    fp_reduction = threat_intelligence.get("fp_reduction") or {}
    calibration = fp_reduction.get("calibration") or {}
    try:
        return float(calibration.get("benign_score_weighted") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _detect_decision_conflicts(
    static_risk: int,
    dynamic_risk: int,
    final_risk_score: int,
    ioc_present: bool,
    benign_score: float,
) -> list[str]:
    conflicts: list[str] = []

    if static_risk < STATIC_LOW_CONFLICT and dynamic_risk > DYNAMIC_HIGH_CONFLICT:
        conflicts.append("STATIC_DYNAMIC_MISMATCH")

    if ioc_present and final_risk_score < IOC_UNDERWEIGHTED_RISK_MAX:
        conflicts.append("IOC_UNDERWEIGHTED")

    if benign_score > BENIGN_HIGH_CONFLICT and final_risk_score > RISK_HIGH_BENIGN_CONFLICT:
        conflicts.append("BENIGN_OVERCLASSIFICATION")

    return conflicts


def _resolve_decision_conflicts(
    conflicts: list[str],
    final_risk_score: int,
    confidence: float,
) -> tuple[int, float, list[str], float]:
    """Apply per-conflict adjustments, then scale confidence by consistency score."""
    resolution_actions: list[str] = []
    adjusted_risk = float(final_risk_score)
    adjusted_confidence = _clamp01(confidence)

    for conflict in conflicts:
        if conflict == "STATIC_DYNAMIC_MISMATCH":
            adjusted_confidence -= CONFLICT_CONFIDENCE_PENALTY
            resolution_actions.append("Reduced confidence by 0.15 (static/dynamic mismatch).")
        elif conflict == "IOC_UNDERWEIGHTED":
            adjusted_confidence += IOC_CONFIDENCE_BOOST
            resolution_actions.append("Increased confidence by 0.10 (IOC present, risk underweighted).")
        elif conflict == "BENIGN_OVERCLASSIFICATION":
            adjusted_risk *= BENIGN_RISK_REDUCTION_FACTOR
            resolution_actions.append("Reduced final risk by 15% (benign overclassification).")

    adjusted_confidence = _clamp01(adjusted_confidence)
    consistency_score = _clamp01(1.0 - (len(conflicts) * CONSISTENCY_PENALTY_PER_CONFLICT))
    adjusted_confidence = round(adjusted_confidence * consistency_score, 3)
    adjusted_risk = int(min(max(round(adjusted_risk), 0), 100))

    return adjusted_risk, adjusted_confidence, resolution_actions, consistency_score


def _compute_confidence(
    final_risk_score: int,
    attack_patterns: list[str],
    has_iocs: bool,
) -> float:
    normalized = min(max(final_risk_score, 0), 100) / 100.0
    confidence = normalized

    if attack_patterns:
        confidence += 0.1
    if has_iocs:
        confidence += 0.1

    return round(min(confidence, 1.0), 3)


def _determine_verdict(
    final_risk_score: int,
    confidence: float,
    attack_patterns: list[str],
    threat_intelligence: dict[str, Any] | None,
) -> str:
    pattern_set = set(attack_patterns)

    if "DATA_EXFILTRATION_PATTERN" in pattern_set and final_risk_score > MALWARE_SCORE_THRESHOLD:
        return "MALWARE"

    if "COMMAND_CONTROL_BEHAVIOR" in pattern_set and confidence > COMMAND_CONTROL_CONFIDENCE_THRESHOLD:
        return "MALWARE"

    if _is_crash_loop_only(attack_patterns, threat_intelligence):
        return "SUSPICIOUS"

    if final_risk_score < SAFE_SCORE_THRESHOLD:
        return "SAFE"

    if final_risk_score >= MALWARE_SCORE_THRESHOLD:
        return "MALWARE"

    return "SUSPICIOUS"


PATTERN_JUDGE_LABELS: dict[str, str] = {
    "DATA_EXFILTRATION_PATTERN": (
        "Sensitive permissions were followed by repeated outbound network activity suggestive of data exfiltration."
    ),
    "PRIVILEGE_ESCALATION_ATTEMPT": (
        "Permission use, runtime errors, and renewed permission requests suggest privilege escalation behavior."
    ),
    "COMMAND_CONTROL_BEHAVIOR": (
        "Sustained back-to-back network communications resemble command-and-control style behavior."
    ),
}

PATTERN_PRIORITY = (
    "DATA_EXFILTRATION_PATTERN",
    "COMMAND_CONTROL_BEHAVIOR",
    "PRIVILEGE_ESCALATION_ATTEMPT",
)


def _humanize_pattern(pattern: str) -> str:
    if pattern in PATTERN_JUDGE_LABELS:
        return PATTERN_JUDGE_LABELS[pattern]
    return pattern.replace("_", " ").strip().capitalize() + "."


def _humanize_evidence(item: Any) -> str:
    text = str(item or "").strip()
    if not text:
        return ""
    if text.lower().startswith("log sample"):
        bracket_split = text.split("]", 1)
        if len(bracket_split) > 1:
            text = bracket_split[1].strip()
    if len(text) > 140:
        return text[:137] + "..."
    return text


def _select_top_patterns(attack_patterns: list[str], limit: int = 2) -> list[str]:
    ordered: list[str] = []
    for pattern in PATTERN_PRIORITY:
        if pattern in attack_patterns and pattern not in ordered:
            ordered.append(pattern)
    for pattern in attack_patterns:
        if pattern not in ordered:
            ordered.append(pattern)
    return ordered[:limit]


def _select_top_evidence(threat_intelligence: dict[str, Any], limit: int = 2) -> list[str]:
    evidence = threat_intelligence.get("evidence") or []
    lines: list[str] = []
    for item in evidence:
        humanized = _humanize_evidence(item)
        if humanized and humanized not in lines:
            lines.append(humanized)
        if len(lines) >= limit:
            break
    return lines


def _highest_contributing_factor(
    threat_intelligence: dict[str, Any],
    final_risk_score: int,
) -> str:
    dynamic_score = int(threat_intelligence.get("risk_score") or 0)
    ioc_score = _ioc_risk_score(threat_intelligence)

    dynamic_weighted = dynamic_score * WEIGHT_DYNAMIC
    ioc_weighted = ioc_score * WEIGHT_IOC
    remaining = max(0, final_risk_score - int(round(dynamic_weighted)) - int(round(ioc_weighted)))
    static_weighted = remaining if WEIGHT_STATIC > 0 else 0.0

    ranked = sorted(
        (
            ("dynamic", dynamic_weighted),
            ("static", static_weighted),
            ("ioc", ioc_weighted),
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    return ranked[0][0] if ranked else "dynamic"


def _verdict_summary_line(verdict: str, risk_level: str) -> str:
    verdict_upper = (verdict or "SAFE").upper()
    if verdict_upper == "MALWARE":
        return f"This application is assessed as malicious ({risk_level} concern)."
    if verdict_upper == "SUSPICIOUS":
        return f"This application is assessed as suspicious ({risk_level} concern)."
    return f"This application is assessed as low risk ({risk_level} concern)."


def _risk_level_label(final_risk_score: int) -> str:
    if final_risk_score >= MALWARE_SCORE_THRESHOLD:
        return "high"
    if final_risk_score >= SAFE_SCORE_THRESHOLD:
        return "moderate"
    return "low"


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.45:
        return "moderate"
    return "low"


def _risk_justification_line(verdict: str, dominant_factor: str, has_iocs: bool) -> str:
    factor_phrase = {
        "dynamic": "runtime behavior during sandbox execution",
        "static": "permissions and code-level indicators in the APK",
        "ioc": "network and credential indicators extracted from the session",
    }.get(dominant_factor, "combined behavioral and code signals")

    if verdict == "SAFE":
        return f"The overall picture is consistent with benign use, with no strong corroboration from {factor_phrase}."
    if verdict == "MALWARE":
        suffix = " and supporting indicators of compromise" if has_iocs else ""
        return f"Malicious assessment is driven primarily by {factor_phrase}{suffix}."
    return f"Caution is warranted based on {factor_phrase}, though evidence is not conclusive for a firm malicious label."


def _ioc_static_confirmation_line(
    threat_intelligence: dict[str, Any],
    dominant_factor: str,
    static_analysis: dict[str, Any] | None,
) -> str:
    iocs = (threat_intelligence.get("forensics") or {}).get("iocs") or {}
    domains = list(iocs.get("domains") or [])[:2]
    ips = list(iocs.get("ips") or [])[:2]

    ioc_parts: list[str] = []
    if domains:
        ioc_parts.append(f"domains ({', '.join(domains)})")
    if ips:
        ioc_parts.append(f"IPs ({', '.join(ips)})")

    static_flags = (static_analysis or {}).get("manifest_analysis", {}).get("risk_flags") or []
    static_note = ""
    if static_flags:
        static_note = f"Static review flagged {static_flags[0].replace('_', ' ').lower()}."

    if ioc_parts and static_note:
        return f"Corroboration includes {', '.join(ioc_parts)} plus {static_note}"
    if ioc_parts:
        return f"Indicators of compromise include {', '.join(ioc_parts)}."
    if static_note:
        return static_note
    if dominant_factor == "static":
        return "Static inspection contributed the strongest supporting signal."
    if dominant_factor == "ioc":
        return "Forensic indicators provided the strongest supporting signal."
    return "No separate static or IOC confirmation was required beyond behavioral signals."


def build_judge_summary(
    final_verdict: dict[str, Any],
    threat_intelligence: dict[str, Any] | None,
    static_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Compress verdict output into a short, judge-readable summary (presentation only).
    """
    final_verdict = final_verdict or {}
    threat_intelligence = threat_intelligence or {}
    static_analysis = static_analysis or {}

    verdict = str(final_verdict.get("verdict") or "SAFE")
    confidence = float(final_verdict.get("confidence") or 0.0)
    final_risk_score = int(final_verdict.get("final_risk_score") or 0)
    risk_level = _risk_level_label(final_risk_score)

    attack_patterns = _select_top_patterns(list(threat_intelligence.get("attack_patterns") or []))
    evidence_items = _select_top_evidence(threat_intelligence)
    dominant_factor = _highest_contributing_factor(threat_intelligence, final_risk_score)
    has_iocs = _has_iocs(threat_intelligence)

    lines: list[str] = []

    # Line 1: Verdict summary
    lines.append(_verdict_summary_line(verdict, risk_level))

    # Line 2: Primary behavior signal
    if attack_patterns:
        lines.append(_humanize_pattern(attack_patterns[0]))
    elif evidence_items:
        lines.append(evidence_items[0])
    else:
        threat_type = (threat_intelligence.get("threat_classification") or {}).get("threat_type")
        if threat_type and threat_type != "Benign / Low Threat":
            lines.append(f"Behavior aligns with a {threat_type} profile.")
        else:
            lines.append("No dominant attack-chain pattern was identified in the session.")

    # Line 3: Secondary signal
    if len(attack_patterns) > 1:
        lines.append(_humanize_pattern(attack_patterns[1]))
    elif len(evidence_items) > 1:
        lines.append(evidence_items[1])
    elif evidence_items and attack_patterns:
        lines.append(evidence_items[0])
    else:
        lines.append("Secondary signals were limited and did not add a distinct threat narrative.")

    # Line 4: IOC / static confirmation
    lines.append(_ioc_static_confirmation_line(threat_intelligence, dominant_factor, static_analysis))

    # Line 5: Risk justification
    lines.append(_risk_justification_line(verdict, dominant_factor, has_iocs))

    # Line 6: Confidence statement
    consistency = (final_verdict.get("decision_consistency") or {}).get("score")
    consistency_note = ""
    if isinstance(consistency, (int, float)) and consistency < 0.8:
        consistency_note = " with reduced consistency due to mixed signals"
    lines.append(
        f"Final assessment confidence is {_confidence_label(confidence)}{consistency_note}."
    )

    lines = lines[:6]
    one_paragraph = " ".join(lines)

    return {
        "lines": lines,
        "one_paragraph_summary": one_paragraph,
    }


def _build_reasoning(
    verdict: str,
    final_risk_score: int,
    confidence: float,
    dynamic_score: int,
    static_score: int,
    ioc_score: int,
    attack_patterns: list[str],
    static_analysis: dict[str, Any] | None,
) -> list[str]:
    reasoning = [
        (
            f"Weighted fusion produced final risk score {final_risk_score}/100 "
            f"(dynamic={dynamic_score}, static={static_score}, ioc={ioc_score})."
        ),
        f"Confidence score derived at {confidence:.2f}.",
        f"Final verdict: {verdict}.",
    ]

    if attack_patterns:
        reasoning.append(f"Attack patterns observed: {', '.join(attack_patterns)}.")

    if static_analysis:
        static_summary = static_analysis.get("summary") or []
        if static_summary:
            reasoning.append(f"Static analysis: {static_summary[0]}")

    return reasoning


def build_final_verdict(
    threat_intelligence: dict[str, Any] | None,
    static_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Fuse dynamic threat intelligence and optional static analysis into a final verdict.

    Args:
        threat_intelligence: Behavior engine output (risk, patterns, forensics, etc.).
        static_analysis: Optional output from StaticAnalyzer.analyze().

    Returns:
        verdict, confidence, final_risk_score, reasoning, signal_weights
    """
    threat_intelligence = threat_intelligence or {}
    static_analysis = normalize_static_analysis(
        static_analysis,
        source_format="final_verdict_engine.build",
    )

    dynamic_score = int(threat_intelligence.get("risk_score") or 0)
    static_score = int(static_analysis.get("static_risk_score") or 0)
    ioc_score = _ioc_risk_score(threat_intelligence)

    final_risk_score = int(
        round(
            (dynamic_score * WEIGHT_DYNAMIC)
            + (static_score * WEIGHT_STATIC)
            + (ioc_score * WEIGHT_IOC)
        )
    )
    final_risk_score = min(max(final_risk_score, 0), 100)

    attack_patterns = list(threat_intelligence.get("attack_patterns") or [])
    iocs_present = _has_iocs(threat_intelligence)

    confidence = _compute_confidence(final_risk_score, attack_patterns, iocs_present)

    benign_score = _weighted_benign_score(threat_intelligence)
    conflicts = _detect_decision_conflicts(
        static_risk=static_score,
        dynamic_risk=dynamic_score,
        final_risk_score=final_risk_score,
        ioc_present=iocs_present,
        benign_score=benign_score,
    )
    resolved_risk, resolved_confidence, resolution_actions, consistency_score = _resolve_decision_conflicts(
        conflicts,
        final_risk_score,
        confidence,
    )

    final_risk_score = resolved_risk
    confidence = resolved_confidence

    package_name = _resolve_package_name(threat_intelligence)
    reputation_adjustment = get_reputation_adjustment(package_name, threat_intelligence)
    confidence = _clamp01(confidence + float(reputation_adjustment.get("confidence_delta") or 0.0))
    final_risk_score = min(
        100,
        max(0, final_risk_score + int(reputation_adjustment.get("risk_delta") or 0)),
    )

    update_global_reputation(package_name, threat_intelligence)

    verdict = _determine_verdict(
        final_risk_score,
        confidence,
        attack_patterns,
        threat_intelligence,
    )

    reasoning = _build_reasoning(
        verdict,
        final_risk_score,
        confidence,
        dynamic_score,
        static_score,
        ioc_score,
        attack_patterns,
        static_analysis,
    )

    if conflicts:
        reasoning.append(
            f"Decision consistency score {consistency_score:.2f} after resolving: "
            f"{', '.join(conflicts)}."
        )

    for note in reputation_adjustment.get("notes") or []:
        reasoning.append(f"Cross-session reputation: {note}")

    if verdict == "MALWARE" and "DATA_EXFILTRATION_PATTERN" in attack_patterns:
        reasoning.append("Elevated to MALWARE due to data exfiltration pattern with high composite risk.")
    if verdict == "MALWARE" and "COMMAND_CONTROL_BEHAVIOR" in attack_patterns:
        reasoning.append("Elevated to MALWARE due to command-and-control behavior with sufficient confidence.")
    if verdict == "SUSPICIOUS" and _is_crash_loop_only(attack_patterns, threat_intelligence):
        reasoning.append("Marked SUSPICIOUS due to crash-loop indicators without broader attack chain.")

    threat_type = (threat_intelligence.get("threat_classification") or {}).get("threat_type")
    if threat_type:
        reasoning.append(f"Dynamic threat classification context: {threat_type}.")

    final_output = {
        "verdict": verdict,
        "confidence": confidence,
        "final_risk_score": final_risk_score,
        "reasoning": reasoning,
        "signal_weights": {
            "static": WEIGHT_STATIC,
            "dynamic": WEIGHT_DYNAMIC,
            "ioc": WEIGHT_IOC,
        },
        "decision_consistency": {
            "score": round(consistency_score, 3),
            "conflicts": conflicts,
            "resolution_actions": resolution_actions,
        },
        "global_reputation": _build_global_reputation_snapshot(package_name, threat_intelligence),
        "reputation_adjustment": reputation_adjustment,
    }
    final_output["judge_summary"] = build_judge_summary(
        final_output,
        threat_intelligence,
        static_analysis=static_analysis,
    )
    return final_output


class FinalVerdictEngine:
    """Deterministic multi-source malware verdict engine."""

    def compute(
        self,
        threat_intelligence: dict[str, Any] | None,
        static_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_final_verdict(threat_intelligence, static_analysis)
