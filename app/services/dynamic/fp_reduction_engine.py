"""
False-positive reduction layer — behavioral stability and session memory.

Deterministic post-processing only. Does not modify core scoring engines.
"""

from __future__ import annotations

import math
from typing import Any

from app.services.static.static_analysis_contract import normalize_static_analysis

RISK_LOW_MAX = 30
RISK_MEDIUM_MAX = 60

CONFIDENCE_MIN = 0.0
CONFIDENCE_MAX = 1.0

STATIC_WEIGHT = 0.05
IOC_WEIGHT = 0.15
STATIC_LOW_THRESHOLD = 30
DYNAMIC_HIGH_THRESHOLD = 70
CROSS_LAYER_CONFIDENCE_PENALTY = 0.1
LOW_SIGNAL_DENSITY_THRESHOLD = 0.25

NOISE_SYSTEM_ACTIVITY_THRESHOLD = 0.70
NOISE_RISK_REDUCTION_FACTOR = 0.80
NOISE_CONFIDENCE_PENALTY = 0.15
NETWORK_SPIKE_ISOLATED_MIN = 3

BENIGN_WEIGHTS: dict[str, float] = {
    "login_session_marker": 0.25,
    "system_activity_dominance": 0.30,
    "no_ioc_present": 0.25,
    "no_sensitive_api": 0.20,
}
BENIGN_WEIGHT_SUM = sum(BENIGN_WEIGHTS.values())
BENIGN_HIGH_THRESHOLD = 0.75
BENIGN_RISK_DAMPEN_FACTOR = 0.90

BASELINE_SMOOTHING_OLD = 0.8
BASELINE_SMOOTHING_NEW = 0.2
BASELINE_DEVIATION_LOW = 0.15
BASELINE_DEVIATION_HIGH = 0.50
BASELINE_LOW_DEVIATION_RISK_FACTOR = 0.90
BASELINE_HIGH_DEVIATION_CONFIDENCE_BOOST = 0.10

LOGIN_SESSION_MARKERS = (
    "login",
    "signin",
    "sign in",
    "session",
    "authenticate",
    "auth token",
)

SENSITIVE_API_KEYWORDS = (
    "telephony",
    "smsmanager",
    "runtime.exec",
    "dexclassloader",
    "class.forname",
    "method.invoke",
    "crypto",
    "password",
    "credential",
    "token",
)

# In-process session memory (deterministic rolling baseline per package)
session_baseline: dict[str, dict[str, Any]] = {}


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _risk_level_from_score(risk_score: int) -> str:
    if risk_score <= RISK_LOW_MAX:
        return "LOW"
    if risk_score <= RISK_MEDIUM_MAX:
        return "MEDIUM"
    return "HIGH"


def _clamp_confidence(value: float) -> float:
    return round(max(CONFIDENCE_MIN, min(CONFIDENCE_MAX, value)), 3)


def _original_confidence(threat_intelligence: dict[str, Any]) -> float:
    threat_classification = threat_intelligence.get("threat_classification") or {}
    try:
        return float(threat_classification.get("confidence", 0.0))
    except (TypeError, ValueError):
        return 0.0


def _validation_reason_flags(validation_result: dict[str, Any]) -> list[str]:
    flags = validation_result.get("reason_flags")
    if isinstance(flags, list):
        return flags
    legacy = validation_result.get("flags")
    return legacy if isinstance(legacy, list) else []


def _package_name(threat_intelligence: dict[str, Any]) -> str:
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


def _event_counts(threat_intelligence: dict[str, Any]) -> dict[str, int]:
    session_state = threat_intelligence.get("session_state") or {}
    counts = session_state.get("event_counts") or {}
    return {
        "activity": int(counts.get("activity", 0) or 0),
        "network": int(counts.get("network", 0) or 0),
        "permission": int(counts.get("permission", 0) or 0),
        "error": int(counts.get("error", 0) or 0),
        "system": int(counts.get("system", 0) or 0),
    }


def _ioc_count(threat_intelligence: dict[str, Any]) -> int:
    iocs = (threat_intelligence.get("forensics") or {}).get("iocs") or {}
    return len(iocs.get("domains") or []) + len(iocs.get("ips") or []) + len(
        iocs.get("suspicious_strings") or []
    )


def _ioc_factor(threat_intelligence: dict[str, Any]) -> float:
    return min(_ioc_count(threat_intelligence) / 5.0, 1.0)


def _static_risk_factor(static_analysis: dict[str, Any]) -> float:
    score = int(static_analysis.get("static_risk_score") or 0)
    return min(max(score, 0), 100) / 100.0


def _session_system_activity_ratio(counts: dict[str, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    return (counts["activity"] + counts["system"]) / total


def _network_spike_isolated(counts: dict[str, int]) -> bool:
    """Network burst without paired permission activity (common GMS/sync noise)."""
    network = counts["network"]
    permission = counts["permission"]
    if network <= NETWORK_SPIKE_ISOLATED_MIN:
        return False
    return permission == 0 or (network >= 2 * max(permission, 1))


def _has_login_session_marker(threat_intelligence: dict[str, Any]) -> bool:
    blobs: list[str] = []
    for item in threat_intelligence.get("evidence") or []:
        blobs.append(str(item).lower())
    summary = threat_intelligence.get("intelligence_summary")
    if isinstance(summary, dict):
        blobs.append(str(summary.get("summary", "")).lower())
    elif isinstance(summary, str):
        blobs.append(summary.lower())
    combined = " ".join(blobs)
    return any(marker in combined for marker in LOGIN_SESSION_MARKERS)


def _has_sensitive_api_signal(threat_intelligence: dict[str, Any]) -> bool:
    for item in threat_intelligence.get("evidence") or []:
        lowered = str(item).lower()
        if any(keyword in lowered for keyword in SENSITIVE_API_KEYWORDS):
            return True
    return False


def _compute_weighted_benign_score(
    threat_intelligence: dict[str, Any],
    counts: dict[str, int],
    ioc_present: bool,
) -> float:
    conditions = {
        "login_session_marker": _has_login_session_marker(threat_intelligence),
        "system_activity_dominance": _session_system_activity_ratio(counts) > 0.60,
        "no_ioc_present": not ioc_present,
        "no_sensitive_api": not _has_sensitive_api_signal(threat_intelligence),
    }
    raw = sum(BENIGN_WEIGHTS[key] for key, met in conditions.items() if met)
    return round(raw / BENIGN_WEIGHT_SUM, 3) if BENIGN_WEIGHT_SUM else 0.0


def _apply_noise_suppression(
    risk_score: float,
    system_activity_ratio: float,
    ioc_present: bool,
    counts: dict[str, int],
    flags: list[str],
    notes: list[str],
) -> tuple[float, bool]:
    apply_penalty = (
        system_activity_ratio > NOISE_SYSTEM_ACTIVITY_THRESHOLD
        and not ioc_present
        and _network_spike_isolated(counts)
    )
    if not apply_penalty:
        return risk_score, False

    reduced = risk_score * NOISE_RISK_REDUCTION_FACTOR
    flags.append("SYSTEM_NOISE_SUPPRESSED")
    notes.append(
        f"Noise suppression: system/activity={system_activity_ratio:.0%}, isolated network spike, "
        f"no IOC — risk reduced by 20%."
    )
    return reduced, True


def _get_baseline(package: str) -> dict[str, Any]:
    return session_baseline.get(
        package,
        {"avg_risk": 0.0, "avg_network": 0.0, "avg_permissions": 0.0, "count": 0},
    )


def _update_session_baseline(
    package: str,
    current_risk: float,
    counts: dict[str, int],
) -> dict[str, Any]:
    baseline = _get_baseline(package)
    old_count = int(baseline.get("count") or 0)

    if old_count == 0:
        updated = {
            "avg_risk": float(current_risk),
            "avg_network": float(counts["network"]),
            "avg_permissions": float(counts["permission"]),
            "count": 1,
        }
    else:
        updated = {
            "avg_risk": (baseline["avg_risk"] * BASELINE_SMOOTHING_OLD)
            + (current_risk * BASELINE_SMOOTHING_NEW),
            "avg_network": (baseline["avg_network"] * BASELINE_SMOOTHING_OLD)
            + (counts["network"] * BASELINE_SMOOTHING_NEW),
            "avg_permissions": (baseline["avg_permissions"] * BASELINE_SMOOTHING_OLD)
            + (counts["permission"] * BASELINE_SMOOTHING_NEW),
            "count": old_count + 1,
        }

    session_baseline[package] = updated
    return updated


def _apply_baseline_deviation(
    risk_score: float,
    confidence: float,
    package: str,
    notes: list[str],
) -> tuple[float, float, float]:
    baseline = _get_baseline(package)
    if int(baseline.get("count") or 0) <= 0:
        return risk_score, confidence, 0.0

    current_norm = risk_score / 100.0
    avg_norm = float(baseline.get("avg_risk") or 0.0) / 100.0
    deviation = abs(current_norm - avg_norm)

    if deviation < BASELINE_DEVIATION_LOW:
        risk_score *= BASELINE_LOW_DEVIATION_RISK_FACTOR
        notes.append(
            f"Baseline stability: deviation={deviation:.2f} < {BASELINE_DEVIATION_LOW} "
            "— risk reduced by 10%."
        )
    elif deviation > BASELINE_DEVIATION_HIGH:
        confidence += BASELINE_HIGH_DEVIATION_CONFIDENCE_BOOST
        notes.append(
            f"Baseline anomaly: deviation={deviation:.2f} > {BASELINE_DEVIATION_HIGH} "
            "— confidence +0.1."
        )

    return risk_score, confidence, deviation


def _final_risk_calibration(
    risk_score: float,
    original_risk_score: int,
    validation_result: dict[str, Any],
    session_density: float,
    flags: list[str],
    notes: list[str],
) -> float:
    valid_chains = list(validation_result.get("valid_chains") or [])
    rejected_chains = list(validation_result.get("rejected_chains") or [])
    reason_flags = _validation_reason_flags(validation_result)

    chain_total = max(len(valid_chains) + len(rejected_chains), 1)
    valid_weight = len(valid_chains) / chain_total
    rejected_weight = len(rejected_chains) / chain_total

    if session_density < LOW_SIGNAL_DENSITY_THRESHOLD and original_risk_score > RISK_LOW_MAX:
        density_reduction = (1.0 - session_density) * 15
        risk_score -= density_reduction

    rejected_pressure = rejected_weight * (12 + 4 * max(len(rejected_chains) - len(valid_chains), 0))
    valid_lift = valid_weight * min(4, 2 * len(valid_chains))
    risk_score = risk_score - rejected_pressure + valid_lift

    if rejected_weight > valid_weight and "FALSE_POSITIVE_RISK" not in flags:
        flags.append("FALSE_POSITIVE_RISK")

    if "CLEAR_FALSE_POSITIVE" in reason_flags:
        risk_score -= 10

    return max(0.0, min(100.0, risk_score))


def apply_fp_reduction(
    threat_intelligence: dict[str, Any] | None,
    validation_result: dict[str, Any] | None,
    static_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Behavioral stability pipeline:
      1) noise suppression
      2) weighted benign scoring
      3) sigmoid confidence transform + adjustments
      4) baseline memory deviation
      5) final risk calibration
    """
    threat_intelligence = threat_intelligence if isinstance(threat_intelligence, dict) else {}
    validation_result = validation_result if isinstance(validation_result, dict) else {}
    static_analysis = normalize_static_analysis(static_analysis or {})

    original_risk_score = int(threat_intelligence.get("risk_score") or 0)
    original_confidence = _original_confidence(threat_intelligence)
    chain_adjustment = float(validation_result.get("confidence_adjustment") or 0.0)

    counts = _event_counts(threat_intelligence)
    ioc_present = _ioc_count(threat_intelligence) > 0
    system_activity_ratio = _session_system_activity_ratio(counts)
    package = _package_name(threat_intelligence)

    flags: list[str] = []
    notes: list[str] = []
    working_risk = float(original_risk_score)

    # --- 1) Noise suppression ---
    working_risk, noise_applied = _apply_noise_suppression(
        working_risk,
        system_activity_ratio,
        ioc_present,
        counts,
        flags,
        notes,
    )

    # --- 2) Weighted benign scoring ---
    benign_score = _compute_weighted_benign_score(threat_intelligence, counts, ioc_present)
    if benign_score >= BENIGN_HIGH_THRESHOLD:
        working_risk *= BENIGN_RISK_DAMPEN_FACTOR
        notes.append(
            f"Weighted benign score={benign_score:.2f} (≥{BENIGN_HIGH_THRESHOLD}) — risk dampened 10%."
        )

    # --- 3) Sigmoid confidence transform (then apply adjustments) ---
    raw_confidence = sigmoid((working_risk - 50.0) / 10.0)
    static_factor = _static_risk_factor(static_analysis)
    ioc_factor = _ioc_factor(threat_intelligence)
    cross_layer_adjustment = (static_factor * STATIC_WEIGHT) + (ioc_factor * IOC_WEIGHT)

    adjusted_confidence = raw_confidence + chain_adjustment + cross_layer_adjustment

    if noise_applied:
        adjusted_confidence -= NOISE_CONFIDENCE_PENALTY

    if benign_score >= BENIGN_HIGH_THRESHOLD:
        adjusted_confidence -= 0.10

    static_risk_score = int(static_analysis.get("static_risk_score") or 0)
    if (
        static_risk_score < STATIC_LOW_THRESHOLD
        and original_risk_score > DYNAMIC_HIGH_THRESHOLD
        and not ioc_present
    ):
        adjusted_confidence -= CROSS_LAYER_CONFIDENCE_PENALTY
        if "FALSE_POSITIVE_RISK" not in flags:
            flags.append("FALSE_POSITIVE_RISK")
        notes.append("Cross-layer inconsistency: low static, high dynamic, no IOC.")

    # --- 4) Baseline memory deviation (read before update) ---
    working_risk, adjusted_confidence, baseline_deviation = _apply_baseline_deviation(
        working_risk,
        adjusted_confidence,
        package,
        notes,
    )

    _update_session_baseline(package, float(original_risk_score), counts)

    # --- 5) Final risk calibration ---
    total_events = max(sum(counts.values()), 1)
    session_density = (counts["permission"] + counts["network"]) / total_events

    working_risk = _final_risk_calibration(
        working_risk,
        original_risk_score,
        validation_result,
        session_density,
        flags,
        notes,
    )

    adjusted_risk_score = max(0, min(100, int(round(working_risk))))
    adjusted_confidence = _clamp_confidence(adjusted_confidence)

    if not notes:
        notes.append("FP stability pipeline neutral for this session.")

    return {
        "original_risk_score": original_risk_score,
        "adjusted_risk_score": adjusted_risk_score,
        "original_confidence": original_confidence,
        "adjusted_confidence": adjusted_confidence,
        "adjusted_risk_level": _risk_level_from_score(adjusted_risk_score),
        "flags": flags,
        "notes": notes,
        "calibration": {
            "pipeline_order": [
                "noise_suppression",
                "weighted_benign_scoring",
                "sigmoid_confidence",
                "baseline_deviation",
                "final_risk_calibration",
            ],
            "benign_score_weighted": benign_score,
            "raw_sigmoid_confidence": round(raw_confidence, 3),
            "chain_confidence_adjustment": chain_adjustment,
            "cross_layer_adjustment": round(cross_layer_adjustment, 3),
            "system_activity_ratio": round(system_activity_ratio, 3),
            "baseline_deviation": round(baseline_deviation, 3),
            "session_baseline_count": int(_get_baseline(package).get("count") or 0),
            "noise_suppression_applied": noise_applied,
            "ioc_factor": round(ioc_factor, 3),
            "static_factor": round(static_factor, 3),
        },
    }


def apply_to_threat_intelligence(
    threat_intelligence: dict[str, Any],
    validation_result: dict[str, Any],
    static_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach validation + FP results and apply adjusted scores before final_verdict."""
    fp_result = apply_fp_reduction(threat_intelligence, validation_result, static_analysis)
    threat_intelligence["attack_validation"] = validation_result
    threat_intelligence["fp_reduction"] = fp_result
    threat_intelligence["risk_score"] = fp_result["adjusted_risk_score"]
    threat_intelligence["risk_level"] = fp_result["adjusted_risk_level"]

    threat_classification = dict(threat_intelligence.get("threat_classification") or {})
    threat_classification["confidence"] = fp_result["adjusted_confidence"]
    threat_intelligence["threat_classification"] = threat_classification
    return threat_intelligence


def reset_session_baseline() -> None:
    """Clear in-process baselines (useful for tests)."""
    session_baseline.clear()
