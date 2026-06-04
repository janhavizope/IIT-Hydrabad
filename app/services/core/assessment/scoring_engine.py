"""
Adaptive risk scoring: behavior profile, confidence engine, fusion, classification.
"""

from __future__ import annotations

import math
import re
from typing import Any

from app.services.core.assessment.constants import (
    DANGEROUS_API_KEYWORDS,
    DANGEROUS_PERMISSION_NAMES,
    DATA_MOVEMENT_MARKERS,
    IOC_SCORE_CAP,
    IOC_WEIGHT_MALICIOUS,
    IOC_WEIGHT_SUSPICIOUS,
    MALICIOUS_CONFIDENCE_DOWNGRADE_CAP,
    MALICIOUS_SCORE_THRESHOLD,
    SAFE_SCORE_THRESHOLD,
    SCORE_CAP_WITHOUT_CHAIN,
    SENSITIVE_ACTION_MARKERS,
    SUSPICIOUS_SCORE_MAX,
    TRUSTED_DOMAIN_PREFIXES,
    URL_PATTERN,
    WEIGHT_DYNAMIC,
    WEIGHT_IOC,
    WEIGHT_STATIC,
)
from app.services.core.assessment.ioc_classifier import ioc_entropy
from app.services.core.assessment.noise_filter import NoiseFilterResult, detect_app_crash_loop


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return min(max(value, low), high)


def permission_basename(permission: str) -> str:
    return str(permission).split(".")[-1]


def extract_explicit_permissions(raw_static: dict[str, Any] | None) -> list[str]:
    if not isinstance(raw_static, dict):
        return []
    perms = raw_static.get("permissions")
    if isinstance(perms, list):
        return [str(p) for p in perms if str(p).strip()]
    if isinstance(perms, dict) and isinstance(perms.get("all"), list):
        return [str(p) for p in perms["all"] if str(p).strip()]
    return []


def explicit_dangerous_permissions(permissions: list[str]) -> list[str]:
    return [p for p in permissions if permission_basename(p) in DANGEROUS_PERMISSION_NAMES]


def _is_trusted_domain(host: str) -> bool:
    lowered = host.strip().lower()
    return any(lowered.startswith(p) for p in TRUSTED_DOMAIN_PREFIXES)


def message_has_external_endpoint(message: str) -> bool:
    for url in URL_PATTERN.findall(message):
        host_match = re.search(r"https?://([^/\s:?#]+)", url, re.I)
        if host_match and not _is_trusted_domain(host_match.group(1)):
            return True
    return False


def compute_static_score(
    explicit_permissions: list[str],
    dangerous_permissions: list[str],
    suspicious_apis: list[str],
    external_urls: list[str],
) -> tuple[float, dict[str, list[str]]]:
    findings: dict[str, list[str]] = {
        "permissions": [],
        "code_patterns": [],
        "embedded_strings": [],
        "manifest_notes": [],
    }
    score = 0.0

    if not explicit_permissions:
        findings["manifest_notes"].append("No permissions in input — treated as empty list.")

    for perm in dangerous_permissions[:5]:
        score += 10.0
        findings["permissions"].append(
            f"Dangerous permission (explicit): {permission_basename(perm)}"
        )
    score = min(score, 50.0)

    api_hits = [a for a in suspicious_apis if any(k in str(a).lower() for k in DANGEROUS_API_KEYWORDS)]
    for api in api_hits[:3]:
        score += 15.0
        findings["code_patterns"].append(f"Sensitive API in static analysis: {api}")
    score = min(score, 80.0)

    for url in external_urls[:2]:
        score += 15.0
        findings["embedded_strings"].append(f"Non-vendor hardcoded URL: {url}")

    if not dangerous_permissions and not api_hits and not external_urls:
        findings["permissions"].append("No elevated static indicators in provided data.")

    return _clamp(score), findings


def build_chain_flags(
    dangerous_permissions: list[str],
    suspicious_apis: list[str],
    external_urls: list[str],
    dynamic_flags: dict[str, bool],
) -> dict[str, bool]:
    """Merge static + dynamic evidence (order-independent)."""
    runtime = bool(
        dynamic_flags.get("sensitive_runtime_action_detected")
        or dynamic_flags.get("sensitive_action_detected")
    )
    flags = {
        "sensitive_permission_detected": bool(dynamic_flags.get("sensitive_permission_detected")),
        "sensitive_runtime_action_detected": runtime,
        "sensitive_action_detected": runtime,
        "external_or_data_movement_detected": bool(
            dynamic_flags.get("external_or_data_movement_detected")
        ),
    }

    if dangerous_permissions:
        flags["sensitive_permission_detected"] = True

    if any(any(k in str(api).lower() for k in DANGEROUS_API_KEYWORDS) for api in suspicious_apis):
        flags["sensitive_runtime_action_detected"] = True
        flags["sensitive_action_detected"] = True

    if external_urls:
        flags["external_or_data_movement_detected"] = True

    return flags


def build_behavior_profile(
    *,
    dangerous_permissions: list[str],
    filtered_events: list[dict[str, Any]],
    ioc_tiers: dict[str, list[dict[str, str]]],
    noise_result: NoiseFilterResult,
) -> dict[str, float]:
    """Per-session behavioral profile for adaptive intelligence."""
    perm_intensity = min(1.0, len(dangerous_permissions) / 5.0) if dangerous_permissions else 0.0

    activity_types = {
        (e.get("event_type") or "").lower()
        for e in filtered_events
        if isinstance(e, dict)
    }
    runtime_density = min(1.0, len(activity_types) / 4.0) if filtered_events else 0.0

    network_attempts = 1.0 if "network" in activity_types else 0.0

    tier_keys = ("TRUSTED", "NEUTRAL", "SUSPICIOUS", "MALICIOUS")
    populated = sum(1 for t in tier_keys if ioc_tiers.get(t))
    ioc_diversity = min(1.0, populated / 4.0)

    system_ratio = noise_result.system_interaction_ratio

    return {
        "permission_intensity": round(perm_intensity, 4),
        "runtime_activity_density": round(runtime_density, 4),
        "network_attempts": round(network_attempts, 4),
        "ioc_diversity": round(ioc_diversity, 4),
        "system_interaction_ratio": round(system_ratio, 4),
    }


def adaptive_risk_multiplier(
    system_interaction_ratio: float,
    *,
    small_dataset: bool = False,
    unreliable_ratio: bool = False,
) -> float:
    if small_dataset or unreliable_ratio:
        return 1.0
    if system_interaction_ratio < 0.2:
        return 1.0
    if system_interaction_ratio <= 0.5:
        return 0.85
    return 0.65


def apply_adaptive_dynamic_score(
    base_dynamic: float,
    behavior_profile: dict[str, float],
    noise_result: NoiseFilterResult | None = None,
) -> float:
    ratio = behavior_profile["system_interaction_ratio"]
    small = bool(noise_result and noise_result.small_dataset)
    unreliable = noise_result is not None and noise_result.raw_event_count == 0
    multiplier = adaptive_risk_multiplier(
        ratio,
        small_dataset=small,
        unreliable_ratio=unreliable,
    )
    return round(_clamp(base_dynamic * multiplier), 2)


def compute_dynamic_evidence(
    filtered_events: list[dict[str, Any]],
    dangerous_permissions: list[str],
    explicit_permissions: list[str],
    suspicious_apis: list[str],
    package_name: str,
    *,
    has_exfil_pattern: bool = False,
) -> dict[str, Any]:
    """Chain flags and findings from app-only events (system logs already excluded)."""
    findings: dict[str, list[str]] = {
        "runtime_behavior": [],
        "crashes_meaningful": [],
        "system_events_downgraded": [],
        "noise_filtering": [],
    }

    flags = {
        "sensitive_permission_detected": False,
        "sensitive_runtime_action_detected": False,
        "sensitive_action_detected": False,
        "external_or_data_movement_detected": False,
    }

    has_dangerous_manifest = bool(dangerous_permissions)
    permission_events = [
        e for e in filtered_events if (e.get("event_type") or "").lower() == "permission"
    ]
    perm_runtime = bool(permission_events) and has_dangerous_manifest
    network_external = any(
        (e.get("event_type") or "").lower() == "network"
        and message_has_external_endpoint(str(e.get("message") or ""))
        for e in filtered_events
    )
    app_activity = any(
        (e.get("event_type") or "").lower() in ("activity", "network", "permission")
        for e in filtered_events
    )

    if has_dangerous_manifest:
        flags["sensitive_permission_detected"] = True

    if perm_runtime:
        flags["sensitive_runtime_action_detected"] = True
        flags["sensitive_action_detected"] = True
        findings["runtime_behavior"].append(
            "Runtime permission event with dangerous manifest permission"
        )

    for event in filtered_events:
        msg = str(event.get("message") or "").lower()
        if any(m in msg for m in SENSITIVE_ACTION_MARKERS):
            flags["sensitive_runtime_action_detected"] = True
            flags["sensitive_action_detected"] = True
            findings["runtime_behavior"].append("Sensitive action marker in app log")
            break

    if network_external:
        flags["external_or_data_movement_detected"] = True
        findings["runtime_behavior"].append("Network communication to non-vendor endpoint")

    for event in filtered_events:
        msg = str(event.get("message") or "").lower()
        if any(m in msg for m in DATA_MOVEMENT_MARKERS):
            flags["external_or_data_movement_detected"] = True
            findings["runtime_behavior"].append("Data movement pattern in app log")
            break

    if has_exfil_pattern and network_external:
        flags["external_or_data_movement_detected"] = True
        findings["runtime_behavior"].append("Exfiltration pattern correlated with network activity")

    crash_loop, crash_note = detect_app_crash_loop(
        filtered_events,
        package_name,
        dangerous_permission_declared=has_dangerous_manifest,
        app_activity_observed=app_activity or perm_runtime,
    )
    if crash_loop:
        flags["sensitive_runtime_action_detected"] = True
        flags["sensitive_action_detected"] = True
        findings["crashes_meaningful"].append(crash_note)
    elif crash_note and "Fewer" not in crash_note:
        findings["system_events_downgraded"].append(crash_note)

    if not findings["runtime_behavior"]:
        findings["runtime_behavior"].append("No suspicious app runtime behavior in filtered logs")

    findings["noise_filtering"].append(
        "System logs excluded before scoring (not downweighted); app-only events used"
    )

    merged_flags = build_chain_flags(
        dangerous_permissions, suspicious_apis, [], flags,
    )
    return {"findings": findings, "chain_flags": merged_flags}


def compute_dynamic_score_base(chain_flags: dict[str, bool], findings: dict[str, list[str]]) -> float:
    """Base dynamic score from boolean signals (app-only events; no event counts)."""
    score = 0.0
    if chain_flags.get("sensitive_permission_detected"):
        score += 10.0
    runtime = chain_flags.get("sensitive_runtime_action_detected") or chain_flags.get(
        "sensitive_action_detected"
    )
    if runtime:
        score += 15.0
    if chain_flags.get("external_or_data_movement_detected"):
        score += 15.0
    if findings.get("crashes_meaningful"):
        score += 8.0
    return _clamp(score)


def compute_ioc_score_filtered(tiers: dict[str, list[dict[str, str]]]) -> float:
    """
    ioc_score = (0.6 × suspicious_count) + (1.0 × malicious_count), cap 40.

    TRUSTED and NEUTRAL never contribute.
    """
    suspicious_count = len(tiers.get("SUSPICIOUS") or [])
    malicious_count = len(tiers.get("MALICIOUS") or [])
    raw = (IOC_WEIGHT_SUSPICIOUS * suspicious_count) + (IOC_WEIGHT_MALICIOUS * malicious_count)
    return round(_clamp(min(raw, IOC_SCORE_CAP)), 2)


def _sigmoid(x: float) -> float:
    if x >= 20:
        return 1.0
    if x <= -20:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


def compute_confidence_score(
    static_score: float,
    dynamic_score: float,
    ioc_score: float,
    *,
    tiers: dict[str, list[dict[str, str]]],
    system_interaction_ratio: float,
    ioc_high_volume: bool,
    dynamic_success: bool = True,
) -> float:
    """
    confidence = sigmoid(0.4×static + 0.4×dynamic + 0.2×ioc) with penalties; [0.1, 0.99].
    """
    blend = (
        0.4 * static_score
        + 0.4 * dynamic_score
        + 0.2 * ioc_score
    )
    confidence = _sigmoid((blend - 50.0) / 12.0)

    entropy = ioc_entropy(tiers)
    if entropy > 0.7:
        confidence -= 0.15
    elif entropy < 0.2:
        confidence += 0.05

    if system_interaction_ratio > 0.5:
        confidence -= 0.10

    if ioc_high_volume:
        confidence -= 0.10
        
    if not dynamic_success:
        confidence = max(0.1, confidence * 0.5)

    return round(min(0.99, max(0.1, confidence)), 4)


def ioc_signal_strong(tiers: dict[str, list[dict[str, str]]]) -> bool:
    if tiers.get("MALICIOUS"):
        return True
    return len(tiers.get("SUSPICIOUS") or []) >= 2


def compute_fused_score(
    static_score: float,
    dynamic_score: float,
    ioc_score: float,
    *,
    valid_chain: bool,
    static_success: bool = True,
    dynamic_success: bool = True,
    ioc_success: bool = True,
) -> float:
    weights = {"static": WEIGHT_STATIC, "dynamic": WEIGHT_DYNAMIC, "ioc": WEIGHT_IOC}
    
    if not static_success:
        weights["static"] = 0.0
    if not dynamic_success:
        weights["dynamic"] = 0.0
    if not ioc_success:
        weights["ioc"] = 0.0
        
    total = sum(weights.values())
    if total > 0:
        w_s = weights["static"] / total
        w_d = weights["dynamic"] / total
        w_i = weights["ioc"] / total
    else:
        w_s = w_d = w_i = 0.0

    fused = (
        w_s * static_score
        + w_d * dynamic_score
        + w_i * ioc_score
    )
    
    highest_signal = max(
        static_score if static_success else 0,
        dynamic_score if dynamic_success else 0,
        ioc_score if ioc_success else 0
    )
    
    fused = max(fused, highest_signal)
    
    fused = _clamp(fused)
    if not valid_chain:
        fused = min(fused, float(SCORE_CAP_WITHOUT_CHAIN))
    return round(_clamp(fused), 2)


def classify_risk(
    fused_score: float,
    valid_chain: bool,
    partial_chain: bool,
    tiers: dict[str, list[dict[str, str]]],
    chain_flags: dict[str, bool],
    *,
    confidence_score: float,
) -> tuple[str, float]:
    """
    Returns (classification, possibly_capped_score).

    MALICIOUS requires score ≥ 76, valid chain, and strong IOC or external comm.
    Low-confidence MALICIOUS is downgraded to SUSPICIOUS with score capped at 74.
    """
    has_external = bool(chain_flags.get("external_or_data_movement_detected"))
    ioc_strong = ioc_signal_strong(tiers)
    score = fused_score

    if (
        score >= MALICIOUS_SCORE_THRESHOLD
        and valid_chain
        and (ioc_strong or has_external)
    ):
        classification = "MALICIOUS"
    elif score < SAFE_SCORE_THRESHOLD and not valid_chain and not partial_chain:
        classification = "SAFE"
    elif SAFE_SCORE_THRESHOLD <= score < MALICIOUS_SCORE_THRESHOLD or partial_chain:
        classification = "SUSPICIOUS"
    else:
        classification = "SUSPICIOUS"

    if classification == "MALICIOUS" and confidence_score < 0.45:
        classification = "SUSPICIOUS"
        score = min(score, float(MALICIOUS_CONFIDENCE_DOWNGRADE_CAP))

    return classification, round(_clamp(score), 2)
