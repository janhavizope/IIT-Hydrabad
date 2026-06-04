"""
Adaptive attack-chain validation — weighted strength, no fabricated timelines.
"""

from __future__ import annotations

from typing import Any

from app.services.core.assessment.constants import CHAIN_STRENGTH_THRESHOLD, NO_VALID_ATTACK_CHAIN

_CHAIN_WEIGHTS = {
    "sensitive_permission_detected": 0.4,
    "sensitive_runtime_action_detected": 0.3,
    "external_or_data_movement_detected": 0.3,
}


def _runtime_detected(chain_flags: dict[str, bool]) -> bool:
    return bool(
        chain_flags.get("sensitive_runtime_action_detected")
        or chain_flags.get("sensitive_action_detected")
    )


def compute_chain_strength(
    chain_flags: dict[str, bool],
    observability: dict[str, bool] | None = None,
) -> float:
    """
    Weighted strength normalized by sum of available (observable) weights only.
    """
    obs = observability or {key: True for key in _CHAIN_WEIGHTS}

    flags = {
        "sensitive_permission_detected": bool(chain_flags.get("sensitive_permission_detected")),
        "sensitive_runtime_action_detected": _runtime_detected(chain_flags),
        "external_or_data_movement_detected": bool(
            chain_flags.get("external_or_data_movement_detected")
        ),
    }

    numerator = 0.0
    denominator = 0.0
    for key, weight in _CHAIN_WEIGHTS.items():
        if not obs.get(key, True):
            continue
        denominator += weight
        if flags.get(key):
            numerator += weight

    if denominator <= 0.0:
        return 0.0
    return round(numerator / denominator, 4)


def build_chain_observability(
    *,
    has_manifest_permissions: bool,
    has_filtered_events: bool,
    has_network_or_static_urls: bool,
) -> dict[str, bool]:
    return {
        "sensitive_permission_detected": has_manifest_permissions,
        "sensitive_runtime_action_detected": has_filtered_events,
        "external_or_data_movement_detected": has_network_or_static_urls,
    }


def evaluate_attack_chain(
    chain_flags: dict[str, bool],
    observability: dict[str, bool] | None = None,
) -> tuple[bool, bool, float, list[str] | str, dict[str, bool]]:
    """
    Returns (valid_chain, partial_chain, chain_strength, attack_chain_output, validation_flags).
    """
    validation_flags = {
        "sensitive_permission_detected": bool(chain_flags.get("sensitive_permission_detected")),
        "sensitive_runtime_action_detected": _runtime_detected(chain_flags),
        "external_or_data_movement_detected": bool(
            chain_flags.get("external_or_data_movement_detected")
        ),
    }

    chain_strength = compute_chain_strength(validation_flags, observability)
    valid_chain = chain_strength >= CHAIN_STRENGTH_THRESHOLD
    partial_chain = 0.0 < chain_strength < CHAIN_STRENGTH_THRESHOLD

    if not valid_chain:
        return False, partial_chain, chain_strength, NO_VALID_ATTACK_CHAIN, validation_flags

    summary = (
        f"Adaptive chain validated (strength={chain_strength:.2f}): permission, "
        "runtime action, and external/data movement signals from static and/or dynamic modules"
    )
    return True, partial_chain, chain_strength, [summary], validation_flags
