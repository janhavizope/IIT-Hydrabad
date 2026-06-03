"""
Canonical static-analysis contract for fusion, decision trace, and FP engines.

All downstream consumers must receive output from normalize_static_analysis() or
StaticAnalyzer.analyze() — never raw pipeline dicts with a flat permissions list.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

SCHEMA_VERSION = 1

# Aligned with app.services.risk_engine.RiskEngine permission_scores keys.
DANGEROUS_PERMISSION_NAMES = frozenset(
    {
        "READ_SMS",
        "SEND_SMS",
        "RECEIVE_SMS",
        "WRITE_EXTERNAL_STORAGE",
        "READ_CONTACTS",
        "ACCESS_FINE_LOCATION",
        "RECORD_AUDIO",
        "INTERNET",
        "ACCESS_NETWORK_STATE",
    }
)

# Aligned with decision_trace_engine._static_component_steps scoring.
_PERMISSION_SCORE_EACH = 10
_PERMISSION_SCORE_CAP = 50
_EXPORTED_UNPROTECTED_SCORE = 15
_SUSPICIOUS_API_SCORE_EACH = 10
_URL_SCORE_EACH = 5
_URL_SCORE_CAP = 20


def _empty_canonical() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "package_name": "",
        "static_risk_score": 0,
        "permissions": {"all": [], "dangerous": []},
        "manifest_analysis": {"exported_components": [], "risk_flags": []},
        "suspicious_indicators": {
            "suspicious_apis": [],
            "hardcoded_urls": [],
            "crypto_usage": [],
            "obfuscation_signs": [],
        },
        "summary": [],
        "_meta": {
            "normalized": True,
            "source_format": "empty",
            "warnings": [],
        },
    }


def _permission_basename(permission: str) -> str:
    return str(permission).strip().split(".")[-1]


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return []


def _extract_dangerous_from_flat_list(
    all_permissions: list[str],
    risk_analysis: dict[str, Any] | None,
) -> list[str]:
    """Map flat manifest permissions to dangerous subset using risk flags or catalog."""
    risk_analysis = risk_analysis or {}
    flags = {_permission_basename(flag) for flag in _coerce_str_list(risk_analysis.get("flags"))}

    dangerous: list[str] = []
    for permission in all_permissions:
        base = _permission_basename(permission)
        if base in flags or base in DANGEROUS_PERMISSION_NAMES:
            dangerous.append(permission)
    return dangerous


def _resolve_permissions_block(
    permissions_raw: Any,
    risk_analysis: dict[str, Any] | None,
    warnings: list[str],
) -> dict[str, list[str]]:
    if isinstance(permissions_raw, dict):
        dangerous = _coerce_str_list(permissions_raw.get("dangerous"))
        all_permissions = _coerce_str_list(permissions_raw.get("all"))
        if not all_permissions and dangerous:
            all_permissions = list(dangerous)
        if dangerous and not all_permissions:
            warnings.append("permissions.dangerous present without permissions.all")
        if all_permissions and not dangerous:
            dangerous = _extract_dangerous_from_flat_list(all_permissions, risk_analysis)
            if dangerous:
                warnings.append("permissions.dangerous derived from flat all list + risk flags")
        return {"all": all_permissions, "dangerous": dangerous}

    if isinstance(permissions_raw, list):
        all_permissions = _coerce_str_list(permissions_raw)
        dangerous = _extract_dangerous_from_flat_list(all_permissions, risk_analysis)
        warnings.append(
            "legacy format: top-level permissions was a list; normalized to "
            '{"permissions": {"all": [...], "dangerous": [...]}}'
        )
        return {"all": all_permissions, "dangerous": dangerous}

    if permissions_raw not in (None, {}):
        warnings.append(f"ignored invalid permissions type: {type(permissions_raw).__name__}")
    return {"all": [], "dangerous": []}


def _manifest_from_raw(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    manifest = data.get("manifest_analysis")
    if isinstance(manifest, dict):
        return {
            "exported_components": _coerce_str_list(manifest.get("exported_components")),
            "risk_flags": _coerce_str_list(manifest.get("risk_flags")),
        }

    risk_flags = _coerce_str_list(data.get("risk_flags"))
    if risk_flags and not isinstance(manifest, dict):
        warnings.append("promoted top-level risk_flags into manifest_analysis.risk_flags")
    return {
        "exported_components": [],
        "risk_flags": risk_flags,
    }


def _indicators_from_raw(data: dict[str, Any], warnings: list[str]) -> dict[str, Any]:
    indicators = data.get("suspicious_indicators")
    if isinstance(indicators, dict):
        return {
            "suspicious_apis": _coerce_str_list(indicators.get("suspicious_apis")),
            "hardcoded_urls": _coerce_str_list(indicators.get("hardcoded_urls")),
            "crypto_usage": _coerce_str_list(indicators.get("crypto_usage")),
            "obfuscation_signs": _coerce_str_list(indicators.get("obfuscation_signs")),
        }

    deep = data.get("deep_static_analysis")
    if isinstance(deep, dict):
        warnings.append("mapped deep_static_analysis into suspicious_indicators (legacy pipeline)")
        return {
            "suspicious_apis": _coerce_str_list(deep.get("suspicious_apis")),
            "hardcoded_urls": _coerce_str_list(deep.get("suspicious_urls")),
            "crypto_usage": _coerce_str_list(deep.get("crypto_usage")),
            "obfuscation_signs": _coerce_str_list(deep.get("obfuscation_signs")),
        }

    return {
        "suspicious_apis": [],
        "hardcoded_urls": [],
        "crypto_usage": [],
        "obfuscation_signs": [],
    }


def compute_static_risk_score(canonical: dict[str, Any]) -> int:
    """Same component weights as decision_trace_engine._static_component_steps."""
    permissions = canonical.get("permissions") or {}
    dangerous = permissions.get("dangerous") or []
    manifest = canonical.get("manifest_analysis") or {}
    indicators = canonical.get("suspicious_indicators") or {}

    permission_points = min(len(dangerous) * _PERMISSION_SCORE_EACH, _PERMISSION_SCORE_CAP)
    exported_points = len(manifest.get("exported_components") or []) * _EXPORTED_UNPROTECTED_SCORE
    api_points = len(indicators.get("suspicious_apis") or []) * _SUSPICIOUS_API_SCORE_EACH
    url_points = min(
        len(indicators.get("hardcoded_urls") or []) * _URL_SCORE_EACH,
        _URL_SCORE_CAP,
    )
    return min(permission_points + exported_points + api_points + url_points, 100)


def _build_summary(
    package_name: str,
    permissions: dict[str, list[str]],
    indicators: dict[str, Any],
    static_risk_score: int,
) -> list[str]:
    dangerous_count = len(permissions.get("dangerous") or [])
    api_count = len(indicators.get("suspicious_apis") or [])
    url_count = len(indicators.get("hardcoded_urls") or [])
    parts = [f"Static risk score {static_risk_score}/100"]
    if package_name:
        parts.append(f"for package {package_name}")
    if dangerous_count:
        parts.append(f"with {dangerous_count} dangerous permission(s)")
    if api_count:
        parts.append(f"{api_count} suspicious API indicator(s)")
    if url_count:
        parts.append(f"{url_count} hardcoded URL(s)")
    return [", ".join(parts) + "."]


def normalize_static_analysis(
    data: Any,
    *,
    source_format: str = "unknown",
) -> dict[str, Any]:
    """
    Coerce any static-analysis payload into the canonical dict schema.

    Handles:
    - canonical dict (pass-through with validation)
    - legacy pipeline dict (flat permissions list, deep_static_analysis sibling)
    - mistaken list root (interpreted as permissions list)
    """
    warnings: list[str] = []

    if data is None:
        empty = _empty_canonical()
        empty["_meta"]["source_format"] = source_format
        return empty

    if isinstance(data, list):
        warnings.append("static_analysis root was a list; treating as permissions list")
        data = {"permissions": data}
        source_format = f"{source_format}+list_root"

    if not isinstance(data, dict):
        warnings.append(f"static_analysis root type {type(data).__name__} is invalid; using empty")
        empty = _empty_canonical()
        empty["_meta"]["warnings"] = warnings
        empty["_meta"]["source_format"] = source_format
        return empty

    risk_analysis = data.get("risk_analysis") if isinstance(data.get("risk_analysis"), dict) else {}
    permissions = _resolve_permissions_block(data.get("permissions"), risk_analysis, warnings)
    manifest_analysis = _manifest_from_raw(data, warnings)
    suspicious_indicators = _indicators_from_raw(data, warnings)

    if not manifest_analysis["risk_flags"] and risk_analysis.get("flags"):
        manifest_analysis["risk_flags"] = _coerce_str_list(risk_analysis.get("flags"))
        warnings.append("copied risk_analysis.flags into manifest_analysis.risk_flags")

    canonical = _empty_canonical()
    canonical["package_name"] = str(data.get("package_name") or "")
    canonical["permissions"] = permissions
    canonical["manifest_analysis"] = manifest_analysis
    canonical["suspicious_indicators"] = suspicious_indicators

    existing_score = data.get("static_risk_score")
    computed_score = compute_static_risk_score(canonical)
    if existing_score is not None:
        try:
            existing_int = int(existing_score)
        except (TypeError, ValueError):
            existing_int = computed_score
            warnings.append("static_risk_score was non-numeric; replaced with computed score")
        if existing_int != computed_score:
            warnings.append(
                f"static_risk_score {existing_int} differs from component sum {computed_score}; "
                "using computed score for downstream consistency"
            )
        canonical["static_risk_score"] = computed_score
    else:
        canonical["static_risk_score"] = computed_score

    summary = data.get("summary")
    if isinstance(summary, list) and summary:
        canonical["summary"] = [str(item) for item in summary]
    else:
        canonical["summary"] = _build_summary(
            canonical["package_name"],
            permissions,
            suspicious_indicators,
            canonical["static_risk_score"],
        )

    if isinstance(data.get("risk_analysis"), dict):
        canonical["legacy_risk_analysis"] = deepcopy(data["risk_analysis"])
    if isinstance(data.get("deep_static_analysis"), dict):
        canonical["legacy_deep_static_analysis"] = deepcopy(data["deep_static_analysis"])
    if data.get("main_activities") is not None:
        canonical["main_activities"] = _coerce_str_list(data.get("main_activities"))

    canonical["_meta"] = {
        "normalized": True,
        "source_format": source_format,
        "warnings": warnings,
    }
    return canonical


def build_canonical_from_pipeline_result(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    """
    Build canonical static analysis from legacy pipeline / run_apk_test output.

    Expected pipeline_result keys: package_name, permissions (list), risk_analysis,
    deep_static_analysis, main_activities (optional).
    """
    return normalize_static_analysis(pipeline_result, source_format="legacy_pipeline")


def validate_canonical_static_analysis(data: dict[str, Any]) -> list[str]:
    """Return validation errors; empty list means structurally valid."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["static_analysis must be a dict"]
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        errors.append("permissions must be a dict")
    elif not isinstance(permissions.get("dangerous"), list):
        errors.append("permissions.dangerous must be a list")
    manifest = data.get("manifest_analysis")
    if manifest is not None and not isinstance(manifest, dict):
        errors.append("manifest_analysis must be a dict")
    indicators = data.get("suspicious_indicators")
    if indicators is not None and not isinstance(indicators, dict):
        errors.append("suspicious_indicators must be a dict")
    return errors
