SCHEMA_VERSION = 1


def normalize_static_analysis(result):
    """
    Standardized static analysis schema normalizer.
    Accepts raw analyzer output and guarantees stable structure.
    """

    if not isinstance(result, dict):
        result = {}

    permissions = result.get("permissions") or {}

    # FIX: handle both list and dict formats safely
    if isinstance(permissions, list):
        permissions = {
            "all": permissions,
            "dangerous": []
        }

    if not isinstance(permissions, dict):
        permissions = {
            "all": [],
            "dangerous": []
        }

    return {
        "schema_version": result.get("schema_version", SCHEMA_VERSION),
        "package_name": result.get("package_name", ""),

        "static_risk_score": int(result.get("static_risk_score") or 0),

        "permissions": {
            "all": permissions.get("all", []),
            "dangerous": permissions.get("dangerous", [])
        },

        "manifest_analysis": result.get("manifest_analysis", {}) or {},
        "attack_patterns": result.get("attack_patterns", []) or [],
        "suspicious_indicators": result.get("suspicious_indicators", {}) or {},
        "extracted_iocs": result.get("extracted_iocs", {}) or {},
        "summary": result.get("summary", []) or []
    }


build_canonical_from_pipeline_result = normalize_static_analysis