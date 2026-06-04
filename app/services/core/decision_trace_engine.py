"""
Deterministic decision trace for malware verdict explanations.

Reconstructs score contributions from static, dynamic, and IOC signals without
modifying upstream analyzers or the final verdict engine.
"""

from __future__ import annotations

from typing import Any

from app.services.dynamic.final_verdict_engine import (
    COMMAND_CONTROL_CONFIDENCE_THRESHOLD,
    MALWARE_SCORE_THRESHOLD,
    SAFE_SCORE_THRESHOLD,
    WEIGHT_DYNAMIC,
    WEIGHT_IOC,
    WEIGHT_STATIC,
)
from app.services.static.static_analysis_contract import normalize_static_analysis

# Must stay aligned with behavior_engine.py bonus rules.
_NETWORK_BURST_THRESHOLD = 5
_NETWORK_BURST_BONUS = 15
_PERMISSION_ABUSE_THRESHOLD = 3
_PERMISSION_ABUSE_BONUS = 10
_CRASH_LOOP_THRESHOLD = 2
_CRASH_LOOP_BONUS = 10

# Must stay aligned with static_analyzer.py scoring.
_PERMISSION_SCORE_EACH = 10
_PERMISSION_SCORE_CAP = 50
_EXPORTED_UNPROTECTED_SCORE = 15
_SUSPICIOUS_API_SCORE_EACH = 10
_URL_SCORE_EACH = 5
_URL_SCORE_CAP = 20

_IOC_DOMAIN_POINTS = 20
_IOC_IP_POINTS = 25
_IOC_URL_POINTS = 15
_IOC_SUSPICIOUS_STRING_POINTS = 10

MAJOR_ATTACK_PATTERNS = {
    "DATA_EXFILTRATION_PATTERN",
    "COMMAND_CONTROL_BEHAVIOR",
    "PRIVILEGE_ESCALATION_ATTEMPT",
}


def _impact(value: int | float) -> str:
    rounded = int(round(value))
    if rounded >= 0:
        return f"+{rounded}"
    return str(rounded)


def _ioc_risk_score(threat_intelligence: dict[str, Any] | None) -> int:
    if not threat_intelligence:
        return 0

    iocs = threat_intelligence.get("iocs")
    if not isinstance(iocs, dict):
        forensics = threat_intelligence.get("forensics") or {}
        iocs = forensics.get("iocs") or {}

    if not isinstance(iocs, dict):
        return 0

    domain_count = len(iocs.get("domains") or [])
    ip_count = len(iocs.get("ips") or [])
    url_count = len(iocs.get("urls") or [])
    suspicious_count = len(iocs.get("suspicious_strings") or [])

    if domain_count == 0 and ip_count == 0 and url_count == 0 and suspicious_count == 0:
        return 0

    score = (
        (domain_count * _IOC_DOMAIN_POINTS)
        + (ip_count * _IOC_IP_POINTS)
        + (url_count * _IOC_URL_POINTS)
        + (suspicious_count * _IOC_SUSPICIOUS_STRING_POINTS)
    )
    return min(score, 100)



def _static_component_steps(static_analysis: dict[str, Any] | None) -> list[dict[str, str]]:
    static_analysis = static_analysis or {}
    steps: list[dict[str, str]] = []

    permissions_block = static_analysis.get("permissions") or {}
    dangerous = permissions_block.get("dangerous") or []
    permission_points = min(len(dangerous) * _PERMISSION_SCORE_EACH, _PERMISSION_SCORE_CAP)
    if permission_points:
        steps.append(
            {
                "step": "dangerous_permissions",
                "source": "static",
                "impact": _impact(permission_points),
                "reason": (
                    f"{len(dangerous)} dangerous permission(s) detected "
                    f"(+{_PERMISSION_SCORE_EACH} each, cap {_PERMISSION_SCORE_CAP})."
                ),
            }
        )

    exported = (static_analysis.get("manifest_analysis") or {}).get("exported_components") or []
    exported_points = len(exported) * _EXPORTED_UNPROTECTED_SCORE
    if exported_points:
        steps.append(
            {
                "step": "exported_unprotected_components",
                "source": "static",
                "impact": _impact(exported_points),
                "reason": (
                    f"{len(exported)} exported component(s) without permission protection "
                    f"(+{_EXPORTED_UNPROTECTED_SCORE} each)."
                ),
            }
        )

    indicators = static_analysis.get("suspicious_indicators") or {}
    apis = indicators.get("suspicious_apis") or []
    api_points = len(apis) * _SUSPICIOUS_API_SCORE_EACH
    if api_points:
        keyword_preview = ", ".join(apis[:5])
        if len(apis) > 5:
            keyword_preview += ", ..."
        steps.append(
            {
                "step": "suspicious_api_keywords",
                "source": "static",
                "impact": _impact(api_points),
                "reason": (
                    f"{len(apis)} suspicious API keyword(s) in bytecode/strings "
                    f"(+{_SUSPICIOUS_API_SCORE_EACH} each): {keyword_preview}."
                ),
            }
        )

    urls = indicators.get("hardcoded_urls") or []
    url_points = min(len(urls) * _URL_SCORE_EACH, _URL_SCORE_CAP)
    if url_points:
        steps.append(
            {
                "step": "hardcoded_urls",
                "source": "static",
                "impact": _impact(url_points),
                "reason": (
                    f"{len(urls)} hardcoded URL(s) found "
                    f"(+{_URL_SCORE_EACH} each, cap {_URL_SCORE_CAP})."
                ),
            }
        )

    static_score = int(static_analysis.get("static_risk_score") or 0)
    if not steps:
        steps.append(
            {
                "step": "static_baseline",
                "source": "static",
                "impact": _impact(static_score),
                "reason": (
                    "No significant static risk indicators were detected."
                    if static_score == 0
                    else f"Static risk score reported as {static_score}/100."
                ),
            }
        )

    return steps


def _dynamic_component_steps(threat_intelligence: dict[str, Any] | None) -> list[dict[str, str]]:
    threat_intelligence = threat_intelligence or {}
    steps: list[dict[str, str]] = []

    dynamic_score = int(threat_intelligence.get("dynamic_risk_score") or threat_intelligence.get("risk_score") or 0)
    event_counts = threat_intelligence.get("event_counts") or {}
    flags = set(threat_intelligence.get("flags") or [])

    bonuses: list[tuple[str, int, str]] = []
    if int(event_counts.get("network", 0)) > _NETWORK_BURST_THRESHOLD or "NETWORK_BURST" in flags:
        bonuses.append(
            (
                "network_burst_bonus",
                _NETWORK_BURST_BONUS,
                f"Network events ({event_counts.get('network', 0)}) exceeded burst threshold "
                f"(>{_NETWORK_BURST_THRESHOLD}).",
            )
        )
    if int(event_counts.get("permission", 0)) > _PERMISSION_ABUSE_THRESHOLD or "PERMISSION_ABUSE" in flags:
        bonuses.append(
            (
                "permission_abuse_bonus",
                _PERMISSION_ABUSE_BONUS,
                f"Permission events ({event_counts.get('permission', 0)}) exceeded abuse threshold "
                f"(>{_PERMISSION_ABUSE_THRESHOLD}).",
            )
        )
    if int(event_counts.get("error", 0)) >= _CRASH_LOOP_THRESHOLD or "CRASH_LOOP" in flags:
        bonuses.append(
            (
                "crash_loop_bonus",
                _CRASH_LOOP_BONUS,
                f"Error events ({event_counts.get('error', 0)}) met crash-loop threshold "
                f"(>={_CRASH_LOOP_THRESHOLD}).",
            )
        )

    bonus_total = sum(points for _, points, _ in bonuses)
    base_score = max(dynamic_score - bonus_total, 0)

    if dynamic_score == 0 and not bonuses:
        steps.append(
            {
                "step": "dynamic_baseline",
                "source": "dynamic",
                "impact": "+0",
                "reason": "Sandbox session produced no weighted behavioral risk score.",
            }
        )
        return steps

    if base_score > 0:
        steps.append(
            {
                "step": "behavioral_event_scoring",
                "source": "dynamic",
                "impact": _impact(base_score),
                "reason": (
                    "Logcat events scored by type with temporal weighting "
                    f"(activity={event_counts.get('activity', 0)}, network={event_counts.get('network', 0)}, "
                    f"permission={event_counts.get('permission', 0)}, error={event_counts.get('error', 0)}, "
                    f"system={event_counts.get('system', 0)})."
                ),
            }
        )

    for step_name, points, reason in bonuses:
        steps.append(
            {
                "step": step_name,
                "source": "dynamic",
                "impact": _impact(points),
                "reason": reason,
            }
        )

    attack_patterns = list(threat_intelligence.get("attack_patterns") or [])
    if attack_patterns:
        steps.append(
            {
                "step": "attack_chain_patterns",
                "source": "dynamic",
                "impact": "+0",
                "reason": f"Attack chain patterns detected: {', '.join(attack_patterns)}.",
            }
        )

    risk_level = threat_intelligence.get("risk_level") or "LOW"
    steps.append(
        {
            "step": "dynamic_risk_aggregate",
            "source": "dynamic",
            "impact": _impact(dynamic_score),
            "reason": f"Dynamic behavioral risk level {risk_level} (score {dynamic_score}/100).",
        }
    )

    return steps


def _ioc_component_steps(threat_intelligence: dict[str, Any] | None) -> list[dict[str, str]]:
    threat_intelligence = threat_intelligence or {}
    steps: list[dict[str, str]] = []

    iocs = threat_intelligence.get("iocs")
    if not isinstance(iocs, dict):
        forensics = threat_intelligence.get("forensics") or {}
        iocs = forensics.get("iocs") or {}

    if not isinstance(iocs, dict):
        return steps

    domains = iocs.get("domains") or []
    ips = iocs.get("ips") or []
    urls = iocs.get("urls") or []
    suspicious_strings = iocs.get("suspicious_strings") or []

    if domains:
        points = len(domains) * _IOC_DOMAIN_POINTS
        steps.append(
            {
                "step": "ioc_domains",
                "source": "ioc",
                "impact": _impact(points),
                "reason": f"{len(domains)} domain IOC(s) extracted (+{_IOC_DOMAIN_POINTS} each).",
            }
        )

    if ips:
        points = len(ips) * _IOC_IP_POINTS
        steps.append(
            {
                "step": "ioc_ip_addresses",
                "source": "ioc",
                "impact": _impact(points),
                "reason": f"{len(ips)} IP IOC(s) extracted (+{_IOC_IP_POINTS} each).",
            }
        )

    if urls:
        points = len(urls) * _IOC_URL_POINTS
        steps.append(
            {
                "step": "ioc_urls",
                "source": "ioc",
                "impact": _impact(points),
                "reason": f"{len(urls)} URL IOC(s) extracted (+{_IOC_URL_POINTS} each).",
            }
        )

    if suspicious_strings:
        points = len(suspicious_strings) * _IOC_SUSPICIOUS_STRING_POINTS
        steps.append(
            {
                "step": "ioc_suspicious_strings",
                "source": "ioc",
                "impact": _impact(points),
                "reason": (
                    f"{len(suspicious_strings)} suspicious string IOC(s) "
                    f"(+{_IOC_SUSPICIOUS_STRING_POINTS} each)."
                ),
            }
        )


    ioc_score = _ioc_risk_score(threat_intelligence)
    if not steps:
        steps.append(
            {
                "step": "ioc_baseline",
                "source": "ioc",
                "impact": "+0",
                "reason": "No network or credential IOCs were extracted from session forensics.",
            }
        )
    else:
        steps.append(
            {
                "step": "ioc_risk_aggregate",
                "source": "ioc",
                "impact": _impact(ioc_score),
                "reason": f"IOC risk score {ioc_score}/100 (capped at 100).",
            }
        )

    return steps


def _fusion_steps(
    dynamic_score: int,
    static_score: int,
    ioc_score: int,
    final_risk_score: int,
) -> list[dict[str, str]]:
    dynamic_weighted = int(round(dynamic_score * WEIGHT_DYNAMIC))
    static_weighted = int(round(static_score * WEIGHT_STATIC))
    ioc_weighted = int(round(ioc_score * WEIGHT_IOC))

    return [
        {
            "step": "fuse_dynamic_signal",
            "source": "fusion",
            "impact": _impact(dynamic_weighted),
            "reason": (
                f"Dynamic score {dynamic_score}/100 weighted at {WEIGHT_DYNAMIC:.0%} "
                f"→ {dynamic_weighted} points toward fusion."
            ),
        },
        {
            "step": "fuse_static_signal",
            "source": "fusion",
            "impact": _impact(static_weighted),
            "reason": (
                f"Static score {static_score}/100 weighted at {WEIGHT_STATIC:.0%} "
                f"→ {static_weighted} points toward fusion."
            ),
        },
        {
            "step": "fuse_ioc_signal",
            "source": "fusion",
            "impact": _impact(ioc_weighted),
            "reason": (
                f"IOC score {ioc_score}/100 weighted at {WEIGHT_IOC:.0%} "
                f"→ {ioc_weighted} points toward fusion."
            ),
        },
        {
            "step": "final_risk_fusion",
            "source": "fusion",
            "impact": _impact(final_risk_score),
            "reason": (
                f"Weighted fusion: ({dynamic_score}×{WEIGHT_DYNAMIC}) + "
                f"({static_score}×{WEIGHT_STATIC}) + ({ioc_score}×{WEIGHT_IOC}) "
                f"= {final_risk_score}/100."
            ),
        },
    ]


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


def _build_final_explanation(
    verdict: str,
    confidence: float,
    final_risk_score: int,
    dynamic_score: int,
    static_score: int,
    ioc_score: int,
    attack_patterns: list[str],
    threat_intelligence: dict[str, Any] | None,
    static_analysis: dict[str, Any] | None,
) -> str:
    threat_intelligence = threat_intelligence or {}
    static_analysis = static_analysis or {}
    pattern_set = set(attack_patterns)

    sentences: list[str] = [
        (
            f"The engine reached a {verdict} verdict with {confidence:.0%} confidence "
            f"from a fused risk score of {final_risk_score}/100."
        ),
    ]

    if dynamic_score >= static_score and dynamic_score >= ioc_score and dynamic_score > 0:
        sentences.append(
            f"Dynamic sandbox behavior was the dominant signal (raw score {dynamic_score}/100, "
            f"{WEIGHT_DYNAMIC:.0%} fusion weight), driven by log-derived events and pattern detection."
        )
    elif static_score >= dynamic_score and static_score >= ioc_score and static_score > 0:
        sentences.append(
            f"Static APK inspection was the dominant signal (raw score {static_score}/100, "
            f"{WEIGHT_STATIC:.0%} fusion weight), reflecting manifest and bytecode risk indicators."
        )
    elif ioc_score > 0:
        sentences.append(
            f"Forensic IOC extraction contributed materially (raw IOC score {ioc_score}/100, "
            f"{WEIGHT_IOC:.0%} fusion weight) from domains, IPs, or suspicious strings."
        )
    else:
        sentences.append(
            "Dynamic, static, and IOC channels contributed little combined risk, "
            "keeping the fused score near baseline."
        )

    if attack_patterns:
        sentences.append(
            f"Attack patterns ({', '.join(attack_patterns)}) were considered alongside numeric thresholds."
        )
    elif final_risk_score < SAFE_SCORE_THRESHOLD:
        sentences.append(
            f"The fused score remained below the safe threshold ({SAFE_SCORE_THRESHOLD}), "
            "so escalation was not warranted."
        )
    elif final_risk_score >= MALWARE_SCORE_THRESHOLD:
        sentences.append(
            f"The fused score met or exceeded the malware threshold ({MALWARE_SCORE_THRESHOLD}), "
            "supporting a malicious classification."
        )
    else:
        sentences.append(
            f"The fused score sat between safe ({SAFE_SCORE_THRESHOLD}) and malware "
            f"({MALWARE_SCORE_THRESHOLD}) thresholds, producing a cautious middle verdict."
        )

    if verdict == "MALWARE" and "DATA_EXFILTRATION_PATTERN" in pattern_set:
        sentences.append(
            "The verdict was elevated because data exfiltration was observed with a high composite risk score."
        )
    elif verdict == "MALWARE" and "COMMAND_CONTROL_BEHAVIOR" in pattern_set:
        sentences.append(
            "The verdict was elevated due to command-and-control behavior with confidence above "
            f"{COMMAND_CONTROL_CONFIDENCE_THRESHOLD:.0%}."
        )
    elif verdict == "SUSPICIOUS" and _is_crash_loop_only(attack_patterns, threat_intelligence):
        sentences.append(
            "The sample was marked suspicious because crash-loop indicators appeared without broader attack chains."
        )
    else:
        threat_type = (threat_intelligence.get("threat_classification") or {}).get("threat_type")
        static_summary = static_analysis.get("summary") or []
        if threat_type:
            sentences.append(f"Dynamic threat classification: {threat_type}.")
        elif static_summary:
            sentences.append(static_summary[0].rstrip("."))

    return " ".join(sentences[:6])


class DecisionTraceEngine:
    """Builds a deterministic audit trail for malware verdict decisions."""

    @staticmethod
    def build(
        static_analysis: dict[str, Any] | None,
        threat_intelligence: dict[str, Any] | None,
        final_verdict: dict[str, Any] | None = None,
        *,
        runtime_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Reconstruct the decision path and human-readable explanation.
        """
        static_analysis = normalize_static_analysis(static_analysis)
        runtime_result = runtime_result or threat_intelligence or {}
        final_verdict = final_verdict or {}

        dynamic_score = int(runtime_result.get("dynamic_risk_score") or runtime_result.get("risk_score") or 0)
        static_score = int(static_analysis.get("static_risk_score") or 0)
        ioc_score = _ioc_risk_score(runtime_result)
        final_risk_score = int(final_verdict.get("final_risk_score") or 0)
        verdict = str(final_verdict.get("verdict") or "SAFE")
        confidence = float(final_verdict.get("confidence") or 0.0)

        # Merge attack patterns from both static and dynamic analyses
        static_patterns = static_analysis.get("attack_patterns", []) or []
        runtime_patterns = runtime_result.get("attack_patterns", []) or []
        attack_patterns = list(set(static_patterns + runtime_patterns))

        decision_trace: list[dict[str, str]] = []
        decision_trace.extend(_static_component_steps(static_analysis))
        decision_trace.extend(_dynamic_component_steps(runtime_result))
        decision_trace.extend(_ioc_component_steps(runtime_result))
        decision_trace.extend(
            _fusion_steps(dynamic_score, static_score, ioc_score, final_risk_score)
        )

        final_explanation = _build_final_explanation(
            verdict=verdict,
            confidence=confidence,
            final_risk_score=final_risk_score,
            dynamic_score=dynamic_score,
            static_score=static_score,
            ioc_score=ioc_score,
            attack_patterns=attack_patterns,
            threat_intelligence=runtime_result,
            static_analysis=static_analysis,
        )

        return {
            "decision_trace": decision_trace,
            "final_explanation": final_explanation,
        }

