# app/services/ai_report_generator.py

import logging
import os
from typing import Any

from google import genai

logger = logging.getLogger(__name__)

# ─── Configure Gemini ─────────────────────────────────────────────────────────

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not found in environment. AI summary will use fallback.")


# ─── Main Class ───────────────────────────────────────────────────────────────

class AIReportGenerator:
    def __init__(self, analysis: dict[str, Any]) -> None:
        self.analysis = analysis or {}
        self.static   = analysis.get("static_analysis") or {}
        self.dynamic  = analysis.get("dynamic_analysis") or {}
        self.verdict  = analysis.get("final_verdict") or {}

    def generate(self) -> str:
        """Try Gemini first. If it fails, fall back to local string report."""
        if GEMINI_API_KEY:
            try:
                return self._generate_with_gemini()
            except Exception as exc:
                logger.error(f"Gemini generation failed: {exc}. Using fallback.", exc_info=True)

        return self._generate_fallback()

    # ─── Gemini Path ──────────────────────────────────────────────────────────

    def _generate_with_gemini(self) -> str:
        package        = self.static.get("package_name", "Unknown")
        verdict        = self.verdict.get("verdict", "Unknown")
        risk_score     = self.verdict.get("final_risk_score", 0)
        confidence     = self.verdict.get("confidence", 0)
        all_perms      = self.static.get("permissions", {}).get("all", [])
        danger_perms   = self.static.get("permissions", {}).get("dangerous", [])
        sus_apis       = self.static.get("suspicious_indicators", {}).get("suspicious_apis", [])
        hardcoded_urls = self.static.get("suspicious_indicators", {}).get("hardcoded_urls", [])
        crypto_usage   = self.static.get("suspicious_indicators", {}).get("crypto_usage", [])
        dyn_status     = self.dynamic.get("status", "UNKNOWN")
        reasoning      = self.verdict.get("reasoning", [])

        prompt = f"""
You are a professional mobile security analyst. Based on the APK analysis data below,
write a detailed and professional malware analysis report.

=== APK ANALYSIS DATA ===
Package Name       : {package}
Verdict            : {verdict}
Risk Score         : {risk_score}/100
Confidence         : {confidence}
Dynamic Analysis   : {dyn_status}

Total Permissions    : {len(all_perms)}
Dangerous Permissions: {len(danger_perms)}
Dangerous List       : {', '.join(danger_perms) if danger_perms else 'None'}

Suspicious API Calls : {len(sus_apis)}
Suspicious APIs List : {', '.join(sus_apis) if sus_apis else 'None'}

Hardcoded URLs       : {', '.join(hardcoded_urls) if hardcoded_urls else 'None'}
Crypto Usage         : {', '.join(crypto_usage) if crypto_usage else 'None'}

Reasoning            : {' | '.join(reasoning) if reasoning else 'None'}

=== INSTRUCTIONS ===
Write the report with exactly these 7 sections in order:
1. EXECUTIVE SUMMARY
2. RISK SCORE
3. VERDICT
4. PACKAGE INFORMATION
5. SUSPICIOUS FINDINGS
6. PERMISSION ANALYSIS SUMMARY
7. SECURITY RECOMMENDATIONS

Rules:
- Be professional and clear
- Keep each section concise but informative
- In Security Recommendations give specific actionable advice
- If verdict is SAFE still mention any permissions or findings that need attention
- Do not use markdown formatting like ** or ##
- Separate each section with a line of 60 equal signs (=)
"""

        client   = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        return response.text.strip()

    # ─── Fallback Path (pure Python) ──────────────────────────────────────────

    def _generate_fallback(self) -> str:
        try:
            sections = [
                self._executive_summary(),
                self._risk_score(),
                self._verdict_section(),
                self._package_name(),
                self._suspicious_findings(),
                self._permission_analysis(),
                self._security_recommendations(),
            ]
            return "\n\n".join(sections)
        except Exception as exc:
            logger.error(f"Fallback generation failed: {exc}", exc_info=True)
            return "AI summary could not be generated due to an internal error."

    def _executive_summary(self) -> str:
        sep       = "=" * 60
        package   = self.static.get("package_name", "Unknown Package")
        verdict   = self.verdict.get("verdict", "Unknown")
        risk      = self.verdict.get("final_risk_score", "N/A")
        num_perms = len(self.static.get("permissions", {}).get("all", []))
        num_sus   = len(self.static.get("suspicious_indicators", {}).get("suspicious_apis", []))
        return (
            f"{sep}\nEXECUTIVE SUMMARY\n{sep}\n"
            f"Application '{package}' has been analyzed and received a "
            f"verdict of '{verdict}' with a risk score of {risk}/100.\n"
            f"The analysis identified {num_perms} permission(s) and "
            f"{num_sus} suspicious API call(s).\n"
            f"This report provides a detailed breakdown of all findings "
            f"and actionable security recommendations."
        )

    def _risk_score(self) -> str:
        sep  = "=" * 60
        risk = self.verdict.get("final_risk_score", 0) or 0
        if isinstance(risk, (int, float)):
            if risk >= 75:   level = "CRITICAL"
            elif risk >= 50: level = "HIGH"
            elif risk >= 25: level = "MEDIUM"
            else:            level = "LOW"
            label = f"{risk}/100 — {level} RISK"
        else:
            label = str(risk)
        return f"{sep}\nRISK SCORE\n{sep}\n  Overall Risk Score : {label}"

    def _verdict_section(self) -> str:
        sep        = "=" * 60
        verdict    = self.verdict.get("verdict", "Unknown")
        confidence = self.verdict.get("confidence", "N/A")
        reasoning  = self.verdict.get("reasoning", [])
        details    = " | ".join(reasoning) if reasoning else "No additional details."
        return (
            f"{sep}\nVERDICT\n{sep}\n"
            f"  Verdict    : {verdict}\n"
            f"  Confidence : {confidence}\n"
            f"  Reasoning  : {details}"
        )

    def _package_name(self) -> str:
        sep     = "=" * 60
        package = self.static.get("package_name", "Unknown")
        risk    = self.static.get("static_risk_score", "N/A")
        return (
            f"{sep}\nPACKAGE INFORMATION\n{sep}\n"
            f"  Package Name       : {package}\n"
            f"  Static Risk Score  : {risk}/100"
        )

    def _suspicious_findings(self) -> str:
        sep        = "=" * 60
        indicators = self.static.get("suspicious_indicators") or {}
        sus_apis   = indicators.get("suspicious_apis", [])
        urls       = indicators.get("hardcoded_urls", [])
        crypto     = indicators.get("crypto_usage", [])
        lines      = [sep, "SUSPICIOUS FINDINGS", sep]
        lines.append(f"  Suspicious API Calls : {', '.join(sus_apis[:10]) if sus_apis else 'None detected.'}")
        lines.append(f"  Hardcoded URLs       : {', '.join(urls[:10]) if urls else 'None detected.'}")
        lines.append(f"  Crypto Usage         : {', '.join(crypto[:5]) if crypto else 'None detected.'}")
        return "\n".join(lines)

    def _permission_analysis(self) -> str:
        sep          = "=" * 60
        perms_data   = self.static.get("permissions") or {}
        all_perms    = perms_data.get("all", [])
        danger_perms = perms_data.get("dangerous", [])
        lines = [sep, "PERMISSION ANALYSIS SUMMARY", sep,
                 f"  Total Permissions    : {len(all_perms)}",
                 f"  Dangerous Permissions: {len(danger_perms)}", ""]
        if danger_perms:
            lines.append("  Dangerous Permissions Detected:")
            for p in danger_perms:
                lines.append(f"    WARNING: {p}")
        else:
            lines.append("  No dangerous permissions detected.")
        return "\n".join(lines)

    def _security_recommendations(self) -> str:
        sep             = "=" * 60
        recommendations = []
        risk            = self.verdict.get("final_risk_score", 0) or 0
        verdict_val     = self.verdict.get("verdict", "").upper()
        danger_perms    = (self.static.get("permissions") or {}).get("dangerous", [])
        sus_apis        = (self.static.get("suspicious_indicators") or {}).get("suspicious_apis", [])
        dyn_status      = self.dynamic.get("status", "")

        if risk >= 75 or verdict_val in ("MALWARE", "MALICIOUS"):
            recommendations.append("IMMEDIATELY uninstall this application. Do not run it on production devices.")
            recommendations.append("Perform a full device scan and revoke all permissions granted to this app.")
        if danger_perms:
            recommendations.append(f"{len(danger_perms)} dangerous permission(s) found. Review whether they are necessary.")
        if sus_apis:
            recommendations.append(f"{len(sus_apis)} suspicious API call(s) detected. Review the source code.")
        if dyn_status == "FAILED":
            recommendations.append("Dynamic analysis failed. Set up ADB correctly and re-run for complete analysis.")
        if risk < 25 and not sus_apis:
            recommendations.append("No immediate threats detected. Continue standard security monitoring.")
        if not recommendations:
            recommendations.append("Exercise caution. Conduct a manual code review before distributing this app.")

        lines = [sep, "SECURITY RECOMMENDATIONS", sep]
        for i, rec in enumerate(recommendations, start=1):
            lines.append(f"  {i}. {rec}")
        return "\n".join(lines)