"""
StaticAnalyzer — single entry point for canonical static-analysis output.
"""

from __future__ import annotations

from typing import Any

from app.models.analysis_context import AnalysisContext
from app.services.deep_static_analyzer import DeepStaticAnalyzer
from app.services.risk_engine import RiskEngine
from app.services.static.static_analysis_contract import (
    build_canonical_from_pipeline_result,
    normalize_static_analysis,
)


class StaticAnalyzer:
    """Produces canonical static-analysis dicts for fusion and explainability engines."""

    def __init__(self) -> None:
        self.risk_engine = RiskEngine()
        self.deep_analyzer = DeepStaticAnalyzer()

    def analyze(self, context: AnalysisContext) -> dict[str, Any]:
        """Analyze APK context and return a normalized canonical static payload."""
        risk_result = self.risk_engine.calculate_risk(context)
        deep_result = self.deep_analyzer.analyze(context)
        pipeline_shape = {
            "package_name": getattr(context, "package_name", "") or "",
            "permissions": getattr(context, "permissions", []) or [],
            "main_activities": getattr(context, "main_activities", []) or [],
            "risk_analysis": risk_result,
            "deep_static_analysis": deep_result,
        }
        return build_canonical_from_pipeline_result(pipeline_shape)

    def analyze_payload(self, raw: Any) -> dict[str, Any]:
        """Normalize an arbitrary static payload (e.g. cached pipeline JSON)."""
        return normalize_static_analysis(raw, source_format="static_analyzer.analyze_payload")
