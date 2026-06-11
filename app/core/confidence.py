from typing import List, Dict, Any
from app.core.models import AnalysisInput

def calculate_confidence(
    analysis_input: AnalysisInput, 
    normalized_features: Dict[str, Any], 
    decision_trace: List[Dict[str, Any]], 
    dynamic_analysis: Dict[str, Any],
    static_analysis: Dict[str, Any],
    is_critical_override: bool
) -> float:
    """
    Centralized confidence scoring logic.
    Identical inputs must produce identical confidence scores across all pipelines.
    """
    confidence = 0.5
    
    # Base indicators
    if normalized_features.get("has_dynamic_evidence"):
        confidence += 0.2
        
    if isinstance(static_analysis, dict) and static_analysis.get("permissions") and static_analysis.get("api_usage"):
        confidence += 0.1
        
    if len(decision_trace) >= 3 or is_critical_override:
        confidence += 0.2
        
    if not dynamic_analysis:
        confidence -= 0.3
        
    # Source Trust impacts
    if analysis_input.trust_level == "HIGH":
        confidence += 0.15
    elif analysis_input.trust_level == "LOW":
        confidence += 0.1
        
    # Deep static completeness (simulating the web adapter's previous boost)
    # We apply this universally to maintain single-source-of-truth.
    if isinstance(static_analysis, dict) and static_analysis.get("extracted_iocs"):
        confidence += 0.1
        
    return min(max(round(confidence, 2), 0.0), 1.0)
