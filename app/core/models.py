from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

@dataclass
class AnalysisInput:
    apk_path: str
    apk_hash: str
    source: str
    trust_level: str = "MEDIUM"
    execution_context: str = "default"
    is_apkm: bool = False

class DecisionTraceItem(BaseModel):
    rule_id: str
    feature_triggered: str
    score_impact: int

class DecisionSchema(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    verdict: str = Field(..., pattern="^(SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN)$")
    decision_trace: List[DecisionTraceItem] = []
    reasons: List[str] = []
    trust_level: str = "MEDIUM"
    failure_type: Optional[str] = None
    raw_report: Optional[Dict[str, Any]] = None
