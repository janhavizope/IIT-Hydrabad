import os
import threading
import logging
import concurrent.futures
from typing import Callable, Any
from app.core.models import DecisionSchema, DecisionTraceItem

logger = logging.getLogger(__name__)

# Global concurrency limit to prevent ADB collisions
_sandbox_semaphore = threading.Semaphore(2)

class AnalysisOrchestrator:
    @staticmethod
    def _fallback_schema(analysis_input: Any, msg: str, fail_type: str, rule_id: str = "E000") -> DecisionSchema:
        """Unified error normalization layer."""
        trust = getattr(analysis_input, 'trust_level', 'LOW') if analysis_input else 'LOW'
        return DecisionSchema(
            risk_score=60.0,
            confidence=0.1,
            verdict="SUSPICIOUS",
            decision_trace=[
                DecisionTraceItem(rule_id=rule_id, feature_triggered=msg, score_impact=60)
            ],
            reasons=[msg, "Fallback to suspicious."],
            trust_level=trust,
            failure_type=fail_type
        )

    @staticmethod
    def analyze_apk(engine_func: Callable, analysis_input: Any, queue_timeout: int = 60, exec_timeout: int = 300) -> DecisionSchema:
        """
        Manages concurrency limits and queueing. Enforces strict schema, execution bounds, and global validation.
        """
        # Global Input Validation
        if not analysis_input or not getattr(analysis_input, 'apk_path', None):
            return AnalysisOrchestrator._fallback_schema(analysis_input, "Invalid input. No APK path provided.", "INVALID_FORMAT", "E001")
        
        if not os.path.exists(analysis_input.apk_path) or os.path.getsize(analysis_input.apk_path) == 0:
            return AnalysisOrchestrator._fallback_schema(analysis_input, "APK file is missing or empty/corrupted.", "INVALID_FORMAT", "E002")

        logger.info("[Orchestrator] Waiting for execution lock...")
        acquired = _sandbox_semaphore.acquire(timeout=queue_timeout)
        if not acquired:
            logger.warning("[Orchestrator] Timeout waiting for execution queue.")
            return AnalysisOrchestrator._fallback_schema(analysis_input, "Queue timeout reached. Sandbox busy.", "TIMEOUT", "E003")
        
        logger.info("[Orchestrator] Lock acquired. Starting execution.")
        try:
            # Enforce deterministic bounded execution window
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(engine_func, analysis_input)
                result = future.result(timeout=exec_timeout)
                
            # Verify strict schema compliance before delivery
            if not isinstance(result, DecisionSchema):
                return AnalysisOrchestrator._fallback_schema(analysis_input, "Engine returned invalid schema type.", "PIPELINE_ERROR", "E004")
            return result

        except concurrent.futures.TimeoutError:
            logger.error("[Orchestrator] Execution timed out!")
            return AnalysisOrchestrator._fallback_schema(analysis_input, "Engine execution timed out.", "TIMEOUT", "E005")
        except Exception as e:
            logger.error(f"[Orchestrator] Execution failed: {e}")
            return AnalysisOrchestrator._fallback_schema(analysis_input, f"Engine execution error: {e}", "PIPELINE_ERROR", "E006")
        finally:
            _sandbox_semaphore.release()
            logger.info("[Orchestrator] Lock released.")

