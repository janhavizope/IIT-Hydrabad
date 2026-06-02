import os
import time
import uuid
from typing import Any

from app.services.dynamic.behavior_engine import BehaviorEngine, detect_attack_chain, extract_network_domains
from app.services.dynamic.log_parser import parse_logs
from app.utils import adb_utils
from app.utils.adb_utils import AdbCommandError, AdbNotFoundError, run_adb_command

DEFAULT_ADB_PATH = r"C:\Users\janhavi\AppData\Local\Android\Sdk\platform-tools\adb.exe"
INSTALL_SDK_TOO_LOW = "INSTALL_FAILED_DEPRECATED_SDK_VERSION"
MAX_LOG_LINES = 500


def get_adb_path() -> str:
    """Return configured adb.exe path (env ADB_PATH overrides adb_utils.ADB_PATH)."""
    env_path = os.environ.get("ADB_PATH", "").strip()
    return env_path or adb_utils.ADB_PATH or DEFAULT_ADB_PATH


def run_adb_safe(args: list[str], timeout: float | None = None) -> dict[str, Any]:
    """
    Windows-safe adb wrapper. Never raises; always uses full adb.exe path via adb_utils.
    """
    adb_path = get_adb_path()
    adb_utils.ADB_PATH = adb_path
    adb_utils.ADB_BINARY = adb_path
    if not os.path.isfile(adb_path):
        return {
            "success": False,
            "output": "",
            "error": (
                f"adb.exe not found at: {adb_path}. "
                "Set ADB_PATH env var or update adb_utils.ADB_PATH."
            ),
            "error_type": "ADB_NOT_FOUND",
            "adb_path": adb_path,
        }

    try:
        output = run_adb_command(args, timeout=timeout)
        return {
            "success": True,
            "output": output,
            "error": None,
            "error_type": None,
            "adb_path": adb_path,
        }
    except AdbNotFoundError as exc:
        return {
            "success": False,
            "output": "",
            "error": str(exc),
            "error_type": "ADB_NOT_FOUND",
            "adb_path": adb_path,
        }
    except AdbCommandError as exc:
        return {
            "success": False,
            "output": exc.output,
            "error": str(exc),
            "error_type": "ADB_COMMAND_FAILED",
            "returncode": exc.returncode,
            "adb_path": adb_path,
        }
    except Exception as exc:
        return {
            "success": False,
            "output": "",
            "error": str(exc),
            "error_type": "UNKNOWN",
            "adb_path": adb_path,
        }


class SandboxController:
    """Dynamic Analysis Sandbox Controller (MVP Orchestrator)."""

    def __init__(self) -> None:
        self.behavior_engine = BehaviorEngine()
        self.session_state: dict[str, dict[str, Any]] = {}
        self.global_behavior_cache: dict[str, dict[str, Any]] = {}

    def _reset_session_state(self, session_id: str) -> None:
        """Reset per-session memory for behavior intelligence."""
        self.session_state = {
            session_id: {
                "event_counts": {event_type: 0 for event_type in ("activity", "network", "permission", "error", "system")},
                "last_events": [],
                "accumulated_score": 0,
            }
        }

    def _update_session_state(self, session_id: str, parsed_events: list[dict[str, Any]], risk_output: dict[str, Any]) -> None:
        state = self.session_state.setdefault(
            session_id,
            {
                "event_counts": {event_type: 0 for event_type in ("activity", "network", "permission", "error", "system")},
                "last_events": [],
                "accumulated_score": 0,
            },
        )
        state["event_counts"] = dict(risk_output.get("event_counts") or state["event_counts"])
        state["last_events"] = risk_output.get("dedupe_signatures", [])
        state["accumulated_score"] = int(risk_output.get("risk_score", 0))
        state["deduplicated_event_count"] = risk_output.get("deduplicated_event_count", len(parsed_events))
        state["raw_event_count"] = risk_output.get("raw_event_count", len(parsed_events))
        state["attack_patterns"] = list(risk_output.get("attack_patterns") or [])
        state["evidence"] = list(risk_output.get("evidence") or [])

    def _cross_session_confidence_boost(
        self,
        package_name: str,
        attack_patterns: list[str],
        network_domains: list[str],
    ) -> float:
        """
        Optional confidence boost (max +0.05) from repeated cross-session behavior.
        """
        if not package_name:
            return 0.0

        cache = self.global_behavior_cache.get(package_name)
        if not cache or int(cache.get("session_count", 0)) < 1:
            return 0.0

        boost = 0.0
        known_patterns = set(cache.get("attack_patterns") or [])
        repeated_patterns = [pattern for pattern in attack_patterns if pattern in known_patterns]
        if repeated_patterns:
            boost += 0.03 * min(len(repeated_patterns), 2)

        known_domains = set(cache.get("network_domains") or [])
        repeated_domains = [domain for domain in network_domains if domain in known_domains]
        if repeated_domains:
            boost += 0.02

        return min(0.05, round(boost, 3))

    def _update_global_behavior_cache(
        self,
        package_name: str,
        parsed_events: list[dict[str, Any]],
        risk_output: dict[str, Any],
    ) -> None:
        """Track repeated package-level behavior across dynamic sessions."""
        if not package_name:
            return

        cache = self.global_behavior_cache.setdefault(
            package_name,
            {
                "package_name": package_name,
                "session_count": 0,
                "attack_patterns": [],
                "network_domains": [],
            },
        )
        cache["session_count"] = int(cache.get("session_count", 0)) + 1

        for pattern in risk_output.get("attack_patterns") or []:
            if pattern not in cache["attack_patterns"]:
                cache["attack_patterns"].append(pattern)

        for domain in extract_network_domains(parsed_events):
            if domain not in cache["network_domains"]:
                cache["network_domains"].append(domain)

    def _response(self, success: bool, **kwargs: Any) -> dict[str, Any]:
        return {"success": success, **kwargs}

    def _parse_devices(self, adb_output: str) -> list[dict[str, str]]:
        devices: list[dict[str, str]] = []
        for line in adb_output.splitlines():
            if "\tdevice" in line:
                serial = line.split("\t")[0].strip()
                devices.append({"serial": serial, "state": "device"})
        return devices

    def _classify_install_failure(self, output: str) -> dict[str, Any] | None:
        text = output or ""
        if INSTALL_SDK_TOO_LOW in text:
            return {
                "error_type": "SDK_VERSION_TOO_LOW",
                "suggestion": "rebuild APK with targetSdk >= 24 OR use debug bypass flag",
                "failure_reason": INSTALL_SDK_TOO_LOW,
            }
        if "INSTALL_FAILED" in text:
            return {
                "error_type": "INSTALL_FAILED",
                "failure_reason": text.strip().splitlines()[-1] if text.strip() else "INSTALL_FAILED",
            }
        return None

    def _install_attempt(self, apk_path: str, bypass_low_sdk: bool = False) -> dict[str, Any]:
        normalized_apk = os.path.normpath(os.path.abspath(apk_path))
        args = ["install", "-r"]
        if bypass_low_sdk:
            args.append("--bypass-low-target-sdk-block")
        args.append(normalized_apk)

        result = run_adb_safe(args)
        result["apk_path"] = normalized_apk
        result["bypass_low_sdk"] = bypass_low_sdk
        return result

    def clear_logcat(self) -> dict[str, Any]:
        """Clear device log buffer (best-effort; does not raise)."""
        result = run_adb_safe(["logcat", "-c"])
        return self._response(
            success=bool(result.get("success")),
            error=result.get("error"),
            error_type=result.get("error_type"),
        )

    def check_adb_connection(self) -> dict[str, Any]:
        result = run_adb_safe(["devices"])
        if not result["success"]:
            return self._response(
                success=False,
                error=result.get("error"),
                error_type=result.get("error_type"),
                adb_path=result.get("adb_path"),
                output=result.get("output", ""),
            )

        output = result["output"]
        devices = self._parse_devices(output)
        connected = [device["serial"] for device in devices if device["state"] == "device"]

        if not connected:
            return self._response(
                success=False,
                error="No active emulator/device found",
                error_type="NO_DEVICE",
                devices=devices,
                output=output,
                adb_path=result.get("adb_path"),
                suggestion="Start an emulator or connect a device; verify with adb devices",
            )

        return self._response(
            success=True,
            devices=devices,
            connected_count=len(connected),
            output=output,
            adb_path=result.get("adb_path"),
        )

    def install_apk(self, apk_path: str) -> dict[str, Any]:
        if not apk_path:
            return self._response(
                success=False,
                apk_path=apk_path,
                error="apk_path is empty",
                error_type="INVALID_APK_PATH",
            )

        if not os.path.isfile(apk_path):
            return self._response(
                success=False,
                apk_path=apk_path,
                error=f"APK file not found: {apk_path}",
                error_type="APK_NOT_FOUND",
            )

        primary = self._install_attempt(apk_path, bypass_low_sdk=False)
        if primary["success"]:
            return self._response(
                success=True,
                apk_path=primary["apk_path"],
                output=primary.get("output", ""),
                adb_path=primary.get("adb_path"),
                bypass_low_sdk=False,
            )

        output = primary.get("output", "")
        classified = self._classify_install_failure(output)

        if classified and classified.get("error_type") == "SDK_VERSION_TOO_LOW":
            bypass = self._install_attempt(apk_path, bypass_low_sdk=True)
            if bypass["success"]:
                return self._response(
                    success=True,
                    apk_path=bypass["apk_path"],
                    output=bypass.get("output", ""),
                    adb_path=bypass.get("adb_path"),
                    bypass_low_sdk=True,
                    note="Installed using --bypass-low-target-sdk-block",
                )

            return self._response(
                success=False,
                apk_path=bypass.get("apk_path", apk_path),
                error=bypass.get("error") or primary.get("error"),
                output=bypass.get("output") or output,
                adb_path=bypass.get("adb_path"),
                bypass_low_sdk=True,
                bypass_attempted=True,
                **classified,
            )

        return self._response(
            success=False,
            apk_path=primary.get("apk_path", apk_path),
            error=primary.get("error"),
            output=output,
            adb_path=primary.get("adb_path"),
            bypass_low_sdk=False,
            **(classified or {"error_type": primary.get("error_type", "INSTALL_FAILED")}),
        )

    def launch_app(self, package_name: str, activity: str) -> dict[str, Any]:
        component = activity if "/" in activity else f"{package_name}/{activity}"
        result = run_adb_safe(["shell", "am", "start", "-n", component])

        if not result["success"]:
            return self._response(
                success=False,
                package_name=package_name,
                activity=activity,
                component=component,
                error=result.get("error"),
                error_type=result.get("error_type"),
                output=result.get("output", ""),
                adb_path=result.get("adb_path"),
            )

        return self._response(
            success=True,
            package_name=package_name,
            activity=activity,
            component=component,
            output=result.get("output", ""),
            adb_path=result.get("adb_path"),
        )

    def _snapshot_logcat_args(self, package_name: str | None = None) -> list[str]:
        """Build adb logcat snapshot command (dump buffer, do not stream)."""
        if package_name:
            return [
                "logcat",
                "-d",
                "-v",
                "time",
                "ActivityManager:I",
                f"{package_name}:V",
                "*:S",
            ]
        return ["logcat", "-d", "-v", "time"]

    def collect_logcat(
        self,
        duration_seconds: int = 10,
        package_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Snapshot logcat after a short wait (non-blocking dump, Windows-safe UTF-8).

        Waits ``duration_seconds`` for logs to accumulate, then runs:
        ``adb logcat -v time -d`` (with optional package / ActivityManager filter).
        """
        if duration_seconds < 1:
            return {
                "success": False,
                "lines": [],
                "line_count": 0,
                "error": "duration_seconds must be at least 1",
                "error_type": "INVALID_DURATION",
            }

        try:
            time.sleep(duration_seconds)

            result = run_adb_safe(self._snapshot_logcat_args(package_name))
            if not result["success"]:
                return {
                    "success": False,
                    "lines": [],
                    "line_count": 0,
                    "error": result.get("error"),
                    "error_type": result.get("error_type", "LOGCAT_FAILED"),
                }

            output = result.get("output") or ""
            lines = [line for line in output.splitlines() if line.strip()]
            if len(lines) > MAX_LOG_LINES:
                lines = lines[-MAX_LOG_LINES:]

            return {
                "success": True,
                "lines": lines,
                "line_count": len(lines),
            }

        except Exception as exc:
            return {
                "success": False,
                "lines": [],
                "line_count": 0,
                "error": str(exc),
                "error_type": "LOGCAT_FAILED",
            }

    def run_analysis_pipeline(
        self,
        log_lines: list[str],
        session_id: str,
        package_name: str = "",
    ) -> dict[str, Any]:
        """
        Parse logcat lines and run explainable behavior intelligence scoring.

        Args:
            log_lines: Raw logcat lines from collect_logcat().
            session_id: Active dynamic session identifier for session memory.
            package_name: Android package name for cross-session memory.

        Returns:
            Combined structured output with parsed events, behavior risk, and summary.
        """
        parsed_events = parse_logs(log_lines)
        cross_session_boost = self._cross_session_confidence_boost(
            package_name,
            detect_attack_chain(parsed_events),
            extract_network_domains(parsed_events),
        )

        behavior_risk = self.behavior_engine.analyze(
            parsed_events,
            cross_session_boost=cross_session_boost,
        )

        self._update_session_state(session_id, parsed_events, behavior_risk)
        self._update_global_behavior_cache(package_name, parsed_events, behavior_risk)

        attack_patterns = behavior_risk.get("attack_patterns", [])

        intelligence_summary = self.behavior_engine.generate_summary(parsed_events, behavior_risk)
        evidence = behavior_risk.get("evidence", [])
        forensics = behavior_risk.get("forensics", {})

        return {
            "success": True,
            "event_count": len(parsed_events),
            "deduplicated_event_count": behavior_risk.get("deduplicated_event_count", len(parsed_events)),
            "events": parsed_events,
            "behavior_risk": behavior_risk,
            "risk_score": behavior_risk.get("risk_score", 0),
            "risk_level": behavior_risk.get("risk_level", "LOW"),
            "intelligence_summary": intelligence_summary,
            "threat_classification": behavior_risk.get("threat_classification", {}),
            "attack_patterns": attack_patterns,
            "evidence": evidence,
            "forensics": forensics,
            "session_state": self.session_state.get(session_id, {}),
            "global_behavior_cache_entry": self.global_behavior_cache.get(package_name, {}),
        }

    def run_dynamic_session(
        self,
        apk_path: str,
        package_name: str,
        activity: str,
        duration: int = 10,
    ) -> dict[str, Any]:
        session_id = f"session_{uuid.uuid4().hex[:8]}"
        self._reset_session_state(session_id)

        context: dict[str, Any] = {
            "success": False,
            "status": "failure",
            "session_id": session_id,
            "adb_path": get_adb_path(),
            "apk_path": apk_path,
            "package_name": package_name,
            "activity": activity,
            "duration": duration,
        }

        adb_check = self.check_adb_connection()
        context["adb_check"] = adb_check
        if not adb_check["success"]:
            context["failed_step"] = "adb_check"
            context["error"] = adb_check.get("error")
            context["error_type"] = adb_check.get("error_type", "ADB_CHECK_FAILED")
            return context

        install_result = self.install_apk(apk_path)
        context["install_result"] = install_result
        if not install_result["success"]:
            context["failed_step"] = "install"
            context["error"] = install_result.get("error")
            context["error_type"] = install_result.get("error_type", "INSTALL_FAILED")
            context["suggestion"] = install_result.get("suggestion")
            context["failure_reason"] = install_result.get("failure_reason")
            return context

        context["logcat_clear"] = self.clear_logcat()

        launch_result = self.launch_app(package_name, activity)
        context["launch_result"] = launch_result
        if not launch_result["success"]:
            context["failed_step"] = "launch"
            context["error"] = launch_result.get("error")
            context["error_type"] = launch_result.get("error_type", "LAUNCH_FAILED")
            return context

        logs = self.collect_logcat(duration, package_name=package_name)
        context["logs"] = logs
        if not logs["success"]:
            context["failed_step"] = "logcat"
            context["error"] = logs.get("error")
            context["error_type"] = logs.get("error_type", "LOGCAT_FAILED")
            return context

        log_analysis = self.run_analysis_pipeline(
            logs.get("lines", []),
            session_id=session_id,
            package_name=package_name,
        )
        context["log_analysis"] = log_analysis
        context["behavior_risk"] = log_analysis.get("behavior_risk")
        context["risk_score"] = log_analysis.get("risk_score")
        context["risk_level"] = log_analysis.get("risk_level")
        context["intelligence_summary"] = log_analysis.get("intelligence_summary")
        context["threat_classification"] = log_analysis.get("threat_classification")
        context["attack_patterns"] = log_analysis.get("attack_patterns")
        context["evidence"] = log_analysis.get("evidence", [])
        context["forensics"] = log_analysis.get("forensics", {})
        context["session_state"] = self.session_state.get(session_id, {})
        context["global_behavior_cache_entry"] = log_analysis.get("global_behavior_cache_entry", {})

        context["success"] = True
        context["status"] = "success"
        context.pop("failed_step", None)
        context.pop("error", None)
        context.pop("error_type", None)
        return context
