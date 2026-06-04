import os
import threading
import time
import uuid
from typing import Any
import urllib.request
import lzma
import subprocess

from app.services.dynamic.behavior_engine import BehaviorEngine, detect_attack_chain, extract_network_domains
from app.services.dynamic.log_parser import parse_logs
from app.services.dynamic.instrumentation import FridaInstrumentation
from app.services.utils import adb_utils
from app.services.utils.adb_utils import AdbCommandError, AdbNotFoundError, run_adb_command

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

    def check_frida_server(self) -> dict[str, Any]:
        result = run_adb_safe(["shell", "ps", "-A"])
        if not result["success"]:
            return self._response(success=False, error="Failed to run ps via ADB")
        
        output = result.get("output", "")
        for line in output.splitlines():
            if "frida-server" in line:
                parts = line.split()
                pid = parts[1] if len(parts) > 1 else "unknown"
                return self._response(success=True, pid=pid, running=True)
        return self._response(success=False, running=False, error="frida-server not found in ps output")

    def deploy_frida_server(self) -> dict[str, Any]:
        try:
            # Get Frida version
            try:
                import frida
                frida_version = frida.__version__
            except ImportError:
                frida_version = "16.1.11" # fallback

            # Get Architecture
            abi_res = run_adb_safe(["shell", "getprop", "ro.product.cpu.abi"])
            if not abi_res["success"]:
                return self._response(success=False, error="Failed to get ABI")
            abi = abi_res["output"].strip()
            # Map standard ABI to frida architecture
            arch_map = {"x86_64": "x86_64", "x86": "x86", "arm64-v8a": "arm64", "armeabi-v7a": "arm"}
            frida_arch = arch_map.get(abi, "arm64")

            print("[*] Starting Frida deployment...")
            print(f"[*] Frida client version: {frida_version}")
            print(f"[*] Device ABI: {abi}")

            # Check if running
            check = self.check_frida_server()
            if check["success"]:
                pid = check.get("pid", "unknown")
                version_res = run_adb_safe(["shell", "/data/local/tmp/frida-server", "--version"])
                server_version = version_res.get("output", "").strip()
                
                print(f"[*] Frida server version: {server_version}")
                print(f"[*] frida-server PID: {pid}")
                
                if server_version != frida_version:
                    print(f"[-] Version mismatch! Client: {frida_version}, Server: {server_version}")
                    return self._response(success=False, error=f"Version mismatch! Client: {frida_version}, Server: {server_version}")
                
                # Retry mechanism for frida-ps connectivity
                connectivity_passed = False
                for attempt in range(3):
                    try:
                        print(f"[*] Validating Frida connection with frida-ps -U (Attempt {attempt+1}/3)")
                        ps_res = subprocess.run(["frida-ps", "-U"], capture_output=True, text=True, timeout=10)
                        if ps_res.returncode == 0:
                            print(f"[+] frida-ps connectivity successful.")
                            connectivity_passed = True
                            break
                        else:
                            print(f"[-] frida-ps failed with return code {ps_res.returncode}. Stderr: {ps_res.stderr.strip()}")
                    except Exception as e:
                        print(f"[-] frida-ps execution exception: {str(e)}")
                    if not connectivity_passed and attempt < 2:
                        print(f"[-] Retrying in 2s...")
                        time.sleep(2)
                        # Re-verify device attachment during retry
                        print(f"[*] Verifying ADB connection stability before retry...")
                        adb_status = self.check_adb_connection()
                        if not adb_status.get("success"):
                            print(f"[-] ADB connection lost during Frida setup: {adb_status.get('error')}")

                print(f"[*] Stability validation result: True (already running)")
                print(f"[*] frida-ps connectivity result: {connectivity_passed}")

                if not connectivity_passed:
                    print("[-] frida-ps -U connectivity check failed after 3 retries. Falling back to direct attach (PARTIAL status).")
                    return self._response(
                        success=True, 
                        status="partial",
                        pid=pid,
                        version=server_version,
                        architecture=frida_arch,
                        error="frida-ps connectivity failed, continuing with partial stability.", 
                        startup_stable=True, 
                        frida_ps_connectivity=False
                    )

                return self._response(success=True, status="already_running", pid=pid, version=server_version, architecture=frida_arch, startup_stable=True, frida_ps_connectivity=True)

            # Check if frida-server exists on device
            ls_res = run_adb_safe(["shell", "ls", "/data/local/tmp/frida-server"])
            if "No such file" in ls_res.get("output", ""):
                # Download matching frida-server
                filename = f"frida-server-{frida_version}-android-{frida_arch}.xz"
                url = f"https://github.com/frida/frida/releases/download/{frida_version}/{filename}"
                local_xz = os.path.join(os.getcwd(), filename)
                local_bin = os.path.join(os.getcwd(), "frida-server")
                
                if not os.path.exists(local_bin):
                    urllib.request.urlretrieve(url, local_xz)
                    with lzma.open(local_xz) as f_in, open(local_bin, "wb") as f_out:
                        f_out.write(f_in.read())
                
                # Push and chmod
                push_res = run_adb_safe(["push", local_bin, "/data/local/tmp/frida-server"])
                if not push_res["success"]:
                    return self._response(success=False, error="Failed to push frida-server")
                    
            chmod_res = run_adb_safe(["shell", "chmod", "755", "/data/local/tmp/frida-server"])
            
            # Start frida-server
            # We use subprocess.Popen because we need it to run in the background detached
            adb_path = get_adb_path()
            subprocess.Popen([adb_path, "shell", "/data/local/tmp/frida-server"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print("[*] Starting 5-second stability validation window...")
            stability_passed = True
            pid = "unknown"
            for i in range(5):
                time.sleep(1)
                check = self.check_frida_server()
                if not check["success"]:
                    print("[-] Frida server crashed during startup validation.")
                    stability_passed = False
                    break
                pid = check.get("pid", "unknown")
                print(f"  [+] Poll {i+1}/5: frida-server running with PID {pid}")

            if not stability_passed:
                return self._response(
                    success=False, 
                    error="Frida server crashed during startup validation.",
                    startup_stable=False,
                    frida_ps_connectivity=False
                )

            print("[*] Stability validation passed. Checking connectivity...")
            
            # Retry mechanism for frida-ps connectivity
            connectivity_passed = False
            for attempt in range(3):
                try:
                    print(f"[*] Validating Frida connection with frida-ps -U (Attempt {attempt+1}/3)")
                    ps_res = subprocess.run(["frida-ps", "-U"], capture_output=True, text=True, timeout=10)
                    if ps_res.returncode == 0:
                        print(f"[+] frida-ps connectivity successful.")
                        connectivity_passed = True
                        break
                    else:
                        print(f"[-] frida-ps failed with return code {ps_res.returncode}. Stderr: {ps_res.stderr.strip()}")
                except Exception as e:
                    print(f"[-] frida-ps execution exception: {str(e)}")
                if not connectivity_passed and attempt < 2:
                    print(f"[-] Retrying in 2s...")
                    time.sleep(2)
                    # Re-verify device attachment during retry
                    print(f"[*] Verifying ADB connection stability before retry...")
                    adb_status = self.check_adb_connection()
                    if not adb_status.get("success"):
                        print(f"[-] ADB connection lost during Frida setup: {adb_status.get('error')}")

            version_res = run_adb_safe(["shell", "/data/local/tmp/frida-server", "--version"])
            server_version = version_res.get("output", "").strip()

            print(f"[*] Frida client version: {frida_version}")
            print(f"[*] Frida server version: {server_version}")
            print(f"[*] Device ABI: {frida_arch}")
            print(f"[*] frida-server PID: {pid}")
            print(f"[*] Stability validation result: {stability_passed}")
            print(f"[*] frida-ps connectivity result: {connectivity_passed}")

            if not connectivity_passed:
                print("[-] frida-ps -U connectivity check failed after 3 retries. Falling back to direct attach (PARTIAL status).")
                return self._response(
                    success=True, 
                    status="partial",
                    pid=pid,
                    version=server_version,
                    architecture=frida_arch,
                    error="frida-ps connectivity failed after stable startup, continuing with partial stability.",
                    startup_stable=True,
                    frida_ps_connectivity=False
                )

            if server_version != frida_version:
                print(f"[-] Version mismatch! Client: {frida_version}, Server: {server_version}")
                return self._response(
                    success=False, 
                    error=f"Version mismatch! Client: {frida_version}, Server: {server_version}",
                    startup_stable=True,
                    frida_ps_connectivity=True
                )
            
            return self._response(
                success=True, 
                status="deployed", 
                pid=pid, 
                version=server_version, 
                architecture=frida_arch,
                startup_stable=True,
                frida_ps_connectivity=True
            )
        except Exception as e:
            return self._response(success=False, error=str(e))

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
        frida_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Parse logcat lines and run explainable behavior intelligence scoring.
        """
        if frida_events is not None:
            parsed_events = frida_events
        else:
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

    def _run_interactions(self, package_name: str, duration: int, username: str = "admin", password: str = "password") -> None:
        """Automated UI interactions to trigger behavioral events."""
        if not package_name:
            return
            
        try:
            # Let the app start properly and reach login
            time.sleep(4)
            
            # Enter username
            run_adb_safe(["shell", "input", "text", username])
            time.sleep(1)
            
            # Tab to next field
            run_adb_safe(["shell", "input", "keyevent", "61"])
            time.sleep(1)
            
            # Enter password
            run_adb_safe(["shell", "input", "text", password])
            time.sleep(1)
            
            # Press enter/login
            run_adb_safe(["shell", "input", "keyevent", "66"])
            time.sleep(3)
            
            # Navigate major activities
            run_adb_safe(["shell", "input", "keyevent", "20"]) # DPAD DOWN
            time.sleep(1)
            run_adb_safe(["shell", "input", "keyevent", "66"]) # ENTER
            time.sleep(2)
            
            # Capture screenshot
            screenshot_dir = os.path.join(os.getcwd(), "reports", "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            screenshot_name = f"dynamic_execution_{int(time.time())}.png"
            local_path = os.path.join(screenshot_dir, screenshot_name)
            
            run_adb_safe(["shell", "screencap", "-p", "/sdcard/screen.png"])
            run_adb_safe(["pull", "/sdcard/screen.png", local_path])
            
            # Run brief monkey for remaining randomized interaction
            run_adb_safe([
                "shell", "monkey", 
                "-p", package_name, 
                "--pct-touch", "50", 
                "--pct-syskeys", "0", 
                "--ignore-crashes", 
                "--ignore-timeouts", 
                "-v", "500"
            ])
        except Exception:
            pass

    def run_dynamic_session(
        self,
        apk_path: str,
        package_name: str,
        activity: str,
        duration: int = 60,
        username: str | None = None,
        password: str | None = None,
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

        instrumentation = None
        frida_events = []

        # Deploy Frida Server
        frida_status = self.deploy_frida_server()
        context["frida_server_status"] = frida_status

        if not frida_status["success"]:
            # Fallback to adb shell am start if Frida is unavailable
            launch_result = self.launch_app(package_name, activity)
            context["launch_result"] = launch_result
            if not launch_result["success"]:
                context["failed_step"] = "launch"
                context["error"] = launch_result.get("error")
                context["error_type"] = launch_result.get("error_type", "LAUNCH_FAILED")
                return context
        else:
            # Start Frida instrumentation
            instrumentation = FridaInstrumentation(package_name)
            frida_started = instrumentation.start()
            context["frida_instrumentation"] = frida_started
            
            if frida_started:
                # Validation commands
                try:
                    ps_res = subprocess.run(["frida-ps", "-U"], capture_output=True, text=True, timeout=15)
                    frida_res = subprocess.run(
                        ["frida", "-U", "-n", "InsecureBankv2", "--eval", "console.log('Validation attachment successful'); Process.id", "-q"],
                        capture_output=True, text=True, timeout=20
                    )
                    context["validation_results"] = {
                        "frida_ps": ps_res.stdout,
                        "frida_attach": frida_res.stdout,
                        "frida_attach_error": frida_res.stderr
                    }
                except Exception as e:
                    context["validation_results"] = {"error": str(e)}
            
            if not frida_started:
                launch_result = self.launch_app(package_name, activity)
                context["launch_result"] = launch_result
                if not launch_result["success"]:
                    context["failed_step"] = "launch"
                    context["error"] = launch_result.get("error")
                    context["error_type"] = launch_result.get("error_type", "LAUNCH_FAILED")
                    return context

        # Start interaction in background
        interaction_thread = threading.Thread(
            target=self._run_interactions,
            args=(package_name, duration, username or "admin", password or "password"),
            daemon=True
        )
        interaction_thread.start()

        logs = self.collect_logcat(duration, package_name=package_name)
        
        # Stop Frida and collect events
        if instrumentation and frida_started:
            instrumentation.stop()
            frida_events = instrumentation.get_events()
        else:
            frida_events = None
        
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
            frida_events=frida_events,
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
