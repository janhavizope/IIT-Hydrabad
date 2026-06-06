import os
import time
from typing import Any, List, Dict

try:
    import frida
except ImportError:
    frida = None


class FridaInstrumentation:
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.events: List[Dict[str, Any]] = []
        self._session = None
        self._script = None
        self._running = False
        self._device = None

    def on_message(self, message: dict, data: bytes) -> None:
        if message["type"] == "send":
            payload = message["payload"]

            event_type = payload.get("type", "unknown")
            msg = payload.get("message", "")

            if event_type == "sharedpreferences":
                event_type = "file_access"

            elif event_type == "database":
                event_type = "database_access"

            elif event_type == "content_provider":
                if "Sensitive" in msg:
                    event_type = "sensitive_data"
                else:
                    event_type = "database_access"

            event = {
                "timestamp": time.strftime("%m-%d %H:%M:%S.000"),
                "tag": "Frida-Instr",
                "pid": "frida",
                "level": "I",
                "message": msg,
                "event_type": event_type,
            }

            self.events.append(event)

        elif message["type"] == "error":
            print(f"[Frida Error] {message['description']}")

    def start(self) -> bool:
        if frida is None:
            print("[Frida] frida-tools not installed.")
            return False

        try:
            import subprocess

            adb_path = os.environ.get(
                "ADB_PATH",
                r"C:\Users\janhavi\AppData\Local\Android\Sdk\platform-tools\adb.exe"
            )

            print("[DEBUG] Checking frida-server...")

            result = subprocess.run(
                [adb_path, "shell", "ps", "-A"],
                capture_output=True,
                text=True
            )

            if "frida-server" not in result.stdout:
                print("[Frida] frida-server is not running.")
                return False

            print("[DEBUG] frida-server detected.")

        except Exception as e:
            print(f"[Frida] Error checking frida-server: {e}")
            return False

        try:
            print("=" * 60)
            print("[DEBUG] STEP 1 - Get USB Device")

            self._device = frida.get_usb_device(timeout=10)

            print("[DEBUG] Device acquired successfully")
            print(f"[DEBUG] Device: {self._device}")

            print("=" * 60)
            print("[DEBUG] STEP 2 - Package Name")

            print(f"[DEBUG] Package = {self.package_name}")

            print("=" * 60)
            print("[DEBUG] STEP 3 - Spawn App")

            pid = self._device.spawn([self.package_name])

            print(f"[DEBUG] Spawn Success")
            print(f"[DEBUG] PID = {pid}")

            print("=" * 60)
            print("[DEBUG] STEP 4 - Attach")

            self._session = self._device.attach(pid)

            print("[DEBUG] Attach Success")

            print("=" * 60)
            print("[DEBUG] STEP 5 - Load Agent")

            agent_path = os.path.join(
                os.path.dirname(__file__),
                "frida_agent.js"
            )

            print(f"[DEBUG] Agent Path = {agent_path}")

            if not os.path.isfile(agent_path):
                print("[Frida] Agent file not found.")
                return False

            with open(agent_path, "r", encoding="utf-8") as f:
                script_code = f.read()

            print(f"[DEBUG] Agent Size = {len(script_code)} bytes")

            self._script = self._session.create_script(script_code)

            print("[DEBUG] Script Created")

            self._script.on("message", self.on_message)

            print("[DEBUG] Loading Script")

            self._script.load()

            print("[DEBUG] Script Loaded Successfully")

            print("=" * 60)
            print("[DEBUG] STEP 6 - Resume App")

            self._device.resume(pid)

            print("[DEBUG] App Resumed")

            self._running = True

            print("=" * 60)
            print(f"[Frida] Successfully attached to {self.package_name}")
            print("=" * 60)

            return True

        except Exception as e:
            print("=" * 60)
            print("[DEBUG] FAILURE LOCATION")
            print(type(e).__name__)
            print(str(e))
            print("=" * 60)
            return False

    def stop(self) -> None:
        if not self._running:
            return

        try:
            if self._session:
                self._session.detach()

            self._running = False

            print("[Frida] Detached successfully")

        except Exception as e:
            print(f"[Frida] Error during detach: {e}")

    def get_events(self) -> List[Dict[str, Any]]:
        return self.events
    