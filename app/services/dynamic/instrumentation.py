import os
import time
import threading
from typing import Any, List, Dict

# Attempt to import frida. In a real environment, it must be installed.
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
        if message['type'] == 'send':
            payload = message['payload']
            # Expected format from JS: { type: "database", message: "..." }
            event_type = payload.get("type", "unknown")
            msg = payload.get("message", "")
            
            # Normalize event types to match BehaviorEngine EVENT_WEIGHTS
            if event_type == "sharedpreferences":
                event_type = "file_access"
            elif event_type == "database":
                event_type = "database_access"
            elif event_type == "content_provider":
                if "Sensitive" in msg:
                    event_type = "sensitive_data"
                else:
                    event_type = "database_access"
            
            # Create a structured event similar to log_parser's output
            event = {
                "timestamp": time.strftime("%m-%d %H:%M:%S.000"),
                "tag": "Frida-Instr",
                "pid": "frida",
                "level": "I",
                "message": msg,
                "event_type": event_type,
            }
            self.events.append(event)
        elif message['type'] == 'error':
            print(f"[Frida Error] {message['description']}")

    def start(self) -> bool:
        if frida is None:
            print("[Frida] frida-tools not installed. Skipping instrumentation.")
            return False

        # Verify frida-server is running before attempting to attach
        try:
            import subprocess
            adb_path = os.environ.get("ADB_PATH", r"C:\Users\janhavi\AppData\Local\Android\Sdk\platform-tools\adb.exe")
            result = subprocess.run([adb_path, "shell", "ps", "-A"], capture_output=True, text=True)
            if "frida-server" not in result.stdout:
                print("[Frida] Error: frida-server is not running on the device. Instrumentation aborted.")
                return False
        except Exception as e:
            print(f"[Frida] Error checking frida-server status: {e}")
            return False

        try:
            self._device = frida.get_usb_device(timeout=5)
            # Try to spawn the app
            pid = self._device.spawn([self.package_name])
            self._session = self._device.attach(pid)
            
            # Load agent script
            agent_path = os.path.join(os.path.dirname(__file__), "frida_agent.js")
            if not os.path.isfile(agent_path):
                print(f"[Frida] Agent script not found at {agent_path}")
                return False
                
            with open(agent_path, "r", encoding="utf-8") as f:
                script_code = f.read()
                
            self._script = self._session.create_script(script_code)
            self._script.on('message', self.on_message)
            self._script.load()
            
            # Resume the app after loading the script
            self._device.resume(pid)
            self._running = True
            print(f"[Frida] Successfully attached to {self.package_name}")
            return True
        except Exception as e:
            print(f"[Frida] Failed to start instrumentation: {e}")
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
