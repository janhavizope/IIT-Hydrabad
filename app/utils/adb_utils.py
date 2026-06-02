import os
import subprocess
from typing import Any

ADB_PATH = r"C:\Users\janhavi\AppData\Local\Android\Sdk\platform-tools\adb.exe"

# Backward-compatible alias used elsewhere in the project
ADB_BINARY = ADB_PATH


class AdbNotFoundError(FileNotFoundError):
    """Raised when adb.exe is missing at the configured ADB_PATH."""


class AdbCommandError(Exception):
    """Raised when an adb command exits with a non-zero status."""

    def __init__(self, message: str, output: str = "", returncode: int = 1):
        super().__init__(message)
        self.output = output
        self.returncode = returncode


def _ensure_adb_available() -> None:
    if not os.path.isfile(ADB_PATH):
        raise AdbNotFoundError(
            f"adb.exe not found at configured path: {ADB_PATH}. "
            "Install Android SDK Platform-Tools or update ADB_PATH in app/utils/adb_utils.py."
        )


_SUBPROCESS_TEXT_KWARGS: dict[str, Any] = {
    "capture_output": True,
    "text": True,
    "encoding": "utf-8",
    "errors": "ignore",
}


def _combine_output(stdout: str | None, stderr: str | None) -> str:
    parts = [part for part in ((stdout or "").strip(), (stderr or "").strip()) if part]
    return "\n".join(parts)


def _normalize_command_args(args: list[str]) -> list[str]:
    """
    Normalize command arguments for Windows reliability.

    APK paths are passed as separate list entries (never shell-quoted strings).
    """
    if not args:
        return args

    normalized = list(args)
    if normalized[0] == "install":
        for index, value in enumerate(normalized):
            if value.lower().endswith(".apk"):
                normalized[index] = os.path.normpath(os.path.abspath(value))
    return normalized


def _raise_command_error(args: list[str], returncode: int, output: str, stderr: str) -> None:
    if args and args[0] == "install":
        detail = stderr.strip() or output.strip() or "unknown install error"
        raise AdbCommandError(
            f"APK install failed (exit {returncode}): {detail}",
            output=output,
            returncode=returncode,
        )

    if args and args[0] == "devices":
        detail = output.strip() or stderr.strip() or "no output from adb devices"
        raise AdbCommandError(
            f"adb devices failed (exit {returncode}):\n{detail}",
            output=output,
            returncode=returncode,
        )

    raise AdbCommandError(
        f"adb command failed (exit {returncode}): {' '.join(args)}",
        output=output,
        returncode=returncode,
    )


def run_adb_command(cmd: list[str], timeout: float | None = None) -> str:
    """
    Run adb using the configured absolute ADB_PATH (no PATH lookup, no shell).

    Args:
        cmd: adb arguments only, e.g. ["install", "-r", "C:\\path\\app.apk"]
        timeout: optional seconds limit (used for long-running commands like logcat)

    Returns:
        Combined stdout/stderr text on success.

    Raises:
        AdbNotFoundError: adb.exe missing at ADB_PATH
        AdbCommandError: non-zero adb exit code
    """
    _ensure_adb_available()
    args = _normalize_command_args(cmd)
    command = [ADB_PATH, *args]

    if timeout is None:
        completed = subprocess.run(
            command,
            check=False,
            **_SUBPROCESS_TEXT_KWARGS,
        )
        output = _combine_output(completed.stdout, completed.stderr)
        if completed.returncode != 0:
            _raise_command_error(
                args,
                completed.returncode,
                output,
                (completed.stderr or "").strip(),
            )
        return output

    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    output = _combine_output(stdout, stderr)
    if proc.returncode not in (0, None):
        _raise_command_error(args, proc.returncode or 1, output, (stderr or "").strip())
    return output


def parse_devices(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for line in output.strip().splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1]})
    return devices


def check_device() -> list[str]:
    """
    Return serial numbers for devices in the 'device' state.

    Raises AdbCommandError with adb devices output when none are connected.
    """
    output = run_adb_command(["devices"])
    connected = [
        device["serial"]
        for device in parse_devices(output)
        if device["state"] == "device"
    ]
    if not connected:
        raise AdbCommandError(
            "No device in 'device' state. adb devices output:\n"
            f"{output.strip() or '(empty)'}",
            output=output,
        )
    return connected
