"""
Log Intelligence Parser for Android logcat output.

Parses raw logcat lines into structured events for downstream analysis.
"""

from __future__ import annotations

import re
from typing import Any

# adb logcat -v time: MM-DD HH:MM:SS.mmm  PID  TID  LEVEL TAG: message
_TIME_FORMAT = re.compile(
    r"^(?P<timestamp>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+\d+\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+):\s*(?P<message>.*)$"
)

# adb logcat -v threadtime (same leading fields as time)
_THREADTIME_FORMAT = re.compile(
    r"^(?P<timestamp>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+\d+\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+):\s*(?P<message>.*)$"
)

# brief: LEVEL/TAG(PID): message
_BRIEF_FORMAT = re.compile(
    r"^(?P<level>[VDIWEF])/(?P<tag>[^(:\s]+)"
    r"(?:\((?P<pid>\d+)\))?:\s*(?P<message>.*)$"
)

# ISO-like / year-inclusive timestamp variants
_ISO_TIME_FORMAT = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+"
    r"(?P<pid>\d+)\s+\d+\s+"
    r"(?P<level>[VDIWEF])\s+"
    r"(?P<tag>[^:]+):\s*(?P<message>.*)$"
)

_LEVEL_TAG_MESSAGE = re.compile(
    r"^(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s*(?P<message>.*)$"
)

_PARSERS = (
    _TIME_FORMAT,
    _THREADTIME_FORMAT,
    _ISO_TIME_FORMAT,
    _BRIEF_FORMAT,
    _LEVEL_TAG_MESSAGE,
)

_ACTIVITY_KEYWORDS = (
    "activitymanager",
    "starting activity",
    "activity task",
    "resumed activity",
    "paused activity",
)
_PERMISSION_KEYWORDS = ("permission", "grant", "denied", "revoke")
_NETWORK_KEYWORDS = (
    "http",
    "https",
    "socket",
    "dns",
    "wifi",
    "connectivity",
    "okhttp",
    "ssl",
    "network",
    "inet",
)
_ERROR_KEYWORDS = ("exception", "error", "fatal", "crash", "caused by")
_SYSTEM_TAGS = (
    "system",
    "systemserver",
    "androidruntime",
    "zygote",
    "systemui",
    "libc",
)


def _classify_event_type(tag: str, message: str) -> str:
    tag_lower = tag.lower()
    combined = f"{tag_lower} {message.lower()}"

    if "activitymanager" in tag_lower or any(k in combined for k in _ACTIVITY_KEYWORDS[1:]):
        return "activity"

    if any(k in combined for k in _PERMISSION_KEYWORDS):
        return "permission"

    if any(k in combined for k in _NETWORK_KEYWORDS):
        return "network"

    if any(k in combined for k in _ERROR_KEYWORDS):
        return "error"

    if any(k in tag_lower for k in _SYSTEM_TAGS):
        return "system"

    return "unknown"


def _build_event(
    *,
    timestamp: str | None,
    tag: str,
    pid: str | None,
    level: str,
    message: str,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "tag": tag,
        "pid": pid,
        "level": level,
        "message": message,
        "event_type": _classify_event_type(tag, message),
    }


def _parse_line(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped:
        return None

    for pattern in _PARSERS:
        match = pattern.match(stripped)
        if not match:
            continue

        groups = match.groupdict()
        return _build_event(
            timestamp=groups.get("timestamp"),
            tag=(groups.get("tag") or "unknown").strip(),
            pid=groups.get("pid"),
            level=(groups.get("level") or "I").upper(),
            message=(groups.get("message") or "").strip(),
        )

    # Fallback: treat entire line as message
    return _build_event(
        timestamp=None,
        tag="unknown",
        pid=None,
        level="I",
        message=stripped,
    )


def parse_logs(lines: list[str]) -> list[dict[str, Any]]:
    """
    Parse raw logcat lines into structured event dictionaries.

    Args:
        lines: Raw logcat output split by line.

    Returns:
        List of parsed events matching the log intelligence schema.
    """
    events: list[dict[str, Any]] = []
    for line in lines:
        event = _parse_line(line)
        if event is not None:
            events.append(event)
    return events
