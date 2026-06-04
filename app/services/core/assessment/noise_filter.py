"""
Noise filter — classify events; only APP_EVENT affects scoring.

SYSTEM_NOISE: excluded from scoring (kept for debug).
SYSTEM_ABUSE: excluded from scoring, included in IOC extraction.
APP_EVENT: used in scoring and IOC.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.services.core.assessment.constants import (
    KNOWN_EVENT_TYPES,
    LOGCAT_SYSTEM_MARKERS,
    SMALL_DATASET_EVENT_THRESHOLD,
    SYSTEM_ABUSE_MARKERS,
    SYSTEM_SOURCES,
)

APP_EVENT = "APP_EVENT"
SYSTEM_NOISE = "SYSTEM_NOISE"
SYSTEM_ABUSE = "SYSTEM_ABUSE"


@dataclass
class NoiseFilterResult:
    filtered_events: list[dict[str, Any]] = field(default_factory=list)
    ioc_events: list[dict[str, Any]] = field(default_factory=list)
    noise_events: list[dict[str, Any]] = field(default_factory=list)
    system_abuse_events: list[dict[str, Any]] = field(default_factory=list)
    noise_notes: list[str] = field(default_factory=list)
    raw_event_count: int = 0
    filtered_event_count: int = 0
    noise_ratio: float = 0.0
    system_interaction_ratio: float = 0.0
    small_dataset: bool = False

    def to_debug_dict(self) -> dict[str, Any]:
        return {
            "noise_ratio": round(self.noise_ratio, 4),
            "system_interaction_ratio": round(self.system_interaction_ratio, 4),
            "filtered_event_count": self.filtered_event_count,
            "raw_event_count": self.raw_event_count,
            "noise_event_count": len(self.noise_events),
            "system_abuse_event_count": len(self.system_abuse_events),
            "ioc_event_count": len(self.ioc_events),
            "small_dataset": self.small_dataset,
        }


def normalize_log_string(event: dict[str, Any]) -> str:
    """Canonical log line for stable SHA-256 deduplication."""
    tag = str(event.get("tag") or "").strip().lower()
    message = str(event.get("message") or "").strip().lower()
    event_type = str(event.get("event_type") or "").strip().lower()
    return f"{event_type}|{tag}|{message}"


def event_signature(event: dict[str, Any]) -> str:
    """SHA-256 hash of normalized log string."""
    return hashlib.sha256(normalize_log_string(event).encode("utf-8")).hexdigest()


def deduplicate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic dedup preserving first occurrence order."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        sig = event_signature(event)
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(event)
    return unique


def _combined_text(event: dict[str, Any]) -> str:
    return f"{event.get('tag') or ''} {event.get('message') or ''}".lower()


def _is_system_noise_source(tag: str, combined: str) -> bool:
    tag_lower = tag.lower()
    combined_lower = combined.lower()
    for source in SYSTEM_SOURCES:
        marker = source.lower()
        if marker in tag_lower or marker in combined_lower:
            return True
    for marker in LOGCAT_SYSTEM_MARKERS:
        if marker in tag_lower or marker in combined_lower:
            return True
    if tag_lower.startswith("system.") or "/system/" in combined_lower:
        return True
    return False


def _is_system_abuse(tag: str, combined: str) -> bool:
    tag_lower = tag.lower()
    combined_lower = combined.lower()
    for marker in SYSTEM_ABUSE_MARKERS:
        if marker in tag_lower or marker in combined_lower:
            return True
    return False


def _is_app_package_event(tag: str, package_name: str, event_type: str) -> bool:
    if not package_name:
        return event_type in ("activity", "network", "permission", "error")

    pkg = package_name.lower().strip()
    tag_lower = tag.lower()
    if pkg in tag_lower:
        return True
    short = pkg.split(".")[-1] if "." in pkg else pkg
    if short in tag_lower and "system" not in tag_lower:
        return True
    return False


def classify_event(
    event: dict[str, Any],
    package_name: str = "",
) -> str:
    """Classify a single event into APP_EVENT, SYSTEM_NOISE, or SYSTEM_ABUSE."""
    tag = str(event.get("tag") or "")
    combined = _combined_text(event)
    event_type = (event.get("event_type") or "").lower()

    if event_type == "system" or _is_system_noise_source(tag, combined):
        return SYSTEM_NOISE

    if _is_system_abuse(tag, combined) and not _is_app_package_event(tag, package_name, event_type):
        return SYSTEM_ABUSE

    if event_type not in KNOWN_EVENT_TYPES - {"system"}:
        return SYSTEM_NOISE

    if package_name and not _is_app_package_event(tag, package_name, event_type):
        if _is_system_abuse(tag, combined):
            return SYSTEM_ABUSE
        return SYSTEM_NOISE

    if event_type in ("activity", "network", "permission", "error"):
        return APP_EVENT

    return SYSTEM_NOISE


def filter_events(
    events: list[dict[str, Any]],
    package_name: str = "",
) -> NoiseFilterResult:
    """
    Classify and partition events. Only APP_EVENT enters scoring.

    ioc_events = APP_EVENT + SYSTEM_ABUSE (deterministic order).
    noise_ratio / system_interaction_ratio are debug-only.
    """
    events = deduplicate_events(events)
    result = NoiseFilterResult()
    result.raw_event_count = len(events)
    result.small_dataset = result.raw_event_count < SMALL_DATASET_EVENT_THRESHOLD
    system_noise_count = 0

    for event in events:
        if not isinstance(event, dict):
            result.noise_events.append(event)
            continue

        label = classify_event(event, package_name)
        event_with_class = {**event, "_event_class": label}

        if label == APP_EVENT:
            result.filtered_events.append(event)
            result.ioc_events.append(event)
        elif label == SYSTEM_ABUSE:
            result.system_abuse_events.append(event_with_class)
            result.ioc_events.append(event)
            result.noise_notes.append(
                f"SYSTEM_ABUSE (IOC only): {str(event.get('tag') or '')[:60]}"
            )
        else:
            result.noise_events.append(event_with_class)
            system_noise_count += 1
            result.noise_notes.append(
                f"SYSTEM_NOISE: {str(event.get('tag') or '')[:60]}"
            )

    result.filtered_event_count = len(result.filtered_events)
    total = result.raw_event_count
    result.noise_ratio = (len(result.noise_events) / total) if total else 0.0
    result.system_interaction_ratio = (system_noise_count / total) if total else 0.0
    return result


def detect_app_crash_loop(
    app_events: list[dict[str, Any]],
    package_name: str,
    *,
    dangerous_permission_declared: bool = False,
    app_activity_observed: bool = False,
) -> tuple[bool, str]:
    if not (dangerous_permission_declared or app_activity_observed):
        return False, "Crash loop ignored without app permission or process activity correlation"

    app_errors: list[dict[str, Any]] = []
    for event in app_events:
        if (event.get("event_type") or "").lower() != "error":
            continue
        tag = str(event.get("tag") or "")
        combined = _combined_text(event)
        if _is_system_noise_source(tag, combined):
            continue
        if package_name and not _is_app_package_event(
            tag, package_name, "error",
        ):
            continue
        app_errors.append(event)

    if len(app_errors) < 3:
        return False, "Fewer than 3 app-process error events"

    tag_counts = Counter(str(e.get("tag") or "unknown") for e in app_errors)
    _tag, count = tag_counts.most_common(1)[0]

    if count >= 3:
        return True, "App process crash loop detected (≥3 errors, same process)"
    return False, "No single app process reached crash-loop threshold"
