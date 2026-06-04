from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalysisContext:
    """Shared container for lightweight APK analysis data."""

    apk_path: str
    permissions: list = field(default_factory=list)
    package_name: str = ""
    main_activities: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
