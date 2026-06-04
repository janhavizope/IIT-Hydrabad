import hashlib
from pathlib import Path

from app.core.logger import log_info
from app.core.pipeline import AnalysisPipeline


class APKAnalyzer:
    """Thin adapter that loads APK bytes and delegates to the analysis pipeline."""

    def __init__(self):
        self.pipeline = AnalysisPipeline()

    def compute_apk_hash(self, file_bytes: bytes) -> str:
        return hashlib.sha256(file_bytes).hexdigest()

    def _load_apk_bytes(self, apk_path: str):
        return Path(apk_path).read_bytes()

    def analyze(self, apk_path: str):
        """Load APK bytes, compute hash, and execute the pipeline."""
        log_info("APK received")

        if not str(apk_path).lower().endswith(".apk"):
            log_info("APK validation result: failed")
            raise ValueError(f"invalid apk extension for path: {apk_path}")

        log_info("APK validation result: passed")

        file_bytes = self._load_apk_bytes(apk_path)

        apk_hash = self.compute_apk_hash(file_bytes)
        return self.pipeline.execute(file_bytes, apk_hash, apk_path)

from androguard.core.apk import APK

def analyze_apk(apk_path):
    apk = APK(apk_path)

    return {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "permissions": apk.get_permissions()
    }