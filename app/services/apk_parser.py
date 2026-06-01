import os
import tempfile
from androguard.misc import AnalyzeAPK

from app.models.analysis_context import AnalysisContext


class APKParser:
    """Parse APK into a safe, lightweight AnalysisContext."""

    def parse(self, apk_bytes: bytes) -> AnalysisContext:
        """
        Parse APK bytes safely using a temp file (required for stable androguard parsing).
        """

        tmp_path = None

        try:
            # -------------------------------------------------
            # STEP 1: Write bytes to temp file (CRITICAL FIX)
            # -------------------------------------------------
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                tmp.write(apk_bytes)
                tmp_path = tmp.name

            # -------------------------------------------------
            # STEP 2: Analyze APK using file path
            # -------------------------------------------------
            apk, dex_objects, _ = AnalyzeAPK(tmp_path)

            package_name = apk.get_package() if apk else ""
            permissions = apk.get_permissions() if apk else []
            main_activities = apk.get_main_activities() if apk else []

            strings = self._collect_strings_safe(apk, dex_objects)

            return AnalysisContext(
                apk_path=tmp_path,
                permissions=permissions or [],
                package_name=package_name or "",
                main_activities=main_activities or [],
                strings=strings[:200],
                metadata={},
            )

        except Exception as e:
            # IMPORTANT: propagate real error to pipeline
            raise Exception(f"APK parsing failed: {str(e)}")

        finally:
            # -------------------------------------------------
            # STEP 3: Cleanup temp file
            # -------------------------------------------------
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    # =====================================================
    # SAFE STRING EXTRACTION
    # =====================================================

    def _collect_strings_safe(self, apk, dex_objects):
        collected = []

        try:
            if apk:
                collected.extend(self._normalize_values(apk.get_strings() or []))

            for dex in dex_objects or []:
                # safe attribute access
                collected.extend(self._safe_call(dex, "get_strings"))
                collected.extend(self._safe_call(dex, "get_classes_names"))
                collected.extend(self._safe_call(dex, "get_methods_names"))

                classes = self._safe_call(dex, "get_classes", default=[])
                for class_def in classes:
                    collected.extend(self._safe_call(class_def, "get_name"))

                    methods = self._safe_call(class_def, "get_methods", default=[])
                    for method in methods:
                        collected.extend(self._safe_call(method, "get_name"))

        except Exception:
            # never break full parsing due to string extraction
            pass

        return self._unique_list(collected)[:200]

    # =====================================================
    # SAFE METHOD CALLER (CRITICAL HARDENING)
    # =====================================================

    def _safe_call(self, obj, method_name, default=None):
        try:
            if not obj or not hasattr(obj, method_name):
                return default or []

            method = getattr(obj, method_name)
            result = method()

            return self._normalize_values(result)

        except Exception:
            return default or []

    # =====================================================
    # NORMALIZATION
    # =====================================================

    def _normalize_values(self, value):
        if value is None:
            return []

        if isinstance(value, bytes):
            try:
                return [value.decode("utf-8", errors="ignore")]
            except Exception:
                return []

        if isinstance(value, str):
            return [value]

        if isinstance(value, dict):
            collected = []
            for k, v in value.items():
                collected.extend(self._normalize_values(k))
                collected.extend(self._normalize_values(v))
            return collected

        if isinstance(value, (list, tuple, set)):
            collected = []
            for item in value:
                collected.extend(self._normalize_values(item))
            return collected

        return [str(value)]

    # =====================================================
    # DEDUP
    # =====================================================

    def _unique_list(self, items):
        seen = set()
        output = []

        for item in items:
            cleaned = str(item).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                output.append(cleaned)

        return output