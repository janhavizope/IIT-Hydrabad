import tempfile
import os
from androguard.misc import AnalyzeAPK


class APKParser:
    """
    Extract REAL analysis context for STATIC + IOC + DYNAMIC pipeline
    """

    def parse(self, file_bytes: bytes):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_file:
            temp_file.write(file_bytes)
            apk_path = temp_file.name

        try:
            a, d, dx = AnalyzeAPK(apk_path)
            permissions = a.get_permissions() or []
            package_name = a.get_package() or ""

            # =========================
            # REAL STRING EXTRACTION
            # =========================
            strings = []
            try:
                for method in dx.get_methods():
                    if method and method.get_strings():
                        strings.extend(method.get_strings())
            except:
                strings = []

            # =========================
            # ACTIVITIES
            # =========================
            activities = a.get_activities() or []

            return type("APKContext", (), {
                "package_name": package_name,
                "permissions": permissions,
                "main_activities": activities,
                "strings": strings,
                "metadata": {},
            })()
        finally:
            try:
                os.remove(apk_path)
            except:
                pass