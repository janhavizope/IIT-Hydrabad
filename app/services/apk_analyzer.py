from androguard.core.apk import APK

def analyze_apk(apk_path):
    apk = APK(apk_path)

    return {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "permissions": apk.get_permissions()
    }