import requests
import time
import zipfile
import shutil
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

TRUSTED_DOMAINS_HIGH = [
    "play.google.com",
    "apkpure.com",
    "apkmirror.com",
    "github.com",
    "githubusercontent.com"
]

TRUSTED_DOMAINS_MEDIUM = [
    "f-droid.org",
    "aptoide.com"
]

def get_domain_trust(url: str) -> str:
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname.lower()
        if not hostname:
            return "LOW"
        for d in TRUSTED_DOMAINS_HIGH:
            if d in hostname:
                return "HIGH"
        for d in TRUSTED_DOMAINS_MEDIUM:
            if d in hostname:
                return "MEDIUM"
        return "LOW"
    except Exception:
        return "LOW"

def download_apk(url: str, output_path: Path) -> dict:
    """Securely downloads APK from URL with validation."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*"
    }

    max_retries = 2
    attempt = 0
    response = None

    while attempt <= max_retries:
        try:
            logger.info(f"[Unified] [URL_RESOLUTION] Download attempt {attempt + 1}/{max_retries + 1} for {url}")
            response = requests.get(url, stream=True, timeout=(3, 30), allow_redirects=True, headers=headers)
            if response.status_code == 200:
                break
        except requests.exceptions.RequestException as e:
            logger.error(f"[Unified] Download exception: {e}")
        attempt += 1
        if attempt <= max_retries:
            time.sleep(2)

    if not response or response.status_code != 200:
        status_code = response.status_code if response else "timeout/error"
        fail_type = "TIMEOUT" if "timeout" in str(status_code) else "NETWORK_ERROR"
        return {"success": False, "error": f"Download failed with status {status_code}", "failure_type": fail_type}

    final_url_path = response.url.lower().split("?")[0]
    content_type = response.headers.get("Content-Type", "").lower()

    # Validation
    error_msg = ""
    is_valid = False
    url_path_lower = url.lower().split("?")[0]
    
    is_apkm = False

    if final_url_path.endswith(".apkm") or url_path_lower.endswith(".apkm"):
        is_valid = True
        is_apkm = True
    elif "text/html" in content_type:
        error_msg = "Not a direct APK file (HTML page / redirect landing page detected)."
    elif "application/vnd.android.package-archive" in content_type:
        is_valid = True
    elif final_url_path.endswith(".apk") or url_path_lower.endswith(".apk"):
        is_valid = True
    elif "application/octet-stream" in content_type and (".apk" in final_url_path or ".apk" in url_path_lower):
        is_valid = True
    else:
        error_msg = f"Unsupported content type: {content_type}"

    if error_msg or not is_valid:
        error_msg = error_msg or "Invalid APK format."
        return {"success": False, "error": error_msg, "failure_type": "INVALID_FORMAT"}

    try:
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return {"success": True, "path": str(output_path), "is_apkm": is_apkm}
    except Exception as e:
        return {"success": False, "error": f"Failed to save downloaded file: {e}", "failure_type": "PIPELINE_ERROR"}

def extract_apkm(apkm_path: str, extract_dir: Path) -> str:
    """Extracts base APK from APKM bundle."""
    try:
        with zipfile.ZipFile(apkm_path, 'r') as zip_ref:
            apk_files = [f for f in zip_ref.namelist() if f.endswith('.apk')]
            if not apk_files:
                return None
            
            base_apk = next((f for f in apk_files if 'base.apk' in f.lower()), None)
            if not base_apk:
                # Fallback to largest apk
                base_apk = max(apk_files, key=lambda f: zip_ref.getinfo(f).file_size)

            extracted_path = extract_dir / "base.apk"
            with zip_ref.open(base_apk) as source, open(extracted_path, "wb") as target:
                shutil.copyfileobj(source, target)
            return str(extracted_path)
    except Exception as e:
        logger.error(f"[Unified] APKM Extraction failed: {e}")
        return None
