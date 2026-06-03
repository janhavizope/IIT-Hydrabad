from fastapi import APIRouter, UploadFile, File
from androguard.misc import AnalyzeAPK
import shutil
import os
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile, status

router = APIRouter()

UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"

UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"


# Risk Score Calculation
def calculate_risk_score(permissions):
    score = 0

    risky_permissions = {
        "android.permission.READ_SMS": 20,
        "android.permission.SEND_SMS": 25,
        "android.permission.RECEIVE_SMS": 15,
        "android.permission.READ_CONTACTS": 15,
        "android.permission.WRITE_CONTACTS": 15,
        "android.permission.RECORD_AUDIO": 20,
        "android.permission.CAMERA": 10,
        "android.permission.ACCESS_FINE_LOCATION": 10,
        "android.permission.READ_CALL_LOG": 20,
        "android.permission.WRITE_CALL_LOG": 20,
        "android.permission.INTERNET": 5
    }

    for permission in permissions:
        if permission in risky_permissions:
            score += risky_permissions[permission]

    return min(score, 100)


# Risk Level
def get_risk_level(score):
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


@router.post("/upload")
async def upload_apk(file: UploadFile = File(...)):

    # Create uploads folder if missing
    os.makedirs("uploads", exist_ok=True)

    apk_path = f"uploads/{file.filename}"

    # Save uploaded APK
    with open(apk_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Analyze APK
    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    app_name = a.get_app_name()
    version_name = a.get_androidversion_name()
    permissions = a.get_permissions()

    # Calculate risk
    risk_score = calculate_risk_score(permissions)
    risk_level = get_risk_level(risk_score)

@router.post("/upload-apk")
async def upload_apk(file: UploadFile = File(...)):
    filename = file.filename or ""

    if not filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .apk files are allowed",
        )

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    safe_filename = Path(filename).name
    saved_file_path = UPLOADS_DIR / safe_filename

    file_content = await file.read()
    saved_file_path.write_bytes(file_content)

    return {
        "package_name": package_name,
        "app_name": app_name,
        "version_name": version_name,
        "permissions": permissions,
        "risk_score": risk_score,
        "risk_level": risk_level
    }
        "message": "APK uploaded successfully",
        "filename": filename,
        "saved_path": str(saved_file_path),
    }
