from pathlib import Path

from fastapi import APIRouter, HTTPException, status

from app.services.apk_analyzer import APKAnalyzer

router = APIRouter()

apk_analyzer = APKAnalyzer()
UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"


def create_safe_error_response(message: str):
    return {
        "package_name": "",
        "permissions": [],
        "main_activities": [],
        "deep_static_analysis": {},
        "risk_analysis": {
            "risk_score": 0,
            "risk_level": "LOW",
            "flags": [],
            "explanation": "Risk analysis unavailable",
        },
        "status": "failed",
        "error_message": message,
        "confidence_score": 0.0,
    }


@router.get("/analyze-apk/{filename}")
def analyze_apk(filename: str):
    apk_path = UPLOADS_DIR / Path(filename).name

    if not apk_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="APK file not found",
        )

    try:
        result = apk_analyzer.analyze(str(apk_path))
    except Exception as e:
        return create_safe_error_response(str(e))

    if not result:
        return create_safe_error_response("analyzer returned empty result")

    return result
