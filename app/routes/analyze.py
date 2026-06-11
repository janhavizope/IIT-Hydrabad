# app/routes/analyze.py

from fastapi import APIRouter
from pydantic import BaseModel

from app.adapters.extension_adapter import ExtensionAdapter

router = APIRouter()

class APKUrlRequest(BaseModel):
    apk_url: str

@router.post("/scan-apk")
def scan_apk(req: APKUrlRequest):
    print("\n================ APK SCAN START ================")
    print(f"[FastAPI] [URL_RESOLUTION] URL RECEIVED: {req.apk_url}")
    
    # Unified Architecture handles download, retries, validation, 
    # full static/dynamic analysis pipeline, and AI report generation
    result = ExtensionAdapter.analyze_url(req.apk_url)
    
    print(f"[FastAPI] [DECISION] ANALYZER COMPLETED: {result.get('verdict')}")
    return result