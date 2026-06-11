from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.upload import router as upload_router
from app.routes.analyze import router as analyze_router

from app.routes.reports import router as reports_router


app = FastAPI(
    title="APK Malware Analyzer",
    description="Backend API for the APK Malware Analyzer project",
    version="1.0.0",
)

# ✅ FIX: Allow Chrome extension + frontend + testing tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(upload_router, prefix="/api", tags=["Upload"])
app.include_router(analyze_router, prefix="/api", tags=["Analysis"])
app.include_router(reports_router, prefix="/api", tags=["Reports"])


@app.get("/")
def root():
    return {"message": "APK Malware Analyzer backend is running"}

import os
import shutil
import hashlib
from fastapi import UploadFile, File

@app.post("/predict-apk")
async def predict_apk_legacy(file: UploadFile = File(...)):
    # Backward compatibility for script.js
    from app.adapters.web_adapter import WebAdapter
    from app.routes.upload import UPLOADS_DIR
    import uuid

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    secure_filename = f"{uuid.uuid4()}.apk"
    apk_path = UPLOADS_DIR / secure_filename
    
    with open(apk_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    with open(apk_path, "rb") as buffer:
        apk_hash = hashlib.sha256(buffer.read()).hexdigest()

    # Synchronous call for the legacy flow, no DB report ID created
    result = WebAdapter.analyze_file(str(apk_path), apk_hash, report_id="")

    return {
        "file": file.filename,
        "risk_score": result.get("risk_score", 0),
        "label": result.get("verdict", "UNKNOWN"),
        "api_key_loaded": True
    }