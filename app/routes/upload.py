import hashlib
from fastapi import APIRouter, File, HTTPException, UploadFile, status, BackgroundTasks, Depends
import shutil
import uuid
import os
from pathlib import Path
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import AnalysisReport
import threading

router = APIRouter()

UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"

# Global lock to prevent overlapping DB writes that cause RocksDB/Postgres contention
db_commit_lock = threading.Lock()

def process_apk_background(report_id: str, apk_path: str, apk_hash: str):
    from app.adapters.web_adapter import WebAdapter
    WebAdapter.analyze_file(apk_path, apk_hash, report_id)

@router.post("/upload-apk")
async def upload_apk(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .apk files are allowed",
        )

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    secure_filename = f"{uuid.uuid4()}.apk"
    apk_path = UPLOADS_DIR / secure_filename
    
    with open(apk_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Compute hash synchronously so we can store it in DB immediately
    with open(apk_path, "rb") as buffer:
        apk_hash = hashlib.sha256(buffer.read()).hexdigest()

    report = AnalysisReport(filename=file.filename, apk_hash=apk_hash, status="PENDING")
    db.add(report)
    with db_commit_lock:
        db.commit()
    db.refresh(report)

    # Start the heavy pipeline in the background
    background_tasks.add_task(process_apk_background, report.id, str(apk_path), apk_hash)

    return {
        "message": "APK uploaded successfully. Analysis started.",
        "filename": file.filename,
        "report_id": report.id,
        "saved_path": str(apk_path)
    }
