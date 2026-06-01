from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile, status

router = APIRouter()

UPLOADS_DIR = Path(__file__).resolve().parents[2] / "uploads"


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
        "message": "APK uploaded successfully",
        "filename": filename,
        "saved_path": str(saved_file_path),
    }
