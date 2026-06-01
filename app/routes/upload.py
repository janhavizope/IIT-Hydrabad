from fastapi import APIRouter

router = APIRouter()


@router.get("/upload")
def upload_status():
    return {
        "message": "Upload route is ready",
        "note": "APK analysis logic will be added in a later phase",
    }
