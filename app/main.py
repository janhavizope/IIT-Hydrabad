from fastapi import FastAPI

from app.routes.upload import router as upload_router

app = FastAPI(
    title="APK Malware Analyzer",
    description="Backend API for the APK Malware Analyzer project",
    version="1.0.0",
)

app.include_router(upload_router, prefix="/api", tags=["Upload"])


@app.get("/")
def root():
    return {"message": "APK Malware Analyzer backend is running"}
