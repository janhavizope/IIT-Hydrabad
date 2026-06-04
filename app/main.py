from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.upload import router as upload_router
from app.database.session import engine, Base
import app.database.models

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="APK Malware Analyzer",
    description="Backend API for the APK Malware Analyzer project",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For hackathon/development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router, prefix="/api", tags=["Upload"])


@app.get("/")
def root():
    return {"message": "APK Malware Analyzer backend is running"}

from app.routes.reports import router as reports_router
app.include_router(reports_router, prefix="/api", tags=["Reports"])
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)