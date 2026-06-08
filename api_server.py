from fastapi import FastAPI, UploadFile, File
import joblib
import os
import pandas as pd
import shutil
from dotenv import load_dotenv

from extract_apk_features import extract_features

# ----------------------------
# Load environment variables (API KEY support)
# ----------------------------
load_dotenv()
API_KEY = os.getenv("API_KEY")   # <-- YOUR API KEY IS LOADED HERE

# ----------------------------
# Initialize FastAPI app
# ----------------------------
app = FastAPI(title="APK Malware Detection API")

# ----------------------------
# Load trained model safely
# ----------------------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_model.pkl")
model = joblib.load(MODEL_PATH)

# ----------------------------
# Create temp directory
# ----------------------------
TEMP_DIR = os.path.join(os.path.dirname(__file__), "temp")
os.makedirs(TEMP_DIR, exist_ok=True)


# ----------------------------
# Prediction Endpoint
# ----------------------------
@app.post("/predict-apk")
async def predict_apk(file: UploadFile = File(...)):

    # Save uploaded APK
    temp_path = os.path.join(TEMP_DIR, file.filename)

    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # ----------------------------
        # Feature Extraction
        # ----------------------------
        features = extract_features(temp_path)

        df = pd.DataFrame([features])

        # ----------------------------
        # Model Prediction
        # ----------------------------
        prob = model.predict_proba(df)[0][1]
        risk_score = round(prob * 100, 2)

        # ----------------------------
        # Risk Labeling
        # ----------------------------
        if risk_score < 35:
            label = "SAFE"
        elif risk_score < 75:
            label = "SUSPICIOUS"
        else:
            label = "MALICIOUS"

        # ----------------------------
        # Response
        # ----------------------------
        return {
            "file": file.filename,
            "risk_score": risk_score,
            "label": label,
            "api_key_loaded": API_KEY is not None   # optional debug check
        }

    except Exception as e:
        return {
            "error": str(e),
            "status": "failed"
        }

    finally:
        # Cleanup temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
    