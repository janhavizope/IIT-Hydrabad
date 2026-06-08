import os
import joblib
import pandas as pd
from androguard.misc import AnalyzeAPK

# =========================
# LOAD TRAINED MODEL
# =========================
MODEL_PATH = "ml_model.pkl"
model = joblib.load(MODEL_PATH)


# =========================
# FEATURE EXTRACTION (SAME AS TRAINING)
# =========================
def extract_features(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)

        perms = a.get_permissions()

        features = {
            "num_permissions": len(perms),
            "dangerous_permissions": len([p for p in perms if "dangerous" in p.lower()]),
            "num_activities": len(a.get_activities()),
            "num_services": len(a.get_services()),
            "num_receivers": len(a.get_receivers()),
            "api_calls": sum(1 for _ in dx.get_methods()),
            "apk_size": os.path.getsize(apk_path)
        }

        return pd.DataFrame([features])

    except Exception as e:
        print("[ERROR] Feature extraction failed:", e)
        return None


# =========================
# PREDICTION + RISK SCORE
# =========================
def predict_apk(apk_path):
    print("[INFO] Extracting features...")

    df = extract_features(apk_path)
    if df is None:
        return

    print("[INFO] Running model prediction...")

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1]  # malware probability

    risk_score = round(probability * 100, 2)

    print("\n==============================")
    print("🔍 APK ANALYSIS RESULT")
    print("==============================")

    if prediction == 1:
        print("🚨 Status: MALICIOUS APK")
    else:
        print("🟢 Status: SAFE APK")

    print(f"📊 Risk Score: {risk_score}/100")
    print("==============================\n")


# =========================
# RUN
# =========================
if __name__ == "__main__":
    apk_path = "sample_apks/InsecureBankv2.apk"
    predict_apk(apk_path)