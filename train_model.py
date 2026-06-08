import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from androguard.misc import AnalyzeAPK

# =========================
# FEATURE ENGINEERING (SAME AS APK)
# =========================
def extract_features_from_apk(apk_path, label):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        perms = a.get_permissions()

        return {
            "num_permissions": len(perms),
            "dangerous_permissions": len([p for p in perms if "dangerous" in p.lower()]),
            "num_activities": len(a.get_activities()),
            "num_services": len(a.get_services()),
            "num_receivers": len(a.get_receivers()),
            "api_calls": sum(1 for _ in dx.get_methods()),
            "apk_size": os.path.getsize(apk_path),
            "label": label
        }
    except:
        return None


# =========================
# BUILD SMALL TRAIN DATASET
# =========================
def build_dataset():
    data = []

    # SAFE APKs
    safe_dir = "./sample_apks"
    for f in os.listdir(safe_dir):
        if f.endswith(".apk"):
            path = os.path.join(safe_dir, f)
            data.append(extract_features_from_apk(path, 0))

    # MALWARE APKs (optional folder)
    malware_dir = "./dataset/malware_apks"
    if os.path.exists(malware_dir):
        for f in os.listdir(malware_dir):
            if f.endswith(".apk"):
                path = os.path.join(malware_dir, f)
                data.append(extract_features_from_apk(path, 1))

    df = pd.DataFrame([d for d in data if d is not None])
    return df


# =========================
# TRAIN MODEL
# =========================
print("[INFO] Building dataset...")
df = build_dataset()

print("[INFO] Dataset shape:", df.shape)
print(df["label"].value_counts())

X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

print("[INFO] Training model...")
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

print("[INFO] Accuracy:", model.score(X_test, y_test))

joblib.dump(model, "ml_model.pkl")
print("[SUCCESS] Model saved as ml_model.pkl")