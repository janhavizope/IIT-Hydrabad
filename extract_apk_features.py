import os
import pandas as pd
from androguard.misc import AnalyzeAPK

# =========================
# CONFIG
# =========================
APK_FOLDER = "./sample_apks"
OUTPUT_FILE = "apk_dataset.csv"

# =========================
# FEATURE EXTRACTOR
# =========================
def extract_features(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)

        features = {}

        # -------------------------
        # 1. PERMISSIONS
        # -------------------------
        perms = a.get_permissions() or []

        features["num_permissions"] = len(perms)

        features["dangerous_permissions"] = len([
            p for p in perms if "dangerous" in p.lower()
        ])

        # -------------------------
        # 2. COMPONENTS
        # -------------------------
        features["num_activities"] = len(a.get_activities() or [])
        features["num_services"] = len(a.get_services() or [])
        features["num_receivers"] = len(a.get_receivers() or [])

        # -------------------------
        # 3. API CALLS
        # -------------------------
        api_calls = sum(1 for _ in dx.get_methods())
        features["api_calls"] = api_calls

        # -------------------------
        # 4. INTENT FILTERS (SAFE VERSION)
        # -------------------------
        try:
            intents = a.get_intent_filters()
            features["intent_filters"] = len(intents) if intents else 0
        except:
            features["intent_filters"] = 0

        # -------------------------
        # 5. FILE SIZE
        # -------------------------
        features["apk_size"] = os.path.getsize(apk_path)

        return features

    except Exception as e:
        print(f"[ERROR] Failed on {apk_path}: {e}")
        return None


# =========================
# BUILD DATASET FROM FOLDER
# =========================
def build_dataset():
    dataset = []

    print("[INFO] Scanning APK folder:", APK_FOLDER)

    for file in os.listdir(APK_FOLDER):
        if file.endswith(".apk"):
            apk_path = os.path.join(APK_FOLDER, file)

            print(f"[INFO] Processing: {file}")

            features = extract_basic_features(apk_path)

            if features:
                # TEMP LABEL (you can modify later)
                features["label"] = 1 if "malware" in file.lower() else 0

                dataset.append(features)

    df = pd.DataFrame(dataset)

    print("\n[INFO] Final Dataset Shape:", df.shape)

    print("\n[INFO] Label Distribution:")
    print(df["label"].value_counts())

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\n[SUCCESS] Dataset saved → {OUTPUT_FILE}")


# =========================
# RUN
# =========================
if __name__ == "__main__":
    build_dataset()