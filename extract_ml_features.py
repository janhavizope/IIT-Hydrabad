import json
import os

APK_DIR = "sample_apks"
OUTPUT_FILE = "ml_training_features.json"

dataset = []

if not os.path.exists(APK_DIR):
    print(f"[ERROR] Folder not found: {APK_DIR}")
    exit()

for file in os.listdir(APK_DIR):
    if file.endswith(".apk"):
        apk_path = os.path.join(APK_DIR, file)

        dataset.append({
            "name": file,
            "size": os.path.getsize(apk_path),
            "verdict": 0  # temporary placeholder
        })

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(dataset, f, indent=4)

print(f"[DONE] Created dataset with {len(dataset)} samples → {OUTPUT_FILE}")
