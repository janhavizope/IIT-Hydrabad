import requests
import json
import os

API_URL = "http://127.0.0.1:8000/predict-apk"

# Create a dummy APK file
with open("test_dummy.apk", "wb") as f:
    f.write(b"PK\x03\x04dummyapkcontent")

print("=== Testing Legacy /predict-apk Endpoint ===")

with open("test_dummy.apk", "rb") as f:
    files = {"file": ("test_dummy.apk", f, "application/vnd.android.package-archive")}
    response = requests.post(API_URL, files=files)

print(f"Status: {response.status_code}")
try:
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error parsing JSON: {e}")
    print(f"Raw response: {response.text}")

os.remove("test_dummy.apk")
