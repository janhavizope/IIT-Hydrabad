import requests
import json
import time

API_URL = "http://127.0.0.1:8000/api/scan-apk"

TEST_URLS = [
    "http://invalid-url-scheme.com/test.apk", # Invalid scheme (should be handled quickly)
    "https://github.com/apk-guardian/test.apk", # Trusted domain, likely 404 but shouldn't hang
    "https://unknown-domain.xyz/malicious.apk", # Unknown domain -> Supply Chain Risk
]

print("=== Testing Production Backend ===")

for url in TEST_URLS:
    print(f"\nTesting URL: {url}")
    start = time.time()
    try:
        response = requests.post(API_URL, json={"apk_url": url}, timeout=40)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")
    end = time.time()
    print(f"Time taken: {end - start:.2f}s")
