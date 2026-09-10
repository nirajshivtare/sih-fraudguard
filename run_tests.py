import requests
import json
import os

URL = "http://localhost:8000/api/v1/analyze-email"

def test_file(filename):
    print(f"\n--- Testing {filename} ---")
    filepath = os.path.join("backend", filename)
    with open(filepath, "rb") as f:
        files = {"file": (filename, f, "message/rfc822")}
        try:
            resp = requests.post(URL, files=files)
            if resp.status_code == 200:
                data = resp.json()
                print("SUCCESS")
                print("Case ID:", data.get("case_id"))
                print("Fraud Risk:", data["scoring"]["fraud_risk"]["score"])
                print("Origin Confidence:", data["scoring"]["origin_confidence"]["score"])
            else:
                print("FAILED:", resp.status_code, resp.text)
        except Exception as e:
            print("ERROR connecting:", e)

test_file("demo_bec_attack.eml")
test_file("test_legitimate.eml")
