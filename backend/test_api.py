from fastapi.testclient import TestClient
from main import app
import json

client = TestClient(app)

def test_full_pipeline():
    # Read the mock email
    with open("sample_phishing.eml", "rb") as f:
        file_content = f.read()

    print("--- Sending sample_phishing.eml to FastAPI Backend ---")
    
    # Simulate a frontend uploading the file to our /api/v1/analyze-email endpoint
    response = client.post(
        "/api/v1/analyze-email",
        files={"file": ("sample_phishing.eml", file_content, "message/rfc822")}
    )
    
    if response.status_code == 200:
        print("SUCCESS! Here is the final consolidated JSON response from the server:\n")
        print(json.dumps(response.json(), indent=4))
    else:
        print(f"Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    test_full_pipeline()
