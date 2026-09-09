import json
from services.nlp_engine import analyze_text
from services.parser import parse_eml

def test_ai():
    # Read the fake paypal email we created earlier
    with open("sample_phishing.eml", "rb") as f:
        content = f.read()
        
    parsed = parse_eml(content)
    body_text = parsed["body_preview"]
    
    print("--- Analyzing Email Text via AI Engine ---")
    print(f"Text snippet: {body_text[:100]}...\n")
    
    # Run the ML prediction
    result = analyze_text(body_text)
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    test_ai()
