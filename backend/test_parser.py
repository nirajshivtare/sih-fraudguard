import json
from services.parser import parse_eml

def test_parser():
    with open("sample_phishing.eml", "rb") as f:
        content = f.read()
        
    result = parse_eml(content)
    
    print("--- Forensic Email Parser Output ---")
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    test_parser()
