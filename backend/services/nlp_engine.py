import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../fraud_model.pkl")

# Keeping dummy training data for prototype functioning, but expanding to realistic BEC examples
TRAINING_DATA = [
    ("URGENT: Your account has been suspended. Click here to verify your identity.", 1),
    ("You have won a $1000 gift card! Reply immediately to claim your prize.", 1),
    ("Invoice #9942 attached. Please wire the payment to the new bank account by today.", 1),
    ("Security Alert: Unauthorized access detected. Update your password now.", 1),
    ("CEO Request: I am in a meeting, please buy $500 in Apple gift cards and send me the codes.", 1),
    ("Hi team, just a reminder about our meeting at 3 PM tomorrow.", 0),
    ("Attached is the quarterly financial report for your review. Let me know if you have questions.", 0),
    ("Hey mom, I'll be coming home for dinner around 7. See you then!", 0),
    ("Your Amazon order has shipped and will arrive on Tuesday.", 0),
    ("Following up on our previous conversation, I have updated the Jira ticket.", 0),
    ("Meet our newest plan: ChatGPT Go. Upgrade today.", 0) # Legitimate marketing
]

def train_dummy_model():
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]
    model = make_pipeline(TfidfVectorizer(stop_words='english'), LogisticRegression())
    model.fit(texts, labels)
    joblib.dump(model, MODEL_PATH)

def analyze_text(text: str) -> dict:
    if not os.path.exists(MODEL_PATH):
        train_dummy_model()
        
    model = joblib.load(MODEL_PATH)
    
    text_clean = text.lower()
    prob = model.predict_proba([text])[0][1] 
    nlp_score = round(prob * 100, 2)
    
    # Multi-signal extraction
    signals = []
    
    urgency = ["urgent", "immediately", "now", "24 hours", "suspended", "action required"]
    if any(w in text_clean for w in urgency):
        signals.append({"type": "URGENCY", "description": "Urgency manipulation language detected"})
        
    financial = ["invoice", "wire", "payment", "gift card", "bank account", "transfer"]
    if any(w in text_clean for w in financial):
        signals.append({"type": "FINANCIAL", "description": "Payment diversion or financial request detected"})
        
    credential = ["verify your", "login", "password", "unauthorized access", "update your account"]
    if any(w in text_clean for w in credential):
        signals.append({"type": "CREDENTIAL", "description": "Credential harvesting language detected"})
        
    impersonation = ["ceo", "president", "board meeting", "confidential request"]
    if any(w in text_clean for w in impersonation):
        signals.append({"type": "IMPERSONATION", "description": "Executive impersonation cues detected"})

    return {
        "nlp_fraud_probability": nlp_score,
        "signals": signals
    }
