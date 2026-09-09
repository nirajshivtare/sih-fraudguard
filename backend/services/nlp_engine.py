import os
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
import joblib

MODEL_PATH = "fraud_model.pkl"

# A small dummy dataset for the prototype (In a real scenario, this would be thousands of emails)
TRAINING_DATA = [
    # Phishing / Fraud
    ("URGENT: Your account has been suspended. Click here to verify your identity.", 1),
    ("You have won a $1000 gift card! Reply immediately to claim your prize.", 1),
    ("Invoice #9942 attached. Please wire the payment to the new bank account by today.", 1),
    ("Security Alert: Unauthorized access detected. Update your password now.", 1),
    ("CEO Request: I am in a meeting, please buy $500 in Apple gift cards and send me the codes.", 1),
    
    # Legitimate
    ("Hi team, just a reminder about our meeting at 3 PM tomorrow.", 0),
    ("Attached is the quarterly financial report for your review. Let me know if you have questions.", 0),
    ("Hey mom, I'll be coming home for dinner around 7. See you then!", 0),
    ("Your Amazon order has shipped and will arrive on Tuesday.", 0),
    ("Following up on our previous conversation, I have updated the Jira ticket.", 0)
]

def train_dummy_model():
    """
    Trains a lightweight TF-IDF + Logistic Regression model for the hackathon prototype.
    """
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]
    
    model = make_pipeline(TfidfVectorizer(stop_words='english'), LogisticRegression())
    model.fit(texts, labels)
    
    joblib.dump(model, MODEL_PATH)
    print("Model trained and saved to", MODEL_PATH)

def analyze_text(text: str) -> dict:
    """
    Analyzes the email body text and returns a fraud probability score and detected flags.
    """
    # 1. Check if model exists, if not train it
    if not os.path.exists(MODEL_PATH):
        train_dummy_model()
        
    model = joblib.load(MODEL_PATH)
    
    # 2. Predict Probability of Fraud (Class 1)
    # predict_proba returns [[prob_legit, prob_fraud]]
    prob = model.predict_proba([text])[0][1] 
    fraud_score_percentage = round(prob * 100, 2)
    
    # 3. Rule-based heuristic extraction (to show the analyst *why* it got this score)
    urgency_keywords = ["urgent", "immediately", "now", "24 hours", "suspended", "action required"]
    financial_keywords = ["invoice", "wire", "payment", "gift card", "bank account", "transfer"]
    
    detected_urgency = [word for word in urgency_keywords if word in text.lower()]
    detected_financial = [word for word in financial_keywords if word in text.lower()]
    
    # Simple risk classification
    if fraud_score_percentage > 70:
        risk_level = "HIGH RISK"
    elif fraud_score_percentage > 40:
        risk_level = "MODERATE RISK"
    else:
        risk_level = "LOW RISK"

    return {
        "fraud_score": fraud_score_percentage,
        "risk_level": risk_level,
        "detected_flags": {
            "urgency_cues": detected_urgency,
            "financial_cues": detected_financial
        }
    }
