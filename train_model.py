"""
train_model.py — Cyber Suraksha AI
Trains a Multinomial Naive Bayes model on SMS spam data.
Run this ONCE before starting the Flask server.

Usage:
    python train_model.py
"""

import os
import pickle
import re
import urllib.request

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATASET    = os.path.join(BASE_DIR, "..", "dataset", "spam.csv")
MODEL_OUT  = os.path.join(BASE_DIR, "model.pkl")
VEC_OUT    = os.path.join(BASE_DIR, "vectorizer.pkl")

# ─── Stopwords ────────────────────────────────────────────────────────────────
STOPWORDS = {
    "i","me","my","we","our","you","your","he","his","she","her",
    "it","its","they","them","their","is","are","was","were","be",
    "been","being","have","has","had","do","does","did","will","would",
    "shall","should","may","might","must","can","could","a","an","the",
    "and","but","or","nor","for","so","yet","at","by","in","of","on",
    "to","up","as","if","then","than","that","this","with","not","no"
}

def preprocess(text):
    """Lowercase, remove special chars, remove stopwords."""
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    tokens = [t for t in text.split() if t not in STOPWORDS]
    return " ".join(tokens)


def load_dataset():
    """
    Load the SMS Spam Collection dataset.
    Download from: https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection
    Expects dataset/spam.csv with columns: label, message
    """
    if not os.path.exists(DATASET):
        print(f"[WARN] Dataset not found at {DATASET}")
        print("Generating synthetic training data instead...")
        return generate_synthetic_data()

    import csv
    labels, messages = [], []
    with open(DATASET, encoding="latin-1") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for row in reader:
            if len(row) >= 2:
                label = 1 if row[0].strip().lower() == "spam" else 0
                labels.append(label)
                messages.append(row[1])

    print(f"[OK] Loaded {len(messages)} records from dataset.")
    return messages, labels


def generate_synthetic_data():
    """
    Fallback: synthetic training data if real dataset is missing.
    Covers Indian scam patterns (OTP fraud, lottery, KYC, etc.)
    """
    ham_messages = [
        "Hey, are you coming for dinner tonight?",
        "Your OTP for login is 482910. Do not share it.",
        "Meeting rescheduled to 3 PM tomorrow.",
        "Mom is calling you, please pick up.",
        "I will be late by 20 minutes, stuck in traffic.",
        "Can you send me the notes from today's class?",
        "Happy birthday! Hope you have a great day.",
        "The package has been delivered to your address.",
        "Please confirm your appointment for tomorrow.",
        "Your order #12345 has been shipped.",
        "Reminder: your bill is due on the 15th.",
        "Thanks for your feedback. We will improve.",
        "See you at the gym at 7 AM.",
        "Your flight is on time. Gate B12.",
        "Call me when you are free. No rush.",
        "The electricity bill for this month is Rs 1200.",
        "Your bank statement is ready for download.",
        "New message from your school: holiday on Monday.",
        "Library book return date: 10th of this month.",
        "Lunch is ready. Come home soon.",
    ] * 30  # repeat to get enough samples

    spam_messages = [
        "Congratulations! You have WON Rs 50,000 lottery. Call now to CLAIM your PRIZE!",
        "URGENT: Your KYC is incomplete. Update NOW or your account will be SUSPENDED.",
        "FREE GIFT! You are our lucky winner. Click here to claim: bit.ly/prize123",
        "Your Aadhaar is linked to illegal activity. Call 9000012345 IMMEDIATELY.",
        "Dear customer, your bank account will be BLOCKED. Verify OTP: 8888888888",
        "Get loan Rs 5 lakh in 10 minutes. No documents needed. Call 7777777777.",
        "You have been selected for a job offer. Send Rs 500 registration fee now.",
        "ALERT: Suspicious login detected. Verify your account: tinyurl.com/verify",
        "Win iPhone 14 FREE! Forward this to 10 friends and click: goo.gl/iphone",
        "Your credit card has been compromised. Call 1800-FAKE-BANK immediately.",
        "SBI ALERT: Your account is at risk. Share OTP to verify: 1234",
        "Income Tax refund of Rs 15,000 pending. Click to claim: bit.ly/taxrefund",
        "Paytm KYC expired! Update in 24 hours or wallet will be disabled.",
        "You won Rs 25 lakh in WhatsApp lottery. Send Rs 1000 processing fee.",
        "CYBER CRIME WARNING: Your mobile will be blocked. Call 9876000001 now.",
        "Get 50% off on all medicines. Limited time offer. Order now: xyz.com",
        "Earn Rs 10,000 daily from home. No experience needed. WhatsApp us NOW.",
        "Your SIM card will be deactivated. Verify immediately by calling 8000000000.",
        "URGENT job offer: Rs 50,000/month. Pay Rs 2,000 registration. Call now.",
        "Free recharge Rs 500! Share your mobile number and OTP to activate.",
    ] * 30

    messages = ham_messages + spam_messages
    labels = [0] * len(ham_messages) + [1] * len(spam_messages)
    print(f"[OK] Generated {len(messages)} synthetic training samples.")
    return messages, labels


def train():
    print("\n🛡️  Cyber Suraksha AI — Model Training")
    print("=" * 50)

    # 1. Load data
    messages, labels = load_dataset()

    # 2. Preprocess
    print("[...] Preprocessing text...")
    cleaned = [preprocess(m) for m in messages]

    # 3. Vectorize (TF-IDF)
    print("[...] Fitting TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),  # unigrams + bigrams
        min_df=2
    )
    X = vectorizer.fit_transform(cleaned)
    y = np.array(labels)

    # 4. Train/test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 5. Train model
    print("[...] Training Multinomial Naive Bayes...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)
    # 6. Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[RESULT] Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Ham (Safe)", "Spam (Scam)"]))

    # 7. Save model and vectorizer
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(model, f)
    with open(VEC_OUT, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"[OK] Model saved to: {MODEL_OUT}")
    print(f"[OK] Vectorizer saved to: {VEC_OUT}")
    print("\n✅ Training complete! You can now run app.py\n")


if __name__ == "__main__":
    train()
