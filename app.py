from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import pickle
import sqlite3
import re
import os
import bcrypt

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"
jwt = JWTManager(app)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VEC_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
DB_PATH = os.path.join(BASE_DIR, "database.db")
# ─── Load Model ─────────────────────────
import joblib

try:
    model = joblib.load("model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    ML_AVAILABLE = True
    print("[OK] ML model loaded")
except Exception as e:
    ML_AVAILABLE = False
    print("[WARN] Model not found:", e)

# ─── DB INIT ───────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password BLOB
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS reported_numbers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS reported_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS scan_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        input_type TEXT,
        input_text TEXT,
        result TEXT
    )""")

    conn.commit()
    conn.close()

# ─── LOGGING ───────────────────────────
def log_scan(t, text, result):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO scan_log (input_type, input_text, result) VALUES (?, ?, ?)",
        (t, text[:500], result)
    )
    conn.commit()
    conn.close()

# ─── PREPROCESS ────────────────────────
def preprocess(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return text

# ─── ROUTES ───────────────────────────

@app.route("/")
def home():
    return jsonify({"status": "running", "ml": ML_AVAILABLE})

# 🔥 MESSAGE DETECTION + INTELLIGENCE
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    if not data or "message" not in data:
        return jsonify({"error": "message required"}), 400

    text = data["message"].strip()

    # intelligence system
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute(
        "SELECT COUNT(*) FROM reported_messages WHERE message LIKE ?",
        ('%' + text[:20] + '%',)
    ).fetchone()[0]
    conn.close()

    if count >= 3:
        return jsonify({"result": "Scam", "note": f"Reported {count} times"})

    if ML_AVAILABLE:
        vec = vectorizer.transform([preprocess(text)])
        pred = model.predict(vec)[0]
        result = "Scam" if pred == 1 else "Safe"
        note = "ML detection"
    else:
        result = "Suspicious"
        note = "Rule-based fallback"

    log_scan("message", text, result)
    return jsonify({"result": result, "note": note})

# 🔗 URL CHECK
@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "url required"}), 400

    url = data["url"].lower()

    if any(x in url for x in ["bit.ly", "tinyurl", "otp", "bank"]):
        result = "Suspicious"
    else:
        result = "Safe"

    log_scan("url", url, result)
    return jsonify({"result": result})

# 📞 NUMBER CHECK
@app.route("/check-number", methods=["POST"])
def check_number():
    data = request.get_json()

    if not data or "number" not in data:
        return jsonify({"error": "number required"}), 400

    number = re.sub(r"\D", "", data["number"])

    conn = sqlite3.connect(DB_PATH)
    count = conn.execute(
        "SELECT COUNT(*) FROM reported_numbers WHERE number=?",
        (number,)
    ).fetchone()[0]
    conn.close()

    if count >= 3:
        result = "Scam Number"
        note = f"Reported {count} times"
    elif count > 0:
        result = "Suspicious"
        note = f"Reported {count} time(s)"
    else:
        result = "Unknown"
        note = "No reports"

    log_scan("number", number, result)
    return jsonify({"result": result, "note": note})

# 🔐 REGISTER (HASHED PASSWORD)
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username & password required"}), 400

    hashed = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (data["username"], hashed)
        )
        conn.commit()
    except:
        return jsonify({"error": "User exists"}), 400
    finally:
        conn.close()

    return jsonify({"message": "registered"})

# 🔐 LOGIN (HASH CHECK)
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username & password required"}), 400

    conn = sqlite3.connect(DB_PATH)
    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (data["username"],)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(data["password"].encode(), user[2]):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=data["username"])
    return jsonify({"token": token})

# 🔒 REPORT (PROTECTED)
@app.route("/report", methods=["POST"])
@jwt_required()
def report():
    data = request.get_json()

    if not data or "type" not in data or "content" not in data:
        return jsonify({"error": "type & content required"}), 400

    conn = sqlite3.connect(DB_PATH)

    if data["type"] == "number":
        num = re.sub(r"\D", "", data["content"])
        conn.execute("INSERT INTO reported_numbers (number) VALUES (?)", (num,))
    else:
        conn.execute("INSERT INTO reported_messages (message) VALUES (?)", (data["content"],))

    conn.commit()
    conn.close()

    return jsonify({"success": True})

# 📊 DASHBOARD
@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB_PATH)

    total = conn.execute("SELECT COUNT(*) FROM scan_log").fetchone()[0]
    scam = conn.execute("SELECT COUNT(*) FROM scan_log WHERE result='Scam'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM scan_log WHERE result='Suspicious'").fetchone()[0]

    conn.close()

    return jsonify({
        "total_scans": total,
        "scam_count": scam,
        "suspicious_count": suspicious,
        "safe_count": total - scam - suspicious
    })

# ─── RUN ───────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=10000)