# 🛡️ Cyber Suraksha AI

AI-powered scam detection and awareness system focused on Indian users.
Combines **Machine Learning + Crowd Intelligence + Secure Authentication**.

---

## 🌐 Live Demo

👉 (Add after deployment)
https://your-app.onrender.com

---

## 🚀 Features

* 🔍 Scam Message Detection (ML-based NLP)
* 🔗 URL Safety Checker
* 📞 Scam Number Detection (crowd intelligence)
* 🧠 Self-learning system (based on reports)
* 🔐 Secure authentication (JWT + bcrypt)
* 📊 Dashboard analytics

---

## 📁 Project Structure

```
cyber-suraksha-ai/
├── backend/
├── frontend/
├── dataset/
└── README.md
```

---

## ⚡ Quick Start

```bash
pip install -r requirements.txt
cd backend
python train_model.py
python app.py
```

Open:

```
frontend/index.html
```

---

## 🔐 Authentication Flow

```text
Register → Login → Get Token → Use in /report API
```

---

## 🧪 API Reference

### POST /predict

Detect scam message

```json
{ "message": "You won ₹50,000 prize!" }
```

---

### POST /check-url

```json
{ "url": "https://bit.ly/free" }
```

---

### POST /check-number

```json
{ "number": "9000000000" }
```

---

### POST /report (🔒 Protected)

Header:

```
Authorization: Bearer YOUR_TOKEN
```

```json
{
  "type": "number",
  "content": "9123456789"
}
```

---

### GET /dashboard

Returns scan statistics

---

## 🧠 Tech Stack

* Backend: Flask (Python)
* ML: Scikit-learn (TF-IDF + Logistic Regression)
* Auth: JWT + bcrypt
* DB: SQLite
* Frontend: HTML/CSS/JS

---

## 🚀 Deployment

Backend deployed on:

* Render

Frontend deployed on:

* Netlify

---

## 💡 Key Highlights

* Real-world problem solving (cyber fraud)
* Secure authentication system
* Self-improving AI (crowd intelligence)
* Full-stack architecture

---

## 🎯 Use Cases

* Detect phishing messages
* Identify scam phone numbers
* Educate users about fraud

---

## 👨‍💻 Author

Devendra Jat

---

*Built as a real-world AI + Web Security project.*
