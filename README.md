# 🛡️ PhishShield — Real-Time Phishing Detection Browser Extension

<div align="center">

![PhishShield Banner](https://img.shields.io/badge/PhishShield-v1.1-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A powerful browser extension that detects phishing websites in real-time using 18+ heuristic checks, live threat database lookups, and typosquatting detection — with automatic blocking and popup warnings.**

</div>

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🔍 **Real-Time URL Scanning** | Every page you visit is automatically scanned in the background |
| 🚫 **Auto-Block** | High-risk phishing pages are instantly blocked with a full-page warning |
| ⚠️ **Popup Warnings** | Medium-risk sites show a dismissible warning toast notification |
| 🎯 **18+ Detection Checks** | SSL verification, typosquatting, keyword analysis, DNS resolution, and more |
| 🌐 **Live Threat Database** | Queries URLhaus (abuse.ch) for known malware/phishing URLs |
| 🧠 **Brand Impersonation Detection** | Detects typosquatting of 50+ major brands (Google, PayPal, Amazon, etc.) |
| 📊 **Risk Scoring** | 0–100 risk score with detailed reasons for each finding |
| 🖥️ **Web Dashboard** | Standalone web frontend to manually scan any URL |
| 📜 **Scan History** | Logs all scanned URLs with scores and verdicts |

---

## 📁 Project Structure

```
phishshield/
├── backend/                  # Flask API Server
│   ├── app.py               # Main API routes (/scan, /health, /history)
│   ├── utils.py             # Core phishing detection engine (18+ checks)
│   ├── requirements.txt     # Python dependencies
│   └── history.txt          # Scan history log (auto-generated)
│
├── extension/               # Chrome/Edge Browser Extension (Manifest V3)
│   ├── manifest.json        # Extension configuration
│   ├── background.js        # Service worker for API communication
│   ├── content.js           # Auto-scan & block/warn injected into pages
│   ├── content.css          # Warning popup styles
│   ├── popup.html           # Extension popup UI
│   └── popup.js             # Popup logic
│
├── frontend/                # Web Dashboard
│   └── index.html           # Manual URL scanner interface
│
└── model/                   # ML Model (optional)
    ├── train.py             # Model training script
    └── model.pkl            # Trained Logistic Regression model
```

---

## 🔬 Detection Engine — 18 Real-World Checks

The phishing detection engine in `utils.py` performs the following checks:

| # | Check | Score Impact |
|---|-------|-------------|
| 1 | HTTPS protocol validation | +20 |
| 2 | Raw IP address usage | +30 |
| 3 | Suspicious TLD detection (.tk, .xyz, .ml, etc.) | +15 |
| 4 | **Typosquatting detection** (50+ brands) | +30 |
| 5 | Phishing keywords in URL path/query | +10 to +25 |
| 6 | Abnormal URL length | +10 to +20 |
| 7 | `@` symbol in URL (redirection attacks) | +25 |
| 8 | Excessive subdomains | +5 to +15 |
| 9 | Excessive hyphens in domain | +5 to +15 |
| 10 | Numeric characters in domain | +10 |
| 11 | Excessive dots in URL | +10 |
| 12 | Suspicious path patterns (hex tokens, double extensions) | +5 to +10 |
| 13 | **SSL certificate verification** | +25 |
| 14 | **URLhaus threat database lookup** (real-time) | +40 |
| 15 | Punycode / IDN domain detection | +20 |
| 16 | Data/JavaScript URI schemes | +40 |
| 17 | DNS resolution check | +15 |
| 18 | URL shortener detection & expansion | +15 |

---

## ⚙️ Setup & Installation

### Prerequisites

- **Python 3.10+**
- **Google Chrome** or **Microsoft Edge** browser
- **pip** (Python package manager)

### 1. Clone the Repository

```bash
git clone https://github.com/sahibjeenwal-bit/RNRJ.git
cd RNRJ
```

### 2. Setup Backend

```bash
cd phishshield/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate      # On macOS/Linux
# venv\Scripts\activate       # On Windows

# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
```

The API server will start at `http://127.0.0.1:5001`

### 3. Load the Browser Extension

1. Open **Chrome** → Navigate to `chrome://extensions/`
2. Enable **Developer Mode** (toggle in top right)
3. Click **"Load unpacked"**
4. Select the `phishshield/extension/` folder
5. The PhishShield icon will appear in your toolbar

### 4. (Optional) Open Web Dashboard

Open `phishshield/frontend/index.html` in your browser to use the manual URL scanner.

---

## 🧪 Testing the Extension

Since legitimate websites (Google, YouTube, etc.) are correctly identified as **Safe**, use these test URLs to see the detection in action:

### Test Phishing URLs (type in browser address bar):

| URL | Expected Score | Expected Verdict |
|-----|---------------|-----------------|
| `http://paypal-secure-login.tk/verify/account` | ~95 | ❌ Phishing (Auto-Blocked) |
| `http://g00gle-login.xyz/secure/verify` | ~65 | ❌ Phishing (Auto-Blocked) |
| `http://free-prize-winner.buzz/claim` | ~50 | ⚠️ Suspicious (Warning Popup) |
| `https://www.google.com` | 0 | ✅ Safe |

### API Test (via curl):

```bash
curl -X POST http://127.0.0.1:5001/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.tk/verify"}'
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API status check |
| `GET` | `/health` | Health check |
| `POST` | `/scan` | Scan a URL for phishing (JSON body: `{"url": "..."}`) |
| `GET` | `/history` | Get scan history |

### Scan Response Example

```json
{
  "url": "http://paypal-secure-login.tk/verify/account",
  "risk_score": 95,
  "risk_level": "High",
  "verdict": "Phishing",
  "is_phishing": true,
  "reasons": [
    "No HTTPS encryption — connection is not secure",
    "Uses suspicious/abused TLD: .tk",
    "Domain impersonates known brand(s): paypal",
    "Suspicious keyword(s) in URL: verify, account",
    "Domain contains hyphens",
    "Domain does not resolve — may be newly registered or fake"
  ],
  "response_time_ms": 1727.47,
  "status": "success"
}
```

---

## 🏗️ Tech Stack

- **Backend:** Python, Flask, Flask-CORS
- **Detection:** Rule-based heuristics + URLhaus API + SSL verification
- **Extension:** Chrome Manifest V3, JavaScript
- **Frontend:** HTML5, CSS3, JavaScript
- **ML Model:** Scikit-learn Logistic Regression (optional)

---

## 👥 Team

**Team RNRJ** — Built for Hackathon

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**⭐ Star this repo if you found it useful! ⭐**

</div>
