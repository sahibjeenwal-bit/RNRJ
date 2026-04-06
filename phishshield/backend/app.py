from flask import Flask, request, jsonify
from flask_cors import CORS
from utils import analyze_url
import validators
import time

app = Flask(__name__)
CORS(app)

# -------------------------------
# Logging Function (History)
# -------------------------------
def log_scan(url, score, verdict):
    with open("history.txt", "a") as f:
        f.write(f"{url} | Score: {score} | Verdict: {verdict}\n")


# -------------------------------
# Home Route
# -------------------------------
@app.route("/")
def home():
    return jsonify({
        "message": "PhishShield API Running",
        "status": "success"
    })


# -------------------------------
# Health Check
# -------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "OK"})


# -------------------------------
# Get History
# -------------------------------
@app.route("/history", methods=["GET"])
def get_history():
    try:
        with open("history.txt", "r") as f:
            data = f.readlines()
        return jsonify({"history": data})
    except:
        return jsonify({"history": []})



# -------------------------------
# Test Phishing Page (for demo)
# -------------------------------
@app.route("/test/phishing", methods=["GET"])
def test_phishing():
    """Serves a fake phishing page for testing the extension"""
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>PayPal - Verify Your Account Security</title></head>
    <body style="font-family:Arial; text-align:center; padding:50px;">
        <h1>🔒 PayPal Account Verification</h1>
        <p>This is a <strong>FAKE</strong> test phishing page.</p>
        <p>The extension should detect this page as suspicious!</p>
        <form>
            <input type="text" placeholder="Email" style="padding:10px; margin:5px;"><br>
            <input type="password" placeholder="Password" style="padding:10px; margin:5px;"><br>
            <button style="padding:10px 20px; margin:10px;">Login</button>
        </form>
    </body>
    </html>
    '''

@app.route("/test/safe", methods=["GET"])
def test_safe():
    """Serves a normal safe page for comparison"""
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>My Portfolio</title></head>
    <body style="font-family:Arial; text-align:center; padding:50px;">
        <h1>Welcome to My Portfolio</h1>
        <p>This is a normal, safe page with no phishing indicators.</p>
    </body>
    </html>
    '''


# -------------------------------
# Scan URL Endpoint
# -------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    try:
        start = time.time()

        data = request.get_json()

        if not data:
            return jsonify({"error": "Request must be JSON"}), 400

        url = data.get("url")

        if not url or not isinstance(url, str):
            return jsonify({"error": "Invalid or missing URL"}), 400

        # -------------------------------
        # Normalize URL (FIXED)
        # -------------------------------
        if not url.startswith("http"):
            url = "https://" + url

        # Validate URL format
        if not validators.url(url):
            return jsonify({"error": "Invalid URL format"}), 400

        # -------------------------------
        # Analyze URL
        # -------------------------------
        print(f"\n🔍 Scanning URL: {url}")
        score, reasons = analyze_url(url)
        print(f"   Score: {score}, Reasons: {reasons}")

        # -------------------------------
        # Risk Level
        # -------------------------------
        if score < 30:
            risk_level = "Low"
        elif score < 60:
            risk_level = "Medium"
        else:
            risk_level = "High"

        # -------------------------------
        # Verdict
        # -------------------------------
        if score > 50:
            verdict = "Phishing"
        elif score > 30:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        # -------------------------------
        # Response Time
        # -------------------------------
        response_time = round((time.time() - start) * 1000, 2)

        # -------------------------------
        # Save History
        # -------------------------------
        log_scan(url, score, verdict)

        return jsonify({
            "url": url,
            "risk_score": score,
            "risk_level": risk_level,
            "verdict": verdict,
            "is_phishing": score > 50,
            "reasons": reasons,
            "response_time_ms": response_time,
            "status": "success"
        })

    except Exception as e:
        return jsonify({
            "error": "Internal Server Error",
            "details": str(e)
        }), 500


# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
