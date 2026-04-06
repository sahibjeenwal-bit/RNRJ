import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
from sklearn.linear_model import LogisticRegression
import joblib

# -------------------------------
# Feature Extraction Function
# -------------------------------
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    ext = tldextract.extract(url)
    subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_https": 1 if url.startswith("https") else 0,
        "has_at": 1 if "@" in url else 0,
        "has_hyphen": 1 if "-" in domain else 0,
        "has_keywords": 1 if re.search(
            r"login|verify|bank|secure|update", url, re.IGNORECASE
        ) else 0,
        "has_ip": 1 if re.match(
            r"http[s]?://\d+\.\d+\.\d+\.\d+", url
        ) else 0,
        "num_subdomains": len(subdomain_parts)
    }


# -------------------------------
# Load Dataset (FROM CSV)
# -------------------------------
df = pd.read_csv("dataset.csv")

# Clean data
df = df.dropna()

# Rename column
df = df.rename(columns={"type": "label"})

# Convert labels to numbers
df["label"] = df["label"].map({
    "benign": 0,
    "phishing": 1,
    "defacement": 1
})

# Remove invalid rows
df = df.dropna()

# Reduce dataset size (fast training)
df = df.sample(5000)

# -------------------------------
# Feature Extraction
# -------------------------------
X = df["url"].apply(extract_features).apply(pd.Series)
y = df["label"]

# -------------------------------
# Train Model
# -------------------------------
model = LogisticRegression(max_iter=200)
model.fit(X, y)

# -------------------------------
# Save Model
# -------------------------------
joblib.dump(model, "model.pkl")

print("Model trained and saved as model.pkl")
