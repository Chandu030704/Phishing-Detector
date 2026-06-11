from flask import Flask, render_template, request, jsonify, redirect
import re
import pickle
import numpy as np
from urllib.parse import urlparse
import warnings
import os

warnings.filterwarnings("ignore", category=UserWarning)

app = Flask(__name__)

# ---------------- LOAD MODEL ----------------
model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
model = pickle.load(open(model_path, 'rb'))


# ---------------- FEATURE EXTRACTION ----------------
def extract_features(url):
    features = []

    # Add protocol if missing
    if not url.startswith('http'):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. having_IP_Address
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain):
        features.append(-1)
    else:
        features.append(1)

    # 2. URL_Length
    length = len(url)
    if length < 54:
        features.append(1)
    elif length <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 3. having_At_Symbol
    features.append(-1 if "@" in url else 1)

    # 4. double_slash_redirecting
    features.append(-1 if url.count("//") > 1 else 1)

    # 5. Prefix_Suffix
    features.append(-1 if "-" in domain else 1)

    # 6. HTTPS_token
    clean_domain = domain.replace("www.", "")
    features.append(-1 if "https" in clean_domain else 1)

    return np.array([features])


# ---------------- PREDICTION FUNCTION ----------------
def check_phishing(url):
    features = extract_features(url)

    prediction = model.predict(features)[0]
    probs = model.predict_proba(features)[0]

    classes = list(model.classes_)

    phishing_prob = probs[classes.index(-1)] if -1 in classes else probs[0]

    url_lower = url.lower()

    # ---------------- RULE-BASED OVERRIDES ----------------

    # Case 1: IP + @
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) and "@" in url:
        return "⚠ Phishing Website", 95.0

    # Case 2: @ + hyphen + suspicious words
    if "@" in url and "-" in url and any(
        word in url_lower for word in
        ['login', 'verify', 'bank', 'secure', 'account']
    ):
        return "⚠ Phishing Website", 92.0

    # Case 3: Long URL + suspicious words
    if len(url) > 75 and any(
        word in url_lower for word in
        ['login', 'verify', 'bank', 'secure']
    ):
        return "⚠ Phishing Website", 88.0

    # Case 4: IP alone
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', url):
        return "⚠ Phishing Website", 85.0

    # ML Prediction
    risk = round(phishing_prob * 100, 2)

    if prediction == -1:
        result = "⚠ Phishing Website"
    else:
        result = "✅ Legitimate Website"

    return result, risk


# ---------------- HOME PAGE ----------------
@app.route('/')
def home():
    return render_template("index.html")


# ---------------- URL CHECK + REDIRECT ----------------
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Accept JSON or form payloads
        if request.is_json:
            data = request.get_json(silent=True) or {}
            url = str(data.get('url', '')).strip()
        else:
            url = request.form.get('url', '').strip()

        if not url:
            if request.is_json:
                return jsonify({"prediction": "❌ No URL provided", "risk": 0}), 400
            return render_template(
                "index.html",
                prediction="❌ No URL provided",
                risk=0
            )

        # Automatically add https if scheme missing
        if not url.startswith("http"):
            url = "https://" + url

        result, risk = check_phishing(url)

        # ---------------- LEGITIMATE WEBSITE ----------------
        if "Legitimate" in result and risk < 50:
            if request.is_json:
                return jsonify({"action": "redirect", "url": url, "prediction": result, "risk": float(risk)})
            return redirect(url)

        # ---------------- PHISHING WEBSITE ----------------
        if request.is_json:
            return jsonify({"action": "block", "prediction": result, "risk": float(risk)})
        return render_template(
            "index.html",
            prediction=result,
            risk=risk,
            blocked_url=url
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        if request.is_json:
            return jsonify({"prediction": "Error: internal server error", "detail": str(e)}), 500
        return render_template("index.html", prediction="Error: internal server error", risk=0)


# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)