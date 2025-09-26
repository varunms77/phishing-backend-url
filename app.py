import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)  # Suppress pandas/XGBoost warnings

from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import xgboost as xgb
import os
import sys

app = Flask(__name__)
CORS(app)

# Model path
MODEL_PATH = "phishing_model.json"

# Load model safely
model = xgb.XGBClassifier()
if not os.path.exists(MODEL_PATH):
    print(f"ERROR: Model file '{MODEL_PATH}' not found!")
    sys.exit(1)

try:
    model.load_model(MODEL_PATH)
    print(f"Model '{MODEL_PATH}' loaded successfully.")
except Exception as e:
    print("Failed to load model:", e)
    sys.exit(1)

# Feature columns (must match training)
FEATURE_COLUMNS = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname',
    'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
    'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks',
    'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms',
    'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction',
    'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch',
    'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow',
    'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
    'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT',
    'PctExtResourceUrlsRT', 'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT',
    'PctExtNullSelfRedirectHyperlinksRT'
]

def extract_features_from_request(data):
    try:
        df = pd.DataFrame([data])
        df = df[FEATURE_COLUMNS]  # Keep only required features
        return df
    except KeyError as e:
        print("Missing features in request:", e)
        return None

@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.json
    features = extract_features_from_request(data)
    if features is None:
        return jsonify({"error": "Missing features"}), 400

    pred = model.predict(features)[0]
    result = "Phishing" if pred == 1 else "Legitimate"

    return jsonify({
        "result": result,
        "reason": "Model analysis",
        "severity": "High risk" if result == "Phishing" else "Low risk"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render provides PORT
    print(f"Starting Flask app on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
