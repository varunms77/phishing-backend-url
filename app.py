from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import xgboost as xgb
import re

app = Flask(__name__)
CORS(app)

# ------------------------
# Load trained model
# ------------------------
model = xgb.XGBClassifier()
model.load_model("phishing_model.json")

# ------------------------
# Feature computation from raw URL
# ------------------------
def compute_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    
    features = {
        "NumDots": url.count("."),
        "SubdomainLevel": hostname.count(".") - 1 if hostname else 0,
        "PathLevel": path.count("/") if path else 0,
        "UrlLength": len(url),
        "NumDash": url.count("-"),
        "NumDashInHostname": hostname.count("-"),
        "AtSymbol": int("@" in url),
        "TildeSymbol": int("~" in url),
        "NumUnderscore": url.count("_"),
        "NumPercent": url.count("%"),
        "NumQueryComponents": url.count("?"),
        "NumAmpersand": url.count("&"),
        "NumHash": url.count("#"),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": int(not url.startswith("https")),
        "RandomString": 0,  # optional advanced computation
        "IpAddress": int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname))),
        "DomainInSubdomains": 0,
        "DomainInPaths": 0,
        "HttpsInHostname": int("https" in hostname),
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(parsed.query),
        "DoubleSlashInPath": int("//" in path),
        "NumSensitiveWords": int(any(word in url.lower() for word in ["login","secure","bank","update"])),
        "EmbeddedBrandName": 0,
        "PctExtHyperlinks": 0,
        "PctExtResourceUrls": 0,
        "ExtFavicon": 0,
        "InsecureForms": 0,
        "RelativeFormAction": 0,
        "ExtFormAction": 0,
        "AbnormalFormAction": 0,
        "PctNullSelfRedirectHyperlinks": 0,
        "FrequentDomainNameMismatch": 0,
        "FakeLinkInStatusBar": 0,
        "RightClickDisabled": 0,
        "PopUpWindow": 0,
        "SubmitInfoToEmail": 0,
        "IframeOrFrame": 0,
        "MissingTitle": 0,
        "ImagesOnlyInForm": 0,
        "SubdomainLevelRT": 0,
        "UrlLengthRT": 0,
        "PctExtResourceUrlsRT": 0,
        "AbnormalExtFormActionR": 0,
        "ExtMetaScriptLinkRT": 0,
        "PctExtNullSelfRedirectHyperlinksRT": 0
    }
    
    return pd.DataFrame([features])

# ------------------------
# Prediction endpoint
# ------------------------
@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    X = compute_features(url)
    
    pred_prob = model.predict_proba(X)[0][1]
    pred_label = "Phishing" if pred_prob >= 0.5 else "Legitimate"
    reason = "Suspicious patterns detected" if pred_label=="Phishing" else "No suspicious patterns"
    severity = "High risk" if pred_label=="Phishing" else "Low risk"

    return jsonify({
        "result": pred_label,
        "reason": reason,
        "severity": severity,
        "confidence": float(pred_prob)
    })

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
