import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import xgboost as xgb

app = Flask(__name__)
CORS(app)

# Load trained model as XGBClassifier
MODEL_PATH = "phishing_model.json"
model = xgb.XGBClassifier()
model.load_model(MODEL_PATH)

# ✅ Full feature extraction placeholder (replace with your 49-feature logic)
def extract_features(url: str):
    # Must return a list or dict of 49 features exactly as used in training
    # Here, a dummy example:
    features = [0] * 49  
    # Example: features[0] = len(url), features[1] = url.count(".") etc.
    return features

# ✅ Prediction function
def make_prediction(url: str):
    try:
        features = extract_features(url)
        df = pd.DataFrame([features])
        proba = model.predict_proba(df)[0][1]  # probability of phishing
        prediction = "Phishing" if proba > 0.5 else "Legitimate"
        reason = "Suspicious URL patterns detected" if prediction == "Phishing" else "No obvious phishing patterns"

        return {"result": prediction, "probability": float(proba), "reason": reason}
    except Exception as e:
        return {"error": str(e)}

# ✅ API endpoints
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url", "")
    return jsonify(make_prediction(url))

@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url", "")
    return jsonify(make_prediction(url))

if __name__ == "__main__":
    app.run(debug=True)
