import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import xgboost as xgb

# ------------------------
# 1️⃣ Load dataset
# ------------------------
df = pd.read_csv(r"C:\phishing-detector\backend\Phishing_Legitimate_full.csv")

# Shuffle
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# ------------------------
# 2️⃣ Prepare features & target
# ------------------------
# Features: all columns except 'id' and 'CLASS_LABEL'
X = df.drop(columns=['id', 'CLASS_LABEL'])
y = df['CLASS_LABEL']  # 1 = phishing, 0 = legitimate

# ------------------------
# 3️⃣ Train-test split
# ------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42)

# ------------------------
# 4️⃣ Train XGBoost
# ------------------------
model = xgb.XGBClassifier(
    n_estimators=500,
    max_depth=6,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric='logloss'
)

model.fit(X_train, y_train)

# ------------------------
# 5️⃣ Evaluate
# ------------------------
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ------------------------
# 6️⃣ Save model
# ------------------------
model.save_model("phishing_model.json")
print("Model saved as phishing_model.json")
