import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
import os

# Load dataset
df = pd.read_csv("data/portscan_dataset.csv")

# ----------------------------
# CVSS → Risk Labeling (FIXED)
# ----------------------------
def cvss_to_risk(score):
    if score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

df["risk"] = df["cvss"].apply(cvss_to_risk)

# ----------------------------
# Feature Selection
# ----------------------------
X = df[["port", "protocol", "service"]].copy()
y = df["risk"]

# Encode categorical features
le = LabelEncoder()
for col in ["protocol", "service"]:
    X.loc[:, col] = le.fit_transform(X[col])

# ----------------------------
# Train/Test Split
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# ----------------------------
# Train Model
# ----------------------------
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# ----------------------------
# Evaluation
# ----------------------------
y_pred = model.predict(X_test)

print("\n[+] Classification Report\n")
print(
    classification_report(
        y_test,
        y_pred,
        labels=["HIGH", "MEDIUM", "LOW"]
    )
)

# ----------------------------
# Save Model
# ----------------------------
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/rf_portscan_model.pkl")

print("\n[+] Model saved: models/rf_portscan_model.pkl")
