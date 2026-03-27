import pandas as pd
import joblib

# Load model
model = joblib.load("models/rf_portscan_model.pkl")

# Load dataset
df = pd.read_csv("data/portscan_dataset.csv")

# Feature selection
X = df[["port", "protocol", "service"]].copy()

# Encode categorical features
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
for col in ["protocol", "service"]:
    X[col] = le.fit_transform(X[col])

# Predict risk
df["predicted_risk"] = model.predict(X)

# Save results
df.to_csv("data/final_risk_report.csv", index=False)

print("[+] Final risk report generated: data/final_risk_report.csv")
print(df[["ip", "port", "service", "cvss", "predicted_risk"]])
