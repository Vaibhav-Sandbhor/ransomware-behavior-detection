import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# Load dataset
df = pd.read_csv("data/portscan_scored.csv")

# Features (convert categorical to numeric)
X = df[["port", "protocol", "service", "cvss"]]

# Encode categorical columns
for col in ["protocol", "service"]:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col])

# Target
y = df["risk"]
y = LabelEncoder().fit_transform(y)  # HIGH=0, MEDIUM=1, LOW=2

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train Random Forest
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Predictions
y_pred = clf.predict(X_test)

# Evaluation
print("[+] Classification Report")
print(classification_report(y_test, y_pred, target_names=["HIGH","MEDIUM","LOW"]))
print("[+] Confusion Matrix")
print(confusion_matrix(y_test, y_pred))

# Save model
import joblib
joblib.dump(clf, "scripts/rf_portscan_model.pkl")
print("[+] Model saved: scripts/rf_portscan_model.pkl")
