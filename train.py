import pandas as pd
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit
from pathlib import Path

csv_file = Path(__file__).parent / "url_features_extracted1.csv"
df = pd.read_csv(csv_file)

df["target"] = 1 - df["ClassLabel"]

features = [
    "url_length", "has_ip_address", "dot_count", "https_flag", "url_entropy",
    "subdomain_count", "query_param_count", "tld_length", "path_length",
    "has_hyphen_in_domain", "number_of_digits", "tld_popularity",
    "suspicious_file_extension", "domain_name_length", "percentage_numeric_chars"
]

X = df[features]
y = df["target"]

gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups=df["host"]))

X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("model", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42))
])

pipeline.fit(X_train, y_train)

score = pipeline.score(X_test, y_test)
print(f"Accuracy: {score * 100:.2f}%")

model_path = Path(__file__).parent / "models" / "phishing_model.joblib"
model_path.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(pipeline, model_path)
print("Saved to:", model_path)
