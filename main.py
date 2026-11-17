import math
import re
from collections import Counter
from urllib.parse import urlparse
from pathlib import Path
import joblib
import pandas as pd
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="PhishGuard AI")

MODEL_PATH = Path(__file__).parent / "models" / "phishing_model.joblib"
model = joblib.load(MODEL_PATH)


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(raw_url: str) -> dict:
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain = parsed.netloc
    parts = domain.split(".")

    url_length = len(url)
    is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)
    has_ip_address = 1 if is_ip else 0
    dot_count = url.count(".")
    https_flag = 1 if parsed.scheme.lower() == "https" else 0
    url_entropy = round(calculate_entropy(url), 6)
    subdomain_count = len(parts) - 2
    query_param_count = 1 if not parsed.query else len(parsed.query.split("&"))
    tld_length = len(parts[-1]) if parts else 0
    path_length = len(parsed.path)
    has_hyphen_in_domain = 1 if "-" in domain else 0
    number_of_digits = sum(1 for c in url if c.isdigit())
    tld = parts[-1].split(":")[0].lower() if parts else ""
    tld_popularity = 1 if tld in ["com", "org", "net", "edu", "gov"] else 0
    suspicious_exts = [".exe", ".zip", ".apk", ".js", ".bin"]
    suspicious_file_extension = 1 if any(parsed.path.lower().endswith(ext) for ext in suspicious_exts) else 0
    domain_name_length = len(parts[-2]) if len(parts) >= 2 else 0
    pct_numeric = (100.0 * number_of_digits / url_length) if url_length > 0 else 0.0

    return {
        "url_length": url_length,
        "has_ip_address": has_ip_address,
        "dot_count": dot_count,
        "https_flag": https_flag,
        "url_entropy": url_entropy,
        "subdomain_count": subdomain_count,
        "query_param_count": query_param_count,
        "tld_length": tld_length,
        "path_length": path_length,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "number_of_digits": number_of_digits,
        "tld_popularity": tld_popularity,
        "suspicious_file_extension": suspicious_file_extension,
        "domain_name_length": domain_name_length,
        "percentage_numeric_chars": round(pct_numeric, 6)
    }


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return FileResponse(Path(__file__).parent / "index.html")


@app.post("/api/predict")
def predict(req: URLRequest):
    features = extract_features(req.url)
    input_data = pd.DataFrame([features])
    prediction = int(model.predict(input_data)[0])
    
    if prediction == 1:
        return {"label": 1, "result": "Fake"}
    else:
        return {"label": 0, "result": "Legit Site"}


if __name__ == "__main__":
    print("\n=======================================================")
    print("  PhishGuard AI Server Started Successfully!")
    print("  Open this link in your browser: http://127.0.0.1:8000")
    print("=======================================================\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)
