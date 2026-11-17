# PhishGuard AI — Line-by-Line Code Explanation Manual (Roman Urdu)
**Project Title:** Machine Learning Based Phishing Website Detection System Using Logistic Regression  
**Technology Stack:** Python, FastAPI, Scikit-Learn, Pandas, HTML5, CSS3, JavaScript  
**Manual Language:** Roman Urdu (Viva / Defense Ready)

---

## 1. Project Ka Overview (Code Ka Asal Kaam Kya Hai?)

Hamare project mein sirf **3 main files** hain jinpar poora system chal raha hai:
1. **`main.py`:** Backend Web Server jo user se URL leta hai, uske 15 features extract karta hai, aur model se pooch kar **"Legit Site"** ya **"Fake"** return karta hai.
2. **`train.py`:** Machine learning training script jo CSV file parh kar Logistic Regression model ko train karta hai aur `phishing_model.joblib` file save karta hai.
3. **`index.html`:** Single-page frontend (HTML + CSS + JavaScript) jismein search bar hai aur result show hota hai.

---

## 2. File 1: `main.py` Ka Line-by-Line Postmortem

### Hissa A: Libraries Import Karna
```python
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
```
- `import math`: Ganit / mathematics ke operations (jaise `math.log2` Shannon Entropy ke liye) use karne ke liye.
- `import re`: Regular Expression (Regex) ke liye, taake check kar sakein ke URL mein direct IP address (e.g. 192.168.1.1) mojood hai ya nahi.
- `from collections import Counter`: URL ke characters ko count karne ke liye (entropy formula mein har character ki tadad chahiye hoti hai).
- `from urllib.parse import urlparse`: Python ka built-in tool jo URL ko tod kar scheme (http), domain (netloc), path aur query alag alag kar deta hai.
- `from pathlib import Path`: Computer ke folder aur files ke paths ko sahi handle karne ke liye.
- `import joblib`: Save kiye gaye machine learning model (`.joblib`) ko memory mein load karne ke liye.
- `import pandas as pd`: Features ko DataFrame (row/column table) mein convert karne ke liye jo model input leta hai.
- `from fastapi import FastAPI`: Tez tareen aur modern web framework API banane ke liye.
- `from fastapi.responses import FileResponse`: Browser ko `index.html` web page send karne ke liye.
- `from pydantic import BaseModel`: API par aane wali request (URL) ka data type validate karne ke liye.
- `import uvicorn`: FastAPI ke server ko run aur host karne wala engine.

---

### Hissa B: FastAPI Initialize Aur Model Load
```python
app = FastAPI(title="PhishGuard AI")

MODEL_PATH = Path(__file__).parent / "models" / "phishing_model.joblib"
model = joblib.load(MODEL_PATH)
```
- `app = FastAPI(...)`: FastAPI ka server object banaya jiska naam "PhishGuard AI" rakha.
- `MODEL_PATH = ...`: Hamari trained model file `models/phishing_model.joblib` ka path set kiya.
- `model = joblib.load(MODEL_PATH)`: Model ko hard drive se utha kar RAM (memory) mein load kar liya taake scan karte waqt foran answer de sake (< 2 milliseconds).

---

### Hissa C: Shannon Entropy Function
```python
def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
```
- `if not text: return 0.0`: Agar string khali ho to entropy 0 return karo.
- `length = len(text)`: URL ke kul characters ki ginti.
- `counts = Counter(text)`: Har character kitni baar aaya (e.g. 'a' kitni baar, '1' kitni baar).
- `return -sum(...)`: Mathematical Shannon Entropy formula: $$H(X) = -\sum P(x) \log_2 P(x)$$. Phishing links mein random tokens aur hashes hote hain is liye unki entropy high aati hai.

---

### Hissa D: Feature Extraction Function (Tamam 15 Features)
```python
def extract_features(raw_url: str) -> dict:
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain = parsed.netloc
    parts = domain.split(".")
```
- `url = raw_url.strip()`: Aage peeche ke fazool spaces khatam kiye.
- `if not url.startswith...`: Agar user ne `http://` ya `https://` nahi likha to default `http://` laga diya taake parser fail na ho.
- `parsed = urlparse(url)`: URL ko alag alag hisson mein split kiya.
- `hostname / domain`: Website ka main address (jaise `www.google.com`).
- `parts = domain.split(".")`: Domain ko dots par divide kiya (jaise `['www', 'google', 'com']`).

#### 15 Features Ki Detail:
1. `url_length = len(url)`: Poore URL ki total character count. Phishing URLs lambi hoti hain.
2. `is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname)`  
   `has_ip_address = 1 if is_ip else 0`: Check karta hai domain ki jagah direct IP address to nahi.
3. `dot_count = url.count(".")`: URL mein kitne dots mojood hain.
4. `https_flag = 1 if parsed.scheme.lower() == "https" else 0`: HTTPS hai to 1, HTTP hai to 0.
5. `url_entropy = round(calculate_entropy(url), 6)`: Randomness measure.
6. `subdomain_count = len(parts) - 2`: Subdomains ki tadad.
7. `query_param_count = 1 if not parsed.query else len(parsed.query.split("&"))`: `?` aur `&` parameters.
8. `tld_length = len(parts[-1]) if parts else 0`: Top-Level Domain length.
9. `path_length = len(parsed.path)`: Domain ke baad folder/page path ki length.
10. `has_hyphen_in_domain = 1 if "-" in domain else 0`: Domain mein `-` hona.
11. `number_of_digits = sum(1 for c in url if c.isdigit())`: Total numbers/digits ki tadad.
12. `tld_popularity = 1 if tld in ["com", "org", "net", "edu", "gov"] else 0`: Reputable TLDs.
13. `suspicious_file_extension = 1 if any(...) else 0`: `.exe`, `.zip`, `.apk` check.
14. `domain_name_length = len(parts[-2]) if len(parts) >= 2 else 0`: Brand name length.
15. `pct_numeric = (100.0 * number_of_digits / url_length)`: Digits ki percentage.

---

### Hissa E: Web Routes & Prediction API
```python
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
        return {"result": "Fake"}
    else:
        return {"result": "Legit Site"}
```
- `@app.get("/")`: Browser mein `http://127.0.0.1:8000` par `index.html` load karta hai.
- `@app.post("/api/predict")`: URL leta hai, 15 features extract karta hai, model se predict karwata hai:
  - Agar **1** ho $\rightarrow$ `{"result": "Fake"}`
  - Agar **0** ho $\rightarrow$ `{"result": "Legit Site"}`

---

### Hissa F: Server Run Karna
```python
if __name__ == "__main__":
    print("PhishGuard AI Server Started Successfully!")
    uvicorn.run(app, host="127.0.0.1", port=8000)
```
- Terminal mein `python main.py` likhne par Uvicorn server ko local port 8000 par live chala deta hai.

---

## 3. File 2: <code>train.py</code> Ka Line-by-Line Postmortem

```python
csv_file = Path(__file__).parent / "url_features_extracted1.csv"
df = pd.read_csv(csv_file)

df["target"] = 1 - df["ClassLabel"]
```
- **Line `1 - df["ClassLabel"]`**: Original dataset mein `0 = Phishing` tha aur `1 = Legit` tha. Data Science conventions mein target (positive class) hamesha 1 hona chahiye us event ke liye jisko detect karna ho (Phishing = 1). Is liye humne 0 aur 1 ko invert kiya:
  - 1 = Phishing (Fake)
  - 0 = Legitimate (Legit Site)

```python
gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups=df["host"]))
```
- **GroupShuffleSplit (Data Leakage Solution)**: Agar aam random split use karein to ek hi domain ke do pages train aur test dono mein chale jate hain aur model domain ko memorize kar leta hai. Host-based group split se poora domain ya train mein rehta hai ya test mein.

```python
pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("model", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42))
])

pipeline.fit(X_train, y_train)
score = pipeline.score(X_test, y_test)
print(f"Accuracy: {score * 100:.2f}%")
```
- `StandardScaler`: Sab features ko normal scale par le aata hai.
- `class_weight="balanced"`: Phishing detection mein False Negative minimize karta hai taake koi fraud link miss na ho.
- `pipeline.fit`: Training complete karta hai.
- `joblib.dump`: Model ko `models/phishing_model.joblib` mein save kar deta hai.

---

## 4. File 3: <code>index.html</code> Ka Line-by-Line Postmortem

### JavaScript Scan Function:
```javascript
async function scanURL(e) {
    e.preventDefault();
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;

    btn.disabled = true;
    btn.textContent = 'Checking...';

    const response = await fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    if (data.label === 1) {
        verdictText.textContent = 'Fake';
        verdictText.className = 'verdict verdict-fake';
    } else {
        verdictText.textContent = 'Legit Site';
        verdictText.className = 'verdict verdict-legit';
    }

    resultBox.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Check Link';
}
```
1. `fetch('/api/predict')`: Backend ko asynchronous POST request bhejta hai.
2. Agar `label === 1` ho to text **"Fake"** (Red box) dikhata hai.
3. Agar `label === 0` ho to text **"Legit Site"** (Green box) dikhata hai.

---

## 5. Top 10 Viva / Defense Questions (Teachers Ke Sawaalat)

1. **Q: Aapka model URL ko scan karne ke liye internet par open kyun nahi karta?**  
   *Ans:* Sir, live request se malicious scripts run hone ka risk hota hai, aur network request 3-5 seconds leti hai jabke offline lexical extraction microseconds mein complete ho jati hai.
2. **Q: Shannon Entropy feature ka kya faida hai?**  
   *Ans:* Shannon Entropy URL text ki randomness aur disorder ko measure karti hai. Phishing links mein random tokens hote hain jis se unki entropy normal websites se wazeh tor par zyada hoti hai.
3. **Q: Machine Learning mein Data Leakage kya hota hai aur aapne kaise roka?**  
   *Ans:* Agar ek hi domain ke URLs train aur test dono mein chale jayein to model memorize kar leta hai. Humne `GroupShuffleSplit(groups=df["host"])` lagaya taake poora domain ya train mein rahe ya test mein.
4. **Q: Dataset ke original labels mein `1 - ClassLabel` kyun kiya?**  
   *Ans:* Original CSV mein 0 Phishing aur 1 Legitimate tha. Data Science convention ke mutabiq positive class (target) hamesha 1 hoti hai. Is liye humne 1 = Phishing banaya.
5. **Q: StandardScaler Pipeline ke andar lagane ka kya faida hai?**  
   *Ans:* URL length ki value 50-100 tak hoti hai jabke IP address ya HTTPS flag 0 ya 1 hote hain. StandardScaler sab features ko 0 mean aur unit variance par normal scale par le aata hai.
6. **Q: Agar user URL ke shuru mein `http://` na likhe to kya code crash karega?**  
   *Ans:* Nahi sir, `extract_features` check karta hai: agar scheme missing ho to automatically `http://` prepend kar deta hai taake parser crash na ho.
7. **Q: Logistic Regression hi kyun use kiya, Neural Network kyun nahi?**  
   *Ans:* Logistic Regression fast hai, low memory leti hai, aur sab se ahem baat ye ke ye black-box nahi hai — iske 15 weights 100% explainable hain jo security mein zaroori hai.
8. **Q: Frontend aur Backend aapas mein kaise baat karte hain?**  
   *Ans:* JavaScript ka `fetch()` method asynchronous POST request ke zariye JSON payload `{"url": "..."}` backend ke `/api/predict` endpoint par bhejta hai aur result render karta hai.
9. **Q: `joblib` ka kya role hai?**  
   *Ans:* `train.py` mein model train hone ke baad `joblib.dump()` freeze karta hai, aur `main.py` mein `joblib.load()` reload karta hai taake bar bar train na karna pade.
10. **Q: Kya is project ko chalane ke liye database ki zaroorat hai?**  
    *Ans:* Nahi sir, hamara architecture stateless aur real-time hai. Model seedha memory mein chal raha hai is liye database ke baghair ultra-fast prediction karta hai.
