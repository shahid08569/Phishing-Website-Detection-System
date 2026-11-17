# 🛡️ PhishGuard AI - Phishing Website Detection System

An intelligent, machine-learning-powered web application that detects phishing URLs in real time. Built with **FastAPI**, **Scikit-learn**, and a modern web interface.

---

## 📌 Project Overview
Phishing attacks trick users into disclosing sensitive credentials and personal data. This system extracts key structural and lexical features from any given URL and classifies it as either **Legitimate Site** or **Fake / Phishing**.

---

## 🚀 Key Features
- **Real-Time URL Feature Extraction**:
  - URL length & domain length
  - Subdomain counts & presence of hyphens
  - Special character counts (`@`, `?`, `-`, `=`, `_`, `.`)
  - IP address detection in URL
  - Numeric character ratio
  - Suspicious keywords detection (`secure`, `login`, `verify`, `account`, `bank`, `update`, etc.)
- **Machine Learning Pipeline**:
  - Balanced dataset of 4,000+ realistic benign and phishing URLs.
  - Logistic Regression classifier trained on engineered features.
  - Serialized model pipeline stored in `models/phishing_model.joblib`.
- **FastAPI Backend & Interactive UI**:
  - High-performance asynchronous API endpoints (`/api/predict`).
  - Sleek, responsive web UI with immediate verdict feedback (Green for Legit, Red for Fake).

---

## 📂 Project Structure
```text
├── models/
│   ├── feature_columns.json      # Expected feature names
│   ├── model_metadata.json       # Training metadata & parameters
│   └── phishing_model.joblib     # Pre-trained ML model
├── CODE_EXPLANATION_LINE_BY_LINE_ROMAN_URDU.pdf  # Line-by-line documentation
├── SRS Machine Learning Based Phishing Website Detection System.pdf # SRS document
├── index.html                    # Frontend interface
├── main.py                       # FastAPI application & feature extractor
├── requirements.txt              # Project dependencies
├── train.py                      # Model training & evaluation script
├── url_features_extracted1.csv   # Dataset used for training
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/shahid08569/Phishing-Website-Detection-System.git
cd Phishing-Website-Detection-System
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
py main.py
# or
python main.py
```

Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 🧪 Model Training & Retraining
To retrain the model with updated data:
```bash
py train.py
```
This script will:
1. Load `url_features_extracted1.csv`
2. Train a scikit-learn classifier
3. Print classification metrics (Accuracy, Precision, Recall, F1)
4. Save the model pipeline to `models/phishing_model.joblib`

---

## 📋 Requirements
- Python 3.10+
- fastapi
- uvicorn
- scikit-learn
- pandas
- numpy
- joblib
