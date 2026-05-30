# 🛡️ Phishing URL Detector

A powerful web app that detects whether a URL is **phishing** or **legitimate** using a multi-layer defense system combining real-time threat intelligence and machine learning.

🔗 **Live Demo:** https://phishingdetector.up.railway.app/

---

## 🚀 How It Works

Every URL goes through **7 security layers** in order:

```
URL Entered
    │
    ▼
1. Whitelist Check ──────── Known safe domain? → ✅ Legitimate
    │
    ▼
2. DNS Resolution ──────── Domain doesn't exist? → ⚠️ Phishing
    │
    ▼
3. PhishTank Database ──── Found in phishing DB? → ⚠️ Phishing
    │
    ▼
4. OpenPhish Feed ──────── Found in live feed? → ⚠️ Phishing
    │
    ▼
5. Suspicious TLD ──────── Using .tk/.xyz/.cyou? → ⚠️ Phishing
    │
    ▼
6. Brand Impersonation ─── Faking paypal/google? → ⚠️ Phishing
    │
    ▼
7. WHOIS Domain Age ────── Domain < 1 year old? → ⚠️ Phishing
    │
    ▼
✅ Legitimate
```

---

## ✨ Features

- **7-layer detection** — whitelist, DNS, PhishTank, OpenPhish, TLD, brand impersonation, WHOIS age
- **Real-time threat feeds** — checks against live PhishTank and OpenPhish databases
- **Brand impersonation detection** — catches fake PayPal, Google, Amazon, Apple sites
- **Suspicious TLD detection** — flags high-risk extensions like `.tk`, `.xyz`, `.cyou`, `.click`
- **Domain age analysis** — new domains (< 1 year) flagged as suspicious
- **Step-by-step results** — shows exactly why a URL was flagged
- **Clean dark UI** — centered, responsive design with color-coded results
- **Deployed on Railway** — live HTTPS URL, auto-deploys on git push

---

## 📁 Project Structure

```
phishing_detector/
├── app.py                  # Flask web server + all detection logic
├── detector.py             # URL feature extractor (for ML model)
├── train_model.py          # ML model training script
├── predict.py              # Command line URL checker
├── dataset.csv             # Training dataset (11,000+ URLs)
├── model.pkl               # Trained Random Forest model
├── feature_names.pkl       # Feature names used by model
├── requirements.txt        # Python dependencies
├── Procfile                # Railway/gunicorn config
├── Dockerfile              # Docker config for Railway
└── templates/
    └── index.html          # Frontend UI
```

---

## 🛠️ Run Locally

### 1. Clone the repo
```bash
git clone https://github.com/ABMohit02/Phishing_Detector.git
cd Phishing_Detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Train the ML model
```bash
python train_model.py
```

### 4. Run the app
```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## 🧪 Test via Command Line

```bash
python predict.py
```

Enter any URL and get an instant prediction without opening the browser.

---

## 📊 ML Model Details

| Property | Value |
|----------|-------|
| Algorithm | Random Forest Classifier |
| Features | 52 URL-based features |
| Training Data | 11,000+ real URLs |
| Accuracy | ~90.55% |
| Label | `legitimate` / `phishing` |

### Features extracted from URL:
- URL length, hostname length
- Count of special characters (`@`, `-`, `.`, `//`, `?`, `=`, `&` etc.)
- HTTPS token, IP address detection
- Subdomain count, prefix/suffix detection
- Suspicious keywords (`login`, `verify`, `bank`, `secure` etc.)
- Word statistics (shortest, longest, average word length)
- Digit ratio, punycode detection
- Shortening service detection

---

## 🔍 Detection Layers Explained

| Layer | Method | What it catches |
|-------|--------|----------------|
| Whitelist | Domain matching | Known safe sites (Google, Microsoft etc.) |
| DNS Check | Socket resolution | Fake/dead domains that don't exist |
| PhishTank | Live API check | Verified phishing URLs in database |
| OpenPhish | Live feed check | Active phishing URLs |
| TLD Check | Extension matching | High-risk domains (.tk, .xyz, .cyou etc.) |
| Brand Check | Keyword matching | Fake PayPal, Google, Amazon pages |
| WHOIS Age | Domain registration | Newly registered suspicious domains |

---

## 🌐 Deployment (Railway)

This app is deployed on **Railway** with automatic deploys on every git push.

### Deploy your own:
1. Fork this repo
2. Go to [railway.app](https://railway.app)
3. New Project → Deploy from GitHub repo
4. Select your fork
5. Done — Railway auto-detects Python and deploys

### Push updates:
```bash
git add .
git commit -m "your message"
git push origin main
```
Railway redeploys automatically.

---

## 📦 Dependencies

```
flask          — Web framework
gunicorn       — Production WSGI server
requests       — HTTP requests for PhishTank/OpenPhish
python-whois   — Domain age lookup
scikit-learn   — Random Forest ML model
pandas         — Data processing
```

---

## ⚠️ Limitations

- WHOIS lookups can be slow (2-5 seconds per URL)
- PhishTank API has rate limits without an API key
- ML model only uses URL features — doesn't visit the page
- Whitelist is manually maintained

---

## 🔮 Future Improvements

- [ ] Add Google Safe Browsing API
- [ ] Add VirusTotal API integration
- [ ] Page content analysis (check for login forms, iframes)
- [ ] Browser extension version
- [ ] API endpoint for bulk URL checking

---

## 👨‍💻 Author

Made by **Mohit Bhardwaj**

- GitHub: [@ABMohit02](https://github.com/ABMohit02)
- Live App: [phishingdetector.up.railway.app](https://phishingdetector.up.railway.app/)

---

## 📄 License

MIT License — free to use, modify and distribute.
