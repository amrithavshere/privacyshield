# PrivacyShield

PrivacyShield is an AI + ML powered web privacy risk checker.
It combines (1) browser evidence (cookies, storage, consent banner signals, HTTPS) and (2) privacy policy understanding to produce an explainable risk score with reasons and recommendations.

## Project Structure
- `backend/` — Django + DRF API + scoring + AI/ML pipeline
- `dashboard/` — React (Vite) dashboard for scan history and reports
- `extension/` — Manifest V3 browser extension (Chrome/Edge)

## Prerequisites
- Python (recommended: 3.10+)
- Node.js (recommended: 18+) + npm
- Chrome or Edge (Developer Mode enabled for loading the extension)

---

# Backend Setup (Django + DRF)

## 1) Create venv + install dependencies
```bash
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 2) Migrate DB
```bash
.\.venv\Scripts\python.exe manage.py migrate
```

## 3) Run backend server
### Command Prompt (single line)
```bat
set DJANGO_SECRET_KEY=your-secret-key-here && .\.venv\Scripts\python.exe manage.py runserver
```

### PowerShell (single line)
```powershell
$env:DJANGO_SECRET_KEY="your-secret-key-here"; .\.venv\Scripts\python.exe manage.py runserver
```

Backend runs at:
- `http://127.0.0.1:8000/api/...`

> Note: `http://127.0.0.1:8000/` returns 404 by design (API-only app). Use `/api/scans` to verify it is running.

## Run backend tests (optional)
```bash
cd backend
.\.venv\Scripts\python.exe manage.py test
```

---

# Dashboard Setup (React + Vite)

## 1) Install and run
```bash
cd dashboard
npm install
npm run dev
```

If PowerShell blocks scripts, use:
```bat
npm.cmd run dev
```

Dashboard runs at:
- `http://localhost:5173`

## API base URL
By default the dashboard uses:
- `http://127.0.0.1:8000`

To override it, create:
- `dashboard/.env`

Example:
```env
VITE_API_BASE=http://127.0.0.1:8000
```

> Do not commit `.env` files. Use `.env.example` with placeholders if needed.

---

# Extension Setup (Chrome / Edge)

## Install
1. Open `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder
5. If you edit extension files later, click **Reload** on the extension card

## Demo Flow (1 minute)
1. Start backend (`backend/` → runserver)
2. Open a supported site in a tab (examples below)
3. Click the **PrivacyShield** extension icon
4. Click **Analyze Current Site**
5. Popup shows score, severity, top reasons, cookie risk counts, and consent banner info

### Recommended safe demo sites
- `https://about.gitlab.com`
- `https://www.mozilla.org`
- `https://foundation.wikimedia.org`

---

# Key API Endpoints

- `POST /api/scans/ingest`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `DELETE /api/scans/{id}`
- `POST /api/policies/fetch`
- `POST /api/policies/analyze`
- `GET /api/preferences?domain=<domain>`
- `POST /api/preferences`

---

# Preferences (Balanced / Strict / Custom)

- **Balanced**: baseline warnings and recommendations
- **Strict**: stronger warnings + stricter guidance (may add extra penalties in some consent cases)
- **Custom**: disable specific warning categories (system still returns minimal safe advice as fallback)

Example update:
```bash
curl -X POST http://127.0.0.1:8000/api/preferences \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "about.gitlab.com",
    "mode": "custom",
    "settings": {
      "warn_trackers": true,
      "warn_ads_profiling": false,
      "warn_retention_unclear": true,
      "warn_cookie_flags": false
    }
  }'
```

---

# AI Configuration

By default, PrivacyShield uses a deterministic **Mock AI Provider** (no API key needed).

To use OpenAI provider:
- `PRIVACYSHIELD_AI_PROVIDER=openai`
- `OPENAI_API_KEY=your-api-key-here`

Restart backend after setting env vars.

---

# Machine Learning Classifier Add-On

PrivacyShield includes an optional TF-IDF + Logistic Regression classifier that labels policy paragraphs and returns short snippet predictions.

## Train the model (run once)
```bash
cd backend
.\.venv\Scripts\python.exe manage.py train_policy_ml
```

If the dashboard shows **“ML model not trained yet”**:
1. Train the model (command above)
2. Restart backend
3. Re-analyze a scan (dashboard Re-analyze button or POST `/api/policies/analyze`)

---

# Database Backfill (optional)

If you enabled persistence fields (reasons/recommendations) after older scans existed, run a backfill to re-analyze and populate them.

From project root:
```bat
.\backend\.venv\Scripts\python.exe backfill_reasons.py
```

---

# Admin (optional)
`/admin` requires a superuser. If you want admin access:
```bash
cd backend
.\.venv\Scripts\python.exe manage.py createsuperuser
```

---

# Common Troubleshooting

- **Backend root 404**: Normal. Use `/api/scans`.
- **PowerShell script blocked for npm**: use `npm.cmd run dev` or run in Command Prompt.
- **CORS errors**: ensure backend CORS is configured for `http://localhost:5173`.
- **ML not showing**: train model, restart backend, re-analyze scan.
