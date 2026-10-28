# Saviour AI — Python Flask Backend

This is a beginner-friendly backend starter for the existing Saviour AI URL Intelligence frontend.

## Features
- `POST /api/scan` — heuristically analyzes and saves a URL
- `GET /api/history` — returns saved scans
- `GET /api/stats` — returns actual database counts
- `DELETE /api/history` — clears saved scan history
- `GET /api/health` — health check
- SQLite database (`saviour_ai.db`) is created automatically when you run the app.

## 1. Install Python
Install Python 3.10+ and make sure `python` works in your terminal.

## 2. Open this folder in VS Code
Open a terminal in the folder containing `app.py`.

## 3. Create a virtual environment (recommended)
Windows:
```powershell
python -m venv .venv
.venv\Scripts\activate
```

If PowerShell blocks activation, you can use Command Prompt:
```bat
.venv\Scripts\activate.bat
```

## 4. Install dependencies
```bash
python -m pip install -r requirements.txt
```

## 5. Start the backend
```bash
python app.py
```
It runs at `http://127.0.0.1:5000`.

## 6. Test the API
Open `http://127.0.0.1:5000/api/health` in your browser.
To scan a URL, send a POST request to `http://127.0.0.1:5000/api/scan` with JSON:
```json
{"url": "https://example.com"}
```
Use Postman, Thunder Client, or the browser console.

## Connect your frontend
The frontend needs JavaScript `fetch()` calls to these API endpoints. Example:

```javascript
const API_BASE = "http://127.0.0.1:5000";

async function scanUrlWithBackend(url) {
  const response = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });

  const data = await response.json();
  if (!response.ok || !data.success) {
    throw new Error(data.error || "Scan failed");
  }
  return data.scan;
}

async function getScanHistory() {
  const response = await fetch(`${API_BASE}/api/history`);
  const data = await response.json();
  if (!response.ok || !data.success) {
    throw new Error(data.error || "Could not load history");
  }
  return data.scans;
}

async function getDashboardStats() {
  const response = await fetch(`${API_BASE}/api/stats`);
  const data = await response.json();
  if (!response.ok || !data.success) {
    throw new Error(data.error || "Could not load statistics");
  }
  return data;
}
```

**Important:** This backend is a heuristic prototype. It does not contact a live threat-intelligence service and cannot guarantee that a URL is safe. A Low result means only that these configured rules did not find many warning signs.

For a production deployment, configure CORS to allow only your frontend origin, disable debug mode, add rate limits and input limits, and use a real threat-intelligence source if required.
