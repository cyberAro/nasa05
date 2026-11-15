# Aswanna.ai account service

The local account API uses FastAPI and SQLite. Passwords are stored as salted scrypt hashes; successful sign-in sets a random, HttpOnly session cookie. The database is created at `data/auth.sqlite3` and is ignored by Git.

## Run locally on Windows

Install the API dependencies from the repository root:

```powershell
.\venv\Scripts\python.exe -m pip install -r api\requirements.txt
```

In one terminal, start the account API:

```powershell
.\venv\Scripts\python.exe -m uvicorn --app-dir api main:app --host 127.0.0.1 --port 8000
```

In another terminal, start the frontend:

```powershell
Set-Location web
npm run dev
```

Vite proxies `/api` requests to the local API. The landing page supports account creation with a name, phone number, and password, and sign-in with a phone number and password. After authentication, users choose a Farmer or Agricultural Officer role for that session. Farmer sessions are limited to farmer pages; officer sessions can access officer and national planning pages. Passwords must be at least 12 characters. Sri Lankan phone numbers can be entered locally (for example, `0771234567`) or with `+94`.

## Before deployment

This local setup does not verify ownership of phone numbers by SMS. Add phone verification and login rate limiting before using accounts for real-world identity or exposing the API publicly. Production must use HTTPS, set `FIELD_SHIFT_COOKIE_SECURE=1`, configure `FIELD_SHIFT_ALLOWED_ORIGINS` for the deployed site, and keep the API behind a same-origin HTTPS proxy.
