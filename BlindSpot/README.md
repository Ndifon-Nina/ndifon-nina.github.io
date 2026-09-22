# 🛡️ BlindSpot

Find the security problems you didn't know you had.

BlindSpot is a beginner-friendly web security scanner. It checks websites you own or have
permission to test for common security misconfigurations: missing HTTPS, missing security
headers, exposed files (like `.env` or backups), directory listing, unsafe cookies, and
error pages that leak technical details.

## Setup

1. Open a terminal in this folder.
2. Create a virtual environment:
   ```
   python -m venv venv
   ```
3. Activate it:
   - Windows: `venv\Scripts\activate`
   - Mac/Linux: `source venv/bin/activate`
4. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```
5. Run the app:
   ```
   python app.py
   ```
6. Open your browser to: **http://127.0.0.1:8000**

## Try it safely first: the practice lab

Before scanning any real website, you can test BlindSpot against a small, deliberately
vulnerable site that ships with this project — no permission questions, no risk.

In a **second terminal** (leave BlindSpot running in the first):
```
venv\Scripts\activate
python practice_lab.py
```
Then scan `http://127.0.0.1:5055` from BlindSpot's home page. It's intentionally broken in
every way BlindSpot checks for, so you should see a 0/100 score with findings for every
category — a good way to confirm everything is working.

## Making yourself an admin

After registering a normal account in the app:
```
python make_admin.py your_email@example.com
```
Log out and back in — an "Admin" link appears in the navbar.

## What's built

- Home, Dashboard, full scan history, "How It Works", "Security Tips"
- Register / Login / Logout / Forgot password (passwords hashed, never stored in plain text)
- Live scanner checks: HTTPS, security headers, exposed resources, directory listing,
  cookie security (Secure/HttpOnly/SameSite), and error-page leakage
- Exposure checks compare against the real homepage first, to avoid false positives on
  sites that serve the same content for every URL
- Results page with a weighted 0–100 score and plain-language findings
- Admin dashboard: user/scan/finding counts, user list, scan list
- CSRF protection on every form (Flask-WTF)
- Rate limiting (Flask-Limiter): login 10/minute, scans 10/hour, password reset 5/hour
- BlindSpot sends its own security headers on every response — it practices what it checks for
- Dark and light theme toggle (🌙/☀️ button in the navbar), remembered between visits

## Not built yet (next slices)

- Actually emailing the password-reset link (shown on screen for now — swap in Flask-Mail
  or an email API when ready)
- Deployment configuration (HTTPS, `FLASK_DEBUG=false`, a persistent rate-limit storage
  backend instead of in-memory)
- Locking an account after repeated failed logins
