# Secure Login System — Complete Working Project

A Flask login web app for a student project. It includes account registration and login, bcrypt password hashing, server-side input checks, SQLite with SQLAlchemy ORM, signed session cookies, logout, CSRF protection, rate limiting, security headers, and optional TOTP 2FA with an authenticator application.

> **Educational project, not a production-certified authentication service.** Before public deployment, use HTTPS, set `COOKIE_SECURE=true`, configure a persistent limiter backend such as Redis, review logging/monitoring and backups, and perform a security audit. Never commit `.env`, live credentials, database files, or real user data to GitHub.

## Windows quick start
1. Install Python 3.10+ from https://www.python.org/downloads/ and check **Add Python to PATH** during setup.
2. Extract this ZIP.
3. Open the extracted `Secure_Login_System_Project` folder.
4. Double-click `run_windows.bat`.
5. The script creates a virtual environment and random local `.env` secret if needed, installs libraries, then starts the server.
6. Open http://127.0.0.1:5000 in Chrome.
7. Click **Create account**, then register with a password at least 12 characters long containing letters and numbers. Log in afterward.

First setup requires internet access to install packages. Keep the command window open while using the website. Press Ctrl+C to stop the local server.

## Run in VS Code
Open VS Code → File → Open Folder → select `Secure_Login_System_Project`. Then double-click `run_windows.bat`, or open a terminal and run `./run_windows.bat` in Command Prompt. Open http://127.0.0.1:5000.

## Optional two-factor authentication
1. Register and log in.
2. On Dashboard choose **Set up 2FA**.
3. Install an authenticator app on your phone, scan the QR code, and enter the current 6-digit code.
4. Log out and log in again; after the password step, enter the authenticator code.
5. To disable 2FA, provide your account password and current code on the dashboard.

Keep the setup key private. This teaching project does not implement recovery codes, email verification, password resets, or lost-authenticator recovery.

## Run tests
After setup:
```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Project files
- `app.py` — Flask routes, account model, password hashing, sessions, 2FA
- `templates/` — web pages
- `static/style.css` — responsive styling
- `requirements.txt` — required libraries
- `run_windows.bat` — Windows automatic setup and startup
- `run_mac_linux.sh` — macOS/Linux setup script
- `tests/test_app.py` — basic registration/login tests

## Security design and limitations
- Passwords are stored as salted bcrypt hashes (12 rounds), never plain text.
- SQLAlchemy ORM is used instead of building SQL queries by concatenating user input.
- Flask-WTF CSRF tokens protect forms that change server state.
- Server-side validation checks username, email, password length/composition, and confirmation.
- Rate limits protect login and select sensitive routes; the default in-memory store resets when the process restarts.
- Sessions are signed by Flask, HttpOnly, SameSite=Lax, and limited to 30 minutes. Logout clears the browser session.
- TOTP-based two-factor authentication is optional.
- `COOKIE_SECURE=false` is for local HTTP only. Set to true only behind HTTPS.
- App binds to `127.0.0.1`; this is a local development setup and should not be exposed directly to the public internet.
