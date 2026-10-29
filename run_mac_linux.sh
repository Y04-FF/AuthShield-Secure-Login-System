#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required."; exit 1; }
[ -d .venv ] || python3 -m venv .venv
if [ ! -f .env ]; then printf "SECRET_KEY=%s
DATABASE_URL=sqlite:///secure_login.db
COOKIE_SECURE=false
" "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env; fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
