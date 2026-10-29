@echo off
setlocal
cd /d "%~dp0"
title Secure Login System Setup
echo.
echo ============================================
echo       SECURE LOGIN SYSTEM - STARTUP
echo ============================================
echo.
where py >nul 2>nul
if %errorlevel%==0 (set "PYTHON=py") else (where python >nul 2>nul & if errorlevel 1 (echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/ and tick Add Python to PATH. & pause & exit /b 1) & set "PYTHON=python")
if not exist ".venv\Scripts\python.exe" (%PYTHON% -m venv .venv || goto failed)
if not exist ".env" (.venv\Scripts\python.exe -c "from pathlib import Path; import secrets; Path('.env').write_text('SECRET_KEY='+secrets.token_hex(32)+'\nDATABASE_URL=sqlite:///secure_login.db\nCOOKIE_SECURE=false\n',encoding='utf-8')" || goto failed)
echo Installing required packages. First run needs an internet connection.
.venv\Scripts\python.exe -m pip install --upgrade pip || goto failed
.venv\Scripts\python.exe -m pip install -r requirements.txt || goto failed
echo Starting server. Open http://127.0.0.1:5000 in Chrome.
echo Keep this window open; press Ctrl+C to stop.
.venv\Scripts\python.exe app.py
pause
exit /b 0
:failed
echo Setup failed. Check Python and internet connection.
pause
exit /b 1
