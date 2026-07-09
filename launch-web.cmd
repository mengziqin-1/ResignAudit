@echo off
setlocal
cd /d "%~dp0"

echo [ResignAudit] Checking Python dependencies...
python -c "import flask, reportlab, docx, pandas, fitz; print('dependencies ok')" || (
  echo.
  echo [ResignAudit] Missing dependencies. Please run:
  echo pip install -r requirements.txt
  pause
  exit /b 1
)

echo.
echo [ResignAudit] Starting local web app...
echo [ResignAudit] URL: http://127.0.0.1:5000
echo [ResignAudit] Keep this window open while using the system.
echo.

start "" "http://127.0.0.1:5000"
python api.py

pause
