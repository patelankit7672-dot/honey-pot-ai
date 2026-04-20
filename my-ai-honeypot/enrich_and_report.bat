@echo off
title HONEY.AI — Enrich, Analyze & Report
color 0A

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║   🍯  HONEY.AI — Intelligence Pipeline Runner           ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

:: Activate venv if present
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

echo  [1/3] Enriching logs with Geo-IP data...
python enrich_data.py
if %errorlevel% neq 0 (
    echo  [!] enrich_data.py failed. Continuing...
)
echo.

echo  [2/3] Running threat intelligence analysis...
python analyze_attacks.py
if %errorlevel% neq 0 (
    echo  [!] analyze_attacks.py failed. Continuing...
)
echo.

echo  [3/3] Sending daily email report...
python daily_report.py
if %errorlevel% neq 0 (
    echo  [!] daily_report.py failed. Check SMTP_EMAIL/SMTP_PASSWORD in .env
)

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║   ✅  Intelligence pipeline complete!                   ║
echo  ║   📄  Check: enriched_attacks.jsonl                     ║
echo  ║   📊  Check: attack_summary.json                        ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
pause
