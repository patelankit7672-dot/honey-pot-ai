@echo off
title HONEY.AI — Full Stack Launcher
color 0A

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   🍯  HONEY.AI — Starting Full Honeypot Stack               ║
echo  ╠══════════════════════════════════════════════════════════════╣
echo  ║   Services: Ollama AI  ^|  SSH Honeypot  ^|  Dashboard        ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

:: Navigate to project directory
cd /d "%~dp0"

:: Activate virtual environment if present
if exist ".venv\Scripts\activate.bat" (
    echo  [*] Activating virtual environment...
    call .venv\Scripts\activate.bat
) else if exist "..\venv\Scripts\activate.bat" (
    call ..\venv\Scripts\activate.bat
)

:: Start Ollama (if not already running)
echo  [*] Starting Ollama AI backend...
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I "ollama.exe" >NUL
if %errorlevel% neq 0 (
    start "Ollama AI Backend" /MIN cmd /c "ollama serve"
    timeout /t 4 /nobreak >nul
    echo  [+] Ollama started.
) else (
    echo  [+] Ollama already running.
)

:: Start Dashboard
echo  [*] Starting HONEY.AI Dashboard on http://localhost:5000 ...
start "HONEY.AI Dashboard" /MIN cmd /c "python dashboard.py & pause"
timeout /t 2 /nobreak >nul

:: Start Honeypot
echo  [*] Starting SSH Honeypot on port 2222...
start "HONEY.AI Honeypot" cmd /c "python honeypot_v2.py & pause"
timeout /t 2 /nobreak >nul

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   ✅  All services launched!                                ║
echo  ╠══════════════════════════════════════════════════════════════╣
echo  ║   🌐  Dashboard : http://localhost:5000                     ║
echo  ║   🔒  Honeypot  : ssh admin@localhost -p 2222               ║
echo  ║   🤖  AI Model  : honeypot-qwen (Ollama)                    ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Press any key to open dashboard in browser...
pause >nul
start http://localhost:5000
