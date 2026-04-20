@echo off
title HONEY.AI — Register Custom Model
color 0A

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║   🍯  HONEY.AI — Registering honeypot-qwen model    ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: Check if Ollama is running
echo  [*] Checking Ollama status...
curl -s http://localhost:11434/api/tags >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Ollama is NOT running. Starting Ollama first...
    start "" ollama serve
    echo  [*] Waiting 5 seconds for Ollama to start...
    timeout /t 5 /nobreak >nul
)

echo  [*] Registering honeypot-qwen from honeypot-merged directory...
echo  [*] This may take 1-3 minutes for the first load.
echo.

ollama create honeypot-qwen -f Modelfile

if %errorlevel% equ 0 (
    echo.
    echo  [+] SUCCESS! Model registered as: honeypot-qwen
    echo.
    echo  [*] Installed models:
    ollama list
    echo.
    echo  [+] You can now start the honeypot with: start_honeypot.bat
) else (
    echo.
    echo  [!] ERROR: Model creation failed.
    echo  [!] Make sure:
    echo      1. Ollama is installed: https://ollama.com/download
    echo      2. The honeypot-merged/ directory exists with model.safetensors
    echo      3. Ollama version is 0.5.0 or newer (run: ollama --version)
)

echo.
pause
