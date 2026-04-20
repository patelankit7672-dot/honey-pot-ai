@echo off
title HONEY.AI — Windows Task Scheduler Setup
color 0A

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║   🍯  HONEY.AI — Auto-Start Setup (Task Scheduler)     ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
echo  This will register HONEY.AI to auto-start on Windows login.
echo.

:: Get the full path to start_honeypot.bat
set "SCRIPT_PATH=%~dp0start_honeypot.bat"
set "TASK_NAME=HONEY.AI Honeypot"

echo  [*] Registering Task Scheduler entry...
echo  [*] Script path: %SCRIPT_PATH%
echo.

:: Delete existing task if it exists
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

:: Create new task — runs at user logon, with highest privileges
schtasks /create ^
    /tn "%TASK_NAME%" ^
    /tr "\"%SCRIPT_PATH%\"" ^
    /sc ONLOGON ^
    /rl HIGHEST ^
    /delay 0001:00 ^
    /f

if %errorlevel% equ 0 (
    echo  [+] SUCCESS! Task registered: "%TASK_NAME%"
    echo.
    echo  [*] Task details:
    schtasks /query /tn "%TASK_NAME%" /fo LIST
    echo.
    echo  [+] HONEY.AI will now auto-start 1 minute after Windows login.
    echo  [+] To remove: schtasks /delete /tn "%TASK_NAME%" /f
) else (
    echo  [!] Failed to create task. Try running this script as Administrator.
    echo  Right-click setup_windows_task.bat → "Run as administrator"
)

echo.
pause
