@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title RyuWebAuth
cd /d "%~dp0"

set "PORT=3180"

echo.
echo   ==========================================
echo                  RyuWebAuth
echo   ==========================================
echo.
echo   2FA / TOTP service is starting...
echo.
echo   Login URLs:
echo.
echo     - https://localhost:%PORT%
echo     - https://127.0.0.1:%PORT%

for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    set "ip=%%a"
    set "ip=!ip: =!"
    echo     - https://!ip!:%PORT%
)

echo.
echo   ------------------------------------------
echo   Default super admin: RyuWebAuth / F2a2026x
echo   (printed once in the console on first run)
echo   ------------------------------------------
echo.

where node >nul 2>nul
if errorlevel 1 (
    echo   [ERROR] Node.js not found. Please install Node.js first.
    echo   Download: https://nodejs.org/
    pause
    exit /b 1
)

if not exist "node_modules" (
    echo   [INFO] Dependencies not found, running npm install ...
    call npm install
    echo.
)

node server.js

echo.
echo   Service stopped.
pause
