@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title RyuWebAuth
cd /d "%~dp0"

set "PORT=3180"

cls

echo.
echo.
echo  ____                     __      __          __       ______           __    __
echo /\  _`\                  /\ \  __/\ \        /\ \     /\  _  \         /\ \__/\ \
echo \ \ \L\ \  __  __  __  __\ \ \/\ \ \ \     __\ \ \____\ \ \L\ \  __  __\ \ ,_\ \ \___
echo  \ \ ,  / /\ \/\ \/\ \/\ \\ \ \ \ \ \ \  /'__`\ \ '__`\\ \  __ \/\ \/\ \\ \ \/\ \  _ `\
echo   \ \ \\ \\ \ \_\ \ \ \_\ \\ \ \_/ \_\ \/\  __/\ \ \L\ \\ \ \/\ \ \ \_\ \\ \ \_\ \ \ \ \
echo    \ \_\ \_\/`____ \ \____/ \ `\___x___/\ \____\\ \_,__/ \ \_\ \_\ \____/ \ \__\\ \_\ \_\
echo     \/_/\/ /`/___/^> \/___/   '\/__//__/  \/____/ \/___/   \/_/\/_/\/___/   \/__/ \/_/\/_/
echo                /\___/
echo                \/__/
echo.
echo		 Welcome to RyuWebAuth
echo		 RyuWebAuth Version 1.0.2.2
echo		 A beautiful Web authentication service
echo		 with 2FA / TOTP support
echo.
echo   ================================================
echo          Service starting on port %PORT% ...
echo   ================================================
echo.
echo   Access URLs:
echo     http://localhost:%PORT%
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    set "ip=%%a"
    set "ip=!ip: =!"
    echo     http://!ip!:%PORT%
)
echo   ================================================
echo.

where node >nul 2>nul
if errorlevel 1 (
    echo   [ERROR] Node.js not found!
    echo   Please install Node.js: https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo   Starting RyuWebAuth server...
echo.

node server.js

echo.
echo   Service stopped.
pause
