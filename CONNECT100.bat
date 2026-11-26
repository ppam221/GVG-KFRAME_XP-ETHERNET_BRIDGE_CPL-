@echo off
cd /d "%~dp0"

:prompt_ip
set /p "USER_IP=Enter GVG XP/K Frame X IP address (default 127.0.0.1): "
if "%USER_IP%"=="" set USER_IP=127.0.0.1
set /p "VERSION=Enter Frame SW version (default 20.1.1): "
if "%VERSION%"=="" set VERSION=20.1.1
set /p "USER_SUITE=Enter SUITE (1-4) (default 1): "
if "%USER_SUITE%"=="" set USER_SUITE=1
set /p "USER_FPS=Enter FPS for Transition Rate Calculation (24, 25, 29.97/30, 50, 59.94/60) (default 30): "
if "%USER_FPS%"=="" set USER_FPS=30
set /p "USER_NAME=Enter panel name shown in the frame (default NTv2): "
if "%USER_NAME%"=="" set USER_NAME=NTv2

:: Validate IPv4 syntax and check that each octet is between 0 and 255
powershell -NoProfile -Command "$match = '%USER_IP%' -match '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'; if ($match) { exit 0 } else { exit 1 }" >nul 2>&1

if errorlevel 1 (
    echo.
    echo [ERROR] Invalid IP address format or octet exceeds 255. Please try again.
    echo.
    goto prompt_ip
)

start "NT Bridge Live" python GVG_CPL_V100.py --ip %USER_IP% --suite %USER_SUITE% --name "%USER_NAME%" --fps %USER_FPS% --version %VERSION% --live

