@echo off
REM Cursor Complete Removal Tool - Batch Wrapper
REM This batch file runs the PowerShell script with proper permissions

echo ========================================
echo    Cursor Complete Removal Tool
echo ========================================
echo.
echo This tool will completely remove Cursor from your Windows 11 system
echo including all files, registry entries, shortcuts, and data.
echo.
echo WARNING: This action cannot be undone!
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    echo.
) else (
    echo ERROR: This tool must be run as Administrator!
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo Starting Cursor removal process...
echo.

REM Run the PowerShell script
powershell.exe -ExecutionPolicy Bypass -File "%~dp0CursorCompleteRemoval.ps1" -SkipConfirmation

echo.
echo ========================================
echo    Removal Process Complete
echo ========================================
echo.
echo Cursor has been completely removed from your system.
echo.
echo RECOMMENDED: Restart your computer now to ensure all changes take effect.
echo.
echo After restart, you can install Cursor fresh as if it's a new system.
echo.
pause
