@echo off
chcp 65001 >nul
title IOC Log Analyzer with VirusTotal Integration

echo.
echo ========================================
echo   IOC Log Analyzer with VirusTotal
echo ========================================
echo.

REM Detect Python (prefer `py -3` if available)
set "PY="
where py >nul 2>&1
if %errorlevel%==0 (
    set "PY=py -3"
) else (
    where python >nul 2>&1
    if %errorlevel%==0 (
        set "PY=python"
    )
)
if "%PY%"=="" (
    echo [ERROR] Python not found.
    echo Install Python 3 from https://python.org
    echo.
    pause
    exit /b 1
)
echo [OK] Python found: %PY%
echo.

REM Sanity-check required files
if not exist "analyzer.py"     ( echo [ERROR] analyzer.py not found    & pause & exit /b 1 )
if not exist "ioc_list.json"   ( echo [ERROR] ioc_list.json not found  & pause & exit /b 1 )
if not exist "vt_config.json"  ( echo [WARN]  vt_config.json not found - VT modes will fail. )

echo [OK] All files found
echo.

:menu
echo ========================================
echo            ANALYSIS MODES
echo ========================================
echo.
echo 1. Log analysis only (fast)
echo 2. Log analysis + VirusTotal check
echo 3. VirusTotal IOC check only
echo 4. Exit
echo.
echo ========================================

set /p choice="Enter number (1-4): "

if "%choice%"=="1" goto basic
if "%choice%"=="2" goto full
if "%choice%"=="3" goto vt_only
if "%choice%"=="4" goto exit_now
echo Invalid choice!
echo.
goto menu

:basic
echo.
echo === Basic log analysis ===
%PY% analyzer.py --log apache.log --ioc ioc_list.json --output alerts.csv
goto end

:full
echo.
echo === Full analysis with VirusTotal ===
%PY% analyzer.py --log apache.log --ioc ioc_list.json --vt-config vt_config.json --vt-check --output alerts.csv
goto end

:vt_only
echo.
echo === VirusTotal IOC check only ===
%PY% analyzer.py --ioc ioc_list.json --vt-config vt_config.json --vt-only
goto end

:exit_now
echo Exit...
exit /b 0

:end
echo.
echo ========================================
echo Analysis completed!
echo.
echo Results saved to:
echo - alerts.csv (found IOCs in logs)
echo - virustotal_results.json (VirusTotal results)
echo - .vt_cache.json (persistent VT cache)
echo.
echo All files are in the src\ folder
echo ========================================
echo.
pause
exit /b 0
