@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel% equ 0 (
  set "PYTHON=py"
) else (
  set "PYTHON=python"
)

%PYTHON% -m pip show dnspython >nul 2>nul
if not %errorlevel% equ 0 (
  echo Installing required DNS package...
  %PYTHON% -m pip install -r requirements.txt
  if errorlevel 1 (
    echo.
    echo Could not install dependencies. Run: %PYTHON% -m pip install -r requirements.txt
    pause
    exit /b 1
  )
)

echo Starting the auditor. Your browser will open automatically.
%PYTHON% server.py
pause
