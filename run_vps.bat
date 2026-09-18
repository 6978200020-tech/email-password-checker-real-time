@echo off
setlocal
if "%VPS_HOST%"=="" (
  echo Set VPS_HOST, VPS_USER and VPS_APP_DIR before running this file.
  echo Example: set VPS_HOST=203.0.113.10
  echo          set VPS_USER=ubuntu
  echo          set VPS_APP_DIR=/opt/email-domain-auditor
  pause
  exit /b 1
)
if "%VPS_USER%"=="" set "VPS_USER=ubuntu"
if "%VPS_APP_DIR%"=="" set "VPS_APP_DIR=/opt/email-domain-auditor"

ssh "%VPS_USER%@%VPS_HOST%" "sudo systemctl restart email-domain-auditor && sudo systemctl --no-pager --full status email-domain-auditor"
if errorlevel 1 (
  echo VPS restart failed. Check SSH key access and the systemd service.
  pause
  exit /b 1
)
echo VPS service restarted successfully.
pause
