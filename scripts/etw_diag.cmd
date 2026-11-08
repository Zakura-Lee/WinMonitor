@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 4: session mode and ProcessTrace blocking
  echo ==========================================================
  echo.

  echo === A. EVENT_RECORD ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 5 --level 5
  echo.

  echo === B. legacy ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 5 --level 5 --legacy
  echo.

  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
