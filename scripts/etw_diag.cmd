@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 6: typed callback fields
  echo ==========================================================
  echo.

  echo === A. EVENT_RECORD with typed callback ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5 --raw
  echo.

  echo === B. legacy callback ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5 --legacy
  echo.

  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
