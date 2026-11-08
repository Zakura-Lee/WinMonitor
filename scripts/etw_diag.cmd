@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 10: struct layout fixed
  echo ==========================================================
  echo.

  echo === our spike after fixing EVENT_TRACE_HEADER ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5 --raw
  echo.

  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
