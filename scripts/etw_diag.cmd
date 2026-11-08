@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 5: is OpenTrace actually attaching
  echo ==========================================================
  echo.

  echo === A. normal session name ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 5 --level 5
  echo.

  echo === B. bogus session name, should behave differently ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 5 --level 5 --bogus
  echo.

  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
