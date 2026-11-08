@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 9: mirroring the reference implementation
  echo ==========================================================
  echo.

  echo === A. our spike, properties mirrored from pywintrace ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5
  echo.

  echo === B. same but without buffer callback ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5 --no-buffer-cb
  echo.

  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
