@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 7: our spike vs reference binding
  echo ==========================================================
  echo.

  echo === A. our ctypes spike ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5
  echo.

  echo === B. pywintrace reference probe ===
  ".venv\Scripts\python.exe" "scripts\etw_ref_probe.py"
  echo.

  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
