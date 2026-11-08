@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0.."

set "LOG=data\etw_diag.log"
set "PY314=C:\Users\Admin\AppData\Local\Programs\Python\Python314\python.exe"
set PYTHONIOENCODING=utf-8

(
  echo ==========================================================
  echo ETW diagnostic round 8: python version and binding comparison
  echo ==========================================================
  echo.

  echo === A. our spike on Python 3.15 (venv) ===
  ".venv\Scripts\python.exe" "src\collect\etw\spike.py" --seconds 6 --level 5
  echo.

  echo === B. our spike on Python 3.14 (system, stdlib only) ===
  "%PY314%" "src\collect\etw\spike.py" --seconds 6 --level 5
  echo.

  echo === C. pywintrace reference binding on Python 3.15 ===
  ".venv\Scripts\python.exe" "scripts\etw_ref_probe.py"
  echo.

  echo === environment ===
  ver
  "%PY314%" --version
  ".venv\Scripts\python.exe" --version
  echo === done ===
) > "%LOG%" 2>&1

type "%LOG%"
