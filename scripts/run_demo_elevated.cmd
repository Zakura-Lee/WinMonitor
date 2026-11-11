@echo off
chcp 65001 >nul
cd /d "%~dp0.."
set PYTHONIOENCODING=utf-8
echo [elevated run] %DATE% %TIME% > "data\elevated_out.log"
".venv\Scripts\python.exe" "scripts\etw_consume_demo.py" --seconds 6 >> "data\elevated_out.log" 2>&1
echo [exit code] %ERRORLEVEL% >> "data\elevated_out.log"
