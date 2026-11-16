@echo off
REM Launcher for the local ETD engine.
REM Prevents __pycache__ from being written inside the extension folder
REM (Chrome rejects extension dirs containing files/dirs starting with "_").
set PYTHONDONTWRITEBYTECODE=1
set PYTHONUTF8=1
cd /d "%~dp0desktop-app"
python run.py