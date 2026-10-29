@echo off
rem Windows: tao .venv (neu chua co), cai thu vien, mo GUI.
cd /d "%~dp0"
if not exist .venv (
    py -3 -m venv .venv 2>nul || python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt -q
python -m demo.gui
if errorlevel 1 pause
