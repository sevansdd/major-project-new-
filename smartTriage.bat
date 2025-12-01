@echo off
REM SmartTriage launcher: install dependencies and run pipeline once (no live monitoring)

REM Go to this script's directory (project root)
cd /d "%~dp0"

echo.
echo ============================================
echo  SmartTriage - One-shot Pipeline Runner
echo  (installs deps, runs pipeline, opens UI)
echo ============================================
echo.

REM 1) Upgrade pip (optional but recommended)
python -m pip install --upgrade pip

REM 2) Install dependencies from requirements.txt
echo Installing Python dependencies from requirements.txt ...
pip install -r requirements.txt

REM 3) Run the pipeline once (this will launch the dashboard at the end)
echo.
echo Running run_pipeline.py ...
python run_pipeline.py

echo.
echo ============================================
echo  Pipeline finished.
echo  If dashboard didn't open, check:
echo    - dashboard.py exists
echo    - Python, Streamlit installed
echo    - logs/ and processed_data/ for errors
echo ============================================
echo.

pause
