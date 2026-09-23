@echo off
setlocal

echo Setting up the environment...

where py >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    where python >nul 2>nul
    if %ERRORLEVEL% NEQ 0 (
        echo Python 3.12 or later is not installed. Please install Python 3.12 or later and add it to your PATH.
        exit /b 1
    )
    set "PYTHON_CMD=python"
) else (
    set "PYTHON_CMD=py -3"
)

%PYTHON_CMD% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1
if errorlevel 1 (
    echo Python 3.12 or later is not installed. Please install Python 3.12 or later and add it to your PATH.
    exit /b 1
)

if exist ".venv" (
    echo Virtual environment already exists. Skipping creation.
) else (
    echo Creating a virtual environment with Python 3.12 or later...
    %PYTHON_CMD% -m venv .venv
)

echo Activating the virtual environment '.venv'...
call .venv\Scripts\activate.bat

if exist "requirements.txt" (
    echo Installing required packages...
    python -m pip install -r requirements.txt
) else (
    echo requirements.txt not found. Skipping package installation.
)

echo Setup complete!
exit /b 0
