@echo off
setlocal

echo [REAI Setup] Creating virtual environment...
python -m venv .venv
if %errorlevel% neq 0 (
    echo [!] Failed to create virtual environment. Ensure Python is installed and added to PATH.
    pause
    exit /b %errorlevel%
)

echo [REAI Setup] Activating virtual environment...
call .\.venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [!] Failed to activate virtual environment.
    pause
    exit /b %errorlevel%
)

echo [REAI Setup] Upgrading pip...
python -m pip install -U pip

echo [REAI Setup] Installing REAI in editable mode...
python -m pip install -e .

echo [REAI Setup] Running REAI help to verify installation...
python -m reai --help
if %errorlevel% neq 0 (
    echo [!] REAI installation failed or could not be run.
    pause
    exit /b %errorlevel%
)

echo.
if defined REAI_CONFIG (
    if exist "%REAI_CONFIG%" (
        echo [REAI Setup] Existing config detected via REAI_CONFIG: %REAI_CONFIG%
        echo [REAI Setup] Skipping interactive configuration.
        goto config_done
    )
)

if exist reai.toml (
    echo [REAI Setup] Existing reai.toml detected.
    echo [REAI Setup] Skipping interactive configuration.
    goto config_done
)

echo [REAI Setup] Launching interactive configuration...
python scripts\setup_config.py
if %errorlevel% neq 0 (
    echo.
    echo [!] Setup encountered an error during API testing.
    echo [!] Exiting setup. Fix the errors in reai.toml and try again.
    pause
    exit /b %errorlevel%
)

:config_done
echo.
echo ======================================================================
echo Setup Complete!
echo.
echo To use REAI, always activate the virtual environment first:
echo   .\.venv\Scripts\Activate.ps1   (PowerShell)
echo   call .\.venv\Scripts\activate  (CMD)
echo.
echo Usage examples:
echo   reai sample.exe
echo   reai sample.exe -o ./case_folder
echo   reai ./samples --recursive
echo ======================================================================
pause
