#!/bin/bash
set -e

echo "[REAI Setup] Creating virtual environment..."
python3 -m venv .venv || { echo "[!] Failed to create virtual environment. Ensure python3-venv is installed."; exit 1; }

echo "[REAI Setup] Activating virtual environment..."
source .venv/bin/activate || { echo "[!] Failed to activate virtual environment."; exit 1; }

echo "[REAI Setup] Upgrading pip..."
python3 -m pip install -U pip

echo "[REAI Setup] Installing REAI in editable mode..."
python3 -m pip install -e .

echo "[REAI Setup] Running REAI help to verify installation..."
python3 -m reai --help || { echo "[!] REAI installation failed or could not be run."; exit 1; }

echo ""
if [ -n "${REAI_CONFIG:-}" ] && [ -f "$REAI_CONFIG" ]; then
    echo "[REAI Setup] Existing config detected via REAI_CONFIG: $REAI_CONFIG"
    echo "[REAI Setup] Skipping interactive configuration."
elif [ -f "reai.toml" ]; then
    echo "[REAI Setup] Existing reai.toml detected."
    echo "[REAI Setup] Skipping interactive configuration."
else
    echo "[REAI Setup] Launching interactive configuration..."
    python3 scripts/setup_config.py || {
        echo ""
        echo "[!] Setup encountered an error during API testing."
        echo "[!] Exiting setup. Fix the errors in reai.toml and try again."
        exit 1
    }
fi

echo ""
echo "======================================================================"
echo "Setup Complete!"
echo ""
echo "To use REAI, always activate the virtual environment first:"
echo "  source .venv/bin/activate"
echo ""
echo "Usage examples:"
echo "  reai sample.exe"
echo "  reai sample.exe -o ./case_folder"
echo "  reai ./samples --recursive"
echo "======================================================================"
