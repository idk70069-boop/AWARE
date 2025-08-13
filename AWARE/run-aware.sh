#!/bin/bash
# AWARE Launcher (macOS/Linux)
# Creates venv if missing, installs requirements, then runs AWARE

cd "$(dirname "$0")"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Please install Python 3.8+."
    exit 1
fi

# Create venv if missing
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate venv
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run AWARE scan on current folder
python aware/aware.py scan . --quarantine