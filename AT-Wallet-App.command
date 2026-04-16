#!/bin/bash
# Move to the directory where this script is located
cd "$(dirname "$0")"

# Auto-install the desktop wrapper dependency if missing
python3 -m pip install pywebview > /dev/null 2>&1

# Activate environment if necessary or run direct
echo "▶ Khởi động AT-Wallet Security Core..."
python3 run_desktop.py
