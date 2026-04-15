#!/bin/bash
# Move to the directory where this script is located
cd "$(dirname "$0")"

# Activate environment if necessary or run direct
echo "▶ Khởi động AT-Wallet Security Core..."
python3 run_desktop.py
