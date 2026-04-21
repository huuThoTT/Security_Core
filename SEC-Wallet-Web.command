#!/bin/bash
# Move to the directory where this script is located
cd "$(dirname "$0")"

# Set Python search path so local 'app' package is found
export PYTHONPATH=$PYTHONPATH:.

echo "▶ Khởi động SEC-Wallet Security Core (Bản Web)..."
echo "------------------------------------------------"
/opt/anaconda3/bin/python3 run_web.py

if [ $? -ne 0 ]; then
    echo "------------------------------------------------"
    echo "❌ LỖI: Không thể khởi chạy Server."
    read -p "Nhấn Enter để đóng cửa sổ này..."
fi
