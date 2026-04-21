#!/bin/bash
# Move to the directory where this script is located
cd "$(dirname "$0")"

# Set Python search path so local 'app' package is found
export PYTHONPATH=$PYTHONPATH:.

echo "▶ Khởi động SEC-Wallet Security Core..."
echo "------------------------------------------------"
python3 run_desktop.py

if [ $? -ne 0 ]; then
    echo "------------------------------------------------"
    echo "❌ LỖI: Không thể khởi chạy ứng dụng."
    echo "Hãy chắc chắn bạn đã cài đặt đủ thư viện: pip install fastapi uvicorn pywebview"
    read -p "Nhấn Enter để đóng cửa sổ này..."
fi
