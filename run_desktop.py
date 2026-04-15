import webview
import subprocess
import time
import os
import signal
import sys

def start_server():
    print("Starting AT-Wallet Security Core...")
    process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5) 
    return process

if __name__ == '__main__':
    # 1. Start the FastAPI Backend securely in the background
    server_proc = start_server()
    
    # 2. Open the Desktop UI Window (simulating a mobile wallet form factor)
    print("Launching Native Interface...")
    webview.create_window('AT-Wallet Desktop Client', 'http://127.0.0.1:8000', width=450, height=850, resizable=False)
    webview.start()
    
    # 3. Clean up the backend when the UI is closed
    print("Shutting down Security Core...")
    server_proc.terminate()
    server_proc.wait()
