import subprocess
import time
import sys
import webbrowser

def start_server():
    print("Starting SEC-Wallet Security Core (Web Mode)...")
    process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", "8000"])
    
    # Wait until server is ready
    import urllib.request
    print("Waiting for server to initialize...")
    for _ in range(30):
        try:
            req = urllib.request.Request("http://127.0.0.1:8000/", method="HEAD")
            urllib.request.urlopen(req)
            print("Server is online!")
            break
        except Exception:
            time.sleep(0.5)
            
    return process

if __name__ == '__main__':
    # 1. Start the FastAPI Backend securely
    server_proc = start_server()
    
    # 2. Open the URL in the Default Browser (Google Chrome, Safari, etc.)
    print("Opening SEC-Wallet in your Web Browser...")
    webbrowser.open("http://127.0.0.1:8000")
    
    # 3. Keep the server running
    try:
        print("\n[BẤM CTRL+C ĐỂ TẮT MÁY CHỦ]")
        server_proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down Security Core...")
        server_proc.terminate()
        server_proc.wait()
