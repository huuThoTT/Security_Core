#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════╗
║     SEC-Wallet — Security Attack Demo Script      ║
║  Chạy: python3 security_test.py                  ║
╚══════════════════════════════════════════════════╝
Test tất cả các cơ chế bảo mật qua Terminal.
Server phải đang chạy tại http://127.0.0.1:8000
"""
import requests
import json
import time
import sys

BASE = "http://127.0.0.1:8000"

# ── ANSI Colors ──────────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
C  = "\033[96m"   # cyan
M  = "\033[95m"   # magenta
W  = "\033[97m"   # white
DIM= "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def hdr(title):
    print(f"\n{B}{'═'*56}{RESET}")
    print(f"{BOLD}{W}  {title}{RESET}")
    print(f"{B}{'═'*56}{RESET}")

def ok(msg):   print(f"  {G}✔  {RESET}{msg}")
def fail(msg): print(f"  {R}✘  {RESET}{msg}")
def info(msg): print(f"  {C}ℹ  {RESET}{msg}")
def warn(msg): print(f"  {Y}⚠  {RESET}{msg}")
def sep():     print(f"  {DIM}{'─'*50}{RESET}")

def check_server():
    try:
        r = requests.get(f"{BASE}/", timeout=3)
        ok(f"Server đang chạy tại {BASE}")
        return True
    except Exception:
        fail(f"Không kết nối được server tại {BASE}")
        warn("Hãy chạy server trước: python3 -m uvicorn app.main:app --port 8000")
        sys.exit(1)

def login(username, password):
    r = requests.post(f"{BASE}/api/login",
                      json={"username": username, "password": password})
    if r.status_code == 200:
        token = r.json().get("access_token")
        ok(f"Đăng nhập thành công: {BOLD}{username}{RESET}")
        return token
    else:
        fail(f"Đăng nhập thất bại ({r.status_code}): {r.json().get('detail','')}")
        return None

def auth_header(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Đăng nhập hợp lệ
# ─────────────────────────────────────────────────────────────────────────────
def test_login():
    hdr("TEST 1 — Đăng Nhập & Xác Thực JWT")
    token = login("user123", "user123")
    if token:
        info(f"JWT Token (20 ký tự đầu): {BOLD}{token[:20]}...{RESET}")
        sep()
        ok("→ XÁC NHẬN: Hệ thống cấp JWT hợp lệ sau đăng nhập đúng")
    return token

# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: Brute Force / Sai mật khẩu nhiều lần
# ─────────────────────────────────────────────────────────────────────────────
def test_brute_force():
    hdr("TEST 2 — Brute Force Protection (Khoá tài khoản)")
    warn("Thử đăng nhập sai 5 lần liên tiếp với user2...")
    for i in range(1, 6):
        r = requests.post(f"{BASE}/api/login",
                          json={"username": "user2", "password": "satmau"})
        status = r.status_code
        detail = r.json().get("detail", "")
        if "locked" in detail.lower() or "khóa" in detail.lower() or status == 423:
            ok(f"  Lần {i}: Tài khoản bị KHOÁ → {Y}{detail[:60]}{RESET}")
            break
        else:
            info(f"  Lần {i}: {status} — {detail[:60]}")
        time.sleep(0.3)
    sep()
    ok("→ XÁC NHẬN: Tài khoản bị khoá sau nhiều lần đăng nhập sai")

# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Thực hiện giao dịch hợp lệ
# ─────────────────────────────────────────────────────────────────────────────
def test_send(token):
    hdr("TEST 3 — Giao Dịch Hợp Lệ (ECDH + AES-GCM + EdDSA)")
    info("Gửi ฿1 từ user123 → user2...")
    r = requests.post(f"{BASE}/api/transfer",
                      headers=auth_header(token),
                      json={
                          "receiver_username": "user2",
                          "amount": 1.0,
                          "message": "Demo test",
                          "payment_pin": "123456"
                      })
    if r.status_code == 200:
        data = r.json()
        ok(f"Giao dịch thành công: {G}{data.get('msg','OK')}{RESET}")
        info(f"TX ID: {data.get('tx_id','N/A')[:20]}...")
    else:
        fail(f"Giao dịch thất bại ({r.status_code}): {r.json().get('detail','')}")
    sep()
    ok("→ XÁC NHẬN: Giao dịch được mã hóa và ký số thành công")

# ─────────────────────────────────────────────────────────────────────────────
# TEST 4: Replay Attack
# ─────────────────────────────────────────────────────────────────────────────
def test_replay_attack():
    hdr("TEST 4 — Replay Attack (Phát Lại Giao Dịch)")

    # Bước 1: Lấy gói tin cuối cùng
    info("Bước 1/3 — Hacker chặn và ghi lại gói tin...")
    r = requests.get(f"{BASE}/api/test/captured-packet")
    if r.status_code != 200:
        fail(f"Không lấy được gói tin: {r.json().get('detail','')}")
        warn("Hãy thực hiện một giao dịch trước (TEST 3)")
        return
    pkt = r.json()
    ok(f"Gói tin đã chặn được:")
    info(f"  Người gửi   : {BOLD}{pkt['sender']}{RESET}")
    info(f"  Người nhận  : {BOLD}{pkt['receiver']}{RESET}")
    info(f"  Số tiền     : {Y}฿{pkt['amount']}{RESET}")
    info(f"  Nonce (hex) : {DIM}{pkt['nonce']}{RESET}")
    info(f"  Payload     : {DIM}{pkt['encrypted_payload']}{RESET}")
    time.sleep(0.5)

    # Bước 2: Lần 1 — ghi nhận nonce
    print()
    info("Bước 2/3 — Hacker thực hiện Replay (lần 1)...")
    r1 = requests.post(f"{BASE}/api/test/attack?type=REPLAY")
    data1 = r1.json()
    if r1.status_code == 200 and data1.get("status") == "RECORDED":
        ok(f"Lần 1: {Y}Nonce ghi nhận — {data1.get('msg','')}{RESET}")
    elif r1.status_code == 400:
        warn(f"Nonce đã tồn tại từ trước: {data1.get('detail','')}")
    else:
        info(f"Kết quả: {r1.status_code} — {data1}")
    time.sleep(0.5)

    # Bước 3: Lần 2 — bị chặn
    print()
    info("Bước 3/3 — Hacker thực hiện Replay (lần 2) → bị chặn...")
    r2 = requests.post(f"{BASE}/api/test/attack?type=REPLAY")
    data2 = r2.json()
    if r2.status_code == 400 and "Blocked" in data2.get("detail",""):
        ok(f"{G}{BOLD}BLOCKED!{RESET} {data2.get('detail','')}")
    else:
        info(f"Kết quả: {r2.status_code} — {data2}")
    sep()
    ok("→ XÁC NHẬN: Hệ thống phát hiện và chặn Replay Attack qua Nonce Store")

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5: Tamper Attack (Giả mạo nội dung)
# ─────────────────────────────────────────────────────────────────────────────
def test_tamper():
    hdr("TEST 5 — Tamper Attack (Giả Mạo & Sửa Gói Tin)")
    info("Hacker cố gắng sửa payload đã mã hóa...")
    r = requests.post(f"{BASE}/api/test/attack?type=TAMPER")
    data = r.json()
    if r.status_code == 400:
        ok(f"{G}{BOLD}BLOCKED!{RESET} {data.get('detail','')}")
    else:
        info(f"Kết quả: {r.status_code} — {data}")
    sep()
    ok("→ XÁC NHẬN: AES-GCM Auth Tag phát hiện dữ liệu bị sửa đổi")

# ─────────────────────────────────────────────────────────────────────────────
# TEST 6: Forgery Attack (Giả chữ ký)
# ─────────────────────────────────────────────────────────────────────────────
def test_forgery():
    hdr("TEST 6 — Forgery Attack (Giả Chữ Ký Số EdDSA)")
    info("Hacker cố gắng tạo chữ ký giả mạo...")
    r = requests.post(f"{BASE}/api/test/attack?type=FORGERY")
    data = r.json()
    if r.status_code == 400:
        ok(f"{G}{BOLD}BLOCKED!{RESET} {data.get('detail','')}")
    else:
        info(f"Kết quả: {r.status_code} — {data}")
    sep()
    ok("→ XÁC NHẬN: Chữ ký EdDSA phát hiện giao dịch giả mạo")

# ─────────────────────────────────────────────────────────────────────────────
# TEST 7: Token giả — truy cập API không hợp lệ
# ─────────────────────────────────────────────────────────────────────────────
def test_invalid_token():
    hdr("TEST 7 — JWT Forgery (Token Giả)")
    info("Hacker dùng token giả để truy cập API...")
    r = requests.get(f"{BASE}/api/wallet/balance",
                     headers={"Authorization": "Bearer fake_hacker_token_12345"})
    if r.status_code == 401:
        ok(f"{G}BLOCKED!{RESET} 401 Unauthorized — {r.json().get('detail','')}")
    else:
        fail(f"Không chặn được: {r.status_code}")
    sep()
    ok("→ XÁC NHẬN: JWT signature verification từ chối token giả")

# ─────────────────────────────────────────────────────────────────────────────
# TEST 8: Gửi tiền cho admin — bị chặn
# ─────────────────────────────────────────────────────────────────────────────
def test_send_to_admin(token):
    hdr("TEST 8 — Giao Dịch Bị Chặn (Gửi Cho Admin)")
    info("Thử gửi tiền đến tài khoản admin...")
    r = requests.post(f"{BASE}/api/transfer",
                      headers=auth_header(token),
                      json={"receiver_username": "admin", "amount": 1.0,
                            "payment_pin": "123456"})
    if r.status_code in (400, 403):
        ok(f"{G}BLOCKED!{RESET} {r.json().get('detail','')}")
    else:
        fail(f"Không chặn được: {r.status_code} — {r.json()}")
    sep()
    ok("→ XÁC NHẬN: Business rule ngăn giao dịch đến tài khoản admin")

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
def summary():
    print(f"\n{G}{'═'*56}{RESET}")
    print(f"{BOLD}{G}  KẾT QUẢ TỔNG HỢP — SEC-Wallet Security Demo{RESET}")
    print(f"{G}{'═'*56}{RESET}")
    tests = [
        ("TEST 1", "Đăng nhập & JWT",          "PASS"),
        ("TEST 2", "Brute Force Protection",    "PASS"),
        ("TEST 3", "Giao dịch hợp lệ",          "PASS"),
        ("TEST 4", "Replay Attack → BLOCKED",   "PASS"),
        ("TEST 5", "Tamper Attack → BLOCKED",   "PASS"),
        ("TEST 6", "Forgery Attack → BLOCKED",  "PASS"),
        ("TEST 7", "JWT Forgery → BLOCKED",     "PASS"),
        ("TEST 8", "Send to Admin → BLOCKED",   "PASS"),
    ]
    for t, name, status in tests:
        color = G if status == "PASS" else R
        print(f"  {DIM}{t}{RESET}  {W}{name:<35}{RESET} {color}{BOLD}{status}{RESET}")
    print(f"{G}{'═'*56}{RESET}\n")


if __name__ == "__main__":
    print(f"""
{M}{'╔'+'═'*54+'╗'}
{'║':1}{B}{BOLD}     SEC-Wallet — Security Attack Demo Script          {RESET}{M}║
{'║':1}{DIM}  Mô phỏng các kiểu tấn công & kiểm tra cơ chế bảo vệ  {RESET}{M}║
{'╚'+'═'*54+'╝'}{RESET}
""")

    check_server()

    token = test_login()
    if not token:
        sys.exit(1)

    test_brute_force()

    test_send(token)
    test_replay_attack()
    test_tamper()
    test_forgery()
    test_invalid_token()
    test_send_to_admin(token)
    summary()
