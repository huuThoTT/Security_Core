# AT-Wallet — Secure Cryptocurrency Wallet Simulator

Đồ án AT-Wallet là một ví điện tử mô phỏng, được thiết kế để áp dụng các kỹ thuật mật mã nâng cao trong việc bảo mật giao dịch, bảo vệ quyền riêng tư và phát hiện/ngăn chặn các hành vi tấn công phổ biến.

## Tính Năng Bảo Mật Cốt Lõi

1. **Bảo mật giao dịch:**
    - Hoán đổi khóa Diffie-Hellman (ECDH) qua Curve25519 (Forward Secrecy).
    - Mã hóa xác thực AES-256-GCM bảo vệ tính bảo mật và toàn vẹn của dữ liệu (chống giả mạo - Tamper Attack).
    - Ký số phân đoạn EdDSA (Ed25519) đảm bảo tính chống chối bỏ.

2. **Chống tấn công phát lại (Replay Attack):**
    - Sử dụng hệ thống theo dõi Nonce độc nhất qua `NonceStore`. Gói tin gửi lần hai với cùng Nonce lập tức bị từ chối.

3. **Bảo mật truy cập & Tài khoản:**
    - Mật khẩu băm an toàn qua PBKDF2 / Argon2.
    - Quản lý mã PIN giao dịch (Payment PIN) độc lập.
    - Bảo vệ chống Brute-force: Khóa tài khoản (Account Lockout) sau 5 lần đăng nhập sai.
    - Quản lý phiên làm việc bằng JSON Web Tokens (JWT) chống giả mạo (JWT Forgery).
    - Hỗ trợ mã OTP dự phòng cho tính năng khôi phục.

4. **Trải nghiệm người dùng:**
    - Web UI phản hồi nhanh (FastAPI backend + JavaScript frontend).
    - Trang Web và Demo được đóng gói gọn nhẹ, dễ dàng thiết lập và sử dụng.

---

## Hướng Dẫn Cài Đặt và Chạy Đồ Án Chấm Điểm

### 1. Yêu Cầu Hệ Thống
- Đã cài đặt **Python 3.10+** (hoặc Anaconda).
- Kiến trúc MacOS / Linux / Windows WSL.

### 2. Cài Đặt Thư Viện (Dependencies)
Mở terminal tại thư mục gốc của đồ án và chạy lệnh sau để tải các thư viện mật mã & server:

```bash
pip install fastapi "uvicorn[standard]" cryptography argon2-cffi pyotp python-jose passlib sqlalchemy
```

### 3. Chạy Server Mô Phỏng (AT-Wallet Backend)
Mở Terminal, di chuyển tới thư mục gốc, và khởi động Uvicorn Server:
```bash
python3 -m uvicorn app.main:app --port 8000
```
*Server sẽ chạy tại địa chỉ `http://127.0.0.1:8000` (port 8000). Dữ liệu sẽ được lưu tự động bằng SQLite `at_wallet.db` và hệ thống khóa RSA/ECC ở thư mục `keys/`.*

### 4. Truy Cập Giao Diện Chấm Bài

Sau khi Server báo chạy thành công, truy cập trình duyệt web vào:
- **Giao diện ví người dùng:** `http://127.0.0.1:8000/static/index.html` (Dùng để trải nghiệm, đăng nhập, nạp/rút/chuyển tiền).
- **Giao diện Hacker (Attacker Demo):** `http://127.0.0.1:8000/static/attacker.html` (Bảng điều khiển trực quan dành riêng cho việc test Replay Attack).

### 5. Dùng Terminal Để Test Attack Tự Động (Kịch Bản Mẫu)
Để tiết kiệm thời gian chấm bài và thể hiện các biện pháp an ninh chạy hậu trường, nhóm đã tạo riêng một **Script Test tự động**. Script này mô phỏng các kiểu tấn công như Brute force, Tamper (giả mạo dữ liệu), Replay (phát lại) và Forgery (ký số sai).

Trong khi Server **vẫn đang chạy**, bạn mở thêm một tab terminal khác và chạy:
```bash
python3 security_test.py
```
Script sẽ khởi chạy toàn bộ 8 bài test từ lúc đăng nhập, gửi tiền, mã hóa cho đến lúc hệ thống từ chối hacker và in kết quả ra log màu cực kỳ rõ ràng.

---

## Danh Sách Tài Khoản Dùng Thử

| Tính năng | Username | Password |
|---|---|---|
| Người gửi / Nạn nhân | `user123` | `user123` |
| Người nhận tiền     | `user2`   | `user2` |
| Quản trị viên (bị khóa gửi) | `admin`   | `admin` |

*(Tất cả đều dùng mã **Payment PIN** là: `123456`)*

Chúc các thầy cô chấm bài trải nghiệm phần mềm thật thú vị!
