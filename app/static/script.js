// State
let currentUser = null;
let currentToken = null;
let authMode = 'login';
// API Base configuration for cross-origin development (e.g., Live Server on 5501)
const API_BASE = (window.location.port === '5501' || window.location.port === '5500')
    ? 'http://127.0.0.1:8000'
    : '';

// ─── TOAST NOTIFICATION SYSTEM ───────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
    let container = document.getElementById('toast-container');
    // Auto-create container if missing
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:1.25rem;left:50%;transform:translateX(-50%);z-index:99999;display:flex;flex-direction:column;gap:0.5rem;width:90%;max-width:380px;pointer-events:none;';
        document.body.appendChild(container);
    }
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const colors = {
        success: { bg: '#d1fae5', border: '#34d399', text: '#065f46' },
        error: { bg: '#fee2e2', border: '#f87171', text: '#7f1d1d' },
        warning: { bg: '#fef3c7', border: '#fbbf24', text: '#78350f' },
        info: { bg: '#e0f2fe', border: '#38bdf8', text: '#0c4a6e' },
    };
    const c = colors[type] || colors.info;
    const toast = document.createElement('div');
    toast.style.cssText = `background:${c.bg};border:1.5px solid ${c.border};color:${c.text};border-radius:0.75rem;padding:0.75rem 1rem;font-size:0.875rem;font-weight:500;display:flex;align-items:flex-start;gap:0.6rem;box-shadow:0 4px 16px rgba(0,0,0,0.12);animation:toastIn 0.3s ease;pointer-events:all;cursor:pointer;line-height:1.4;`;
    toast.innerHTML = `<span style="font-size:1.1rem;flex-shrink:0">${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
    toast.onclick = () => { clearTimeout(toast._t); toast.style.animation = 'toastOut 0.25s ease forwards'; setTimeout(() => toast.remove(), 250); };
    container.appendChild(toast);
    toast._t = setTimeout(() => toast.onclick(), duration);
}
// Inject CSS after DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('_ts')) return;
    const s = document.createElement('style');
    s.id = '_ts';
    s.textContent = '@keyframes toastIn{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}@keyframes toastOut{from{opacity:1;transform:translateY(0)}to{opacity:0;transform:translateY(-8px)}}';
    document.head.appendChild(s);
});
// ─────────────────────────────────────────────────────────────────────────────

// Navigation

function toggleAuthMode(mode) {
    authMode = mode;
    document.getElementById('tab-login').classList.toggle('active', mode === 'login');
    document.getElementById('tab-register').classList.toggle('active', mode === 'register');

    const title = document.getElementById('auth-title');
    const btn = document.getElementById('auth-btn');
    const desc = document.getElementById('auth-desc');

    if (mode === 'login') {
        title.innerText = 'Unlock Wallet';
        btn.innerText = 'Unlock Now';
        desc.innerText = 'Enter your master password to decrypt your wallet keys.';
        document.getElementById('pin-setup-group').style.display = 'none';
    } else {
        title.innerText = 'Initialize Wallet';
        btn.innerText = 'Create Secure Wallet';
        desc.innerText = 'Your keys will be protected by a dedicated 6-digit Payment PIN.';
        document.getElementById('pin-setup-group').style.display = 'block';
    }
}

function handleAuth() {
    if (authMode === 'login') {
        loginUser();
    } else {
        registerUser();
    }
}

function switchView(viewId, navEl) {
    // Hide all sections
    document.querySelectorAll('.app-section').forEach(s => s.classList.remove('active'));

    // Show selected section
    const target = document.getElementById('view-' + viewId);
    if (target) target.classList.add('active');

    // Update Nav bar
    if (navEl) {
        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        navEl.classList.add('active');
    } else {
        // Find the nav item manually if navEl is null (for programmatic switching)
        document.querySelectorAll('.nav-item').forEach(i => {
            if (i.innerText.toLowerCase().includes(viewId)) {
                i.classList.add('active');
            } else {
                i.classList.remove('active');
            }
        });
    }

    if (viewId === 'admin') {
        loadAdminPanel();
    }

    // Always clear auth fields when returning to login screen
    if (viewId === 'auth') {
        const fields = ['auth-username', 'auth-password', 'auth-pin',
            'recovery-username', 'recovery-otp', 'recovery-new-password'];
        fields.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        // Focus username for quick entry
        const u = document.getElementById('auth-username');
        if (u) setTimeout(() => u.focus(), 100);
    }

    // Clear request form when entering request view
    if (viewId === 'request') {
        ['req-target', 'req-amount'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        const t = document.getElementById('req-target');
        if (t) setTimeout(() => t.focus(), 100);
    }
}

// Actions
async function loginUser() {
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;

    if (!username || !password) {
        showToast("Nhập tên đăng nhập và mật khẩu để mở khoá ví.", 'info');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();
            currentUser = data.user;
            currentToken = data.access_token;
            loginSuccess();
        } else {
            const err = await response.json();
            showToast("Đăng nhập thất bại: " + (err.detail || "Sai tên đăng nhập hoặc mật khẩu."), 'error');
        }
    } catch (e) {
        showToast("Lỗi kết nối với Security Core.", 'error');
    }
}

async function registerUser() {
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;
    const pin = document.getElementById('auth-pin').value;

    if (!username || !password || !pin) {
        showToast("Vui lòng nhập đủ tên đăng nhập, mật khẩu và mã PIN 6 chữ số.", 'warning');
        return;
    }

    if (pin.length !== 6 || isNaN(pin)) {
        showToast("Mã PIN phải đúng 6 chữ số.", 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, payment_pin: pin })
        });

        if (response.ok) {
            const data = await response.json();

            showToast("Đăng ký thành công! Ví bảo mật đã được khởi tạo. Hãy đăng nhập.", 'success');

            // Populate Mnemonic
            if (data.recovery_mnemonic) {
                const display = document.getElementById('mnemonic-display');
                display.innerHTML = ''; // Clear
                data.recovery_mnemonic.split(' ').forEach((word, index) => {
                    const span = document.createElement('div');
                    span.innerHTML = `<span style="opacity: 0.5;">${index + 1}.</span> ${word}`;
                    display.appendChild(span);
                });
                document.getElementById('mnemonic-container').style.display = 'block';
            }

            // Populate 2FA elements
            if (data.totp_secret) {
                document.getElementById('totp-secret-text').innerText = data.totp_secret;
                document.getElementById('totp-qr').src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(data.totp_uri)}`;
            }

            // Navigate to Setup View
            switchView('setup');

        } else {
            const err = await response.json();
            showToast("Đăng ký thất bại: " + err.detail, 'error');
        }
    } catch (e) {
        showToast("Không thể kết nối tới server.", 'error');
    }
}

function loginSuccess() {
    // UI Transitions
    document.getElementById('view-auth').style.display = 'none';
    document.getElementById('app-header').style.display = 'flex';

    // Set Profile
    document.getElementById('display-username').innerText = currentUser.username;

    // Clear password inputs
    document.getElementById('auth-password').value = '';

    // Admin vs Normal User Interface Routing
    if (currentUser.role === 'Admin') {
        document.getElementById('user-avatar').innerText = '👮';
        document.getElementById('main-nav').style.display = 'none';
        switchView('admin');
    } else {
        document.getElementById('user-avatar').innerText = currentUser.username[0].toUpperCase();
        document.getElementById('main-nav').style.display = 'flex';
        switchView('home');
        refreshAppData();
    }
}

function logoutUser() {
    // Clear state
    currentUser = null;
    currentToken = null;

    // UI Reset
    document.getElementById('app-header').style.display = 'none';
    document.getElementById('main-nav').style.display = 'none';
    document.getElementById('view-auth').style.display = 'block';

    // Clear inputs
    document.getElementById('auth-username').value = '';
    document.getElementById('auth-password').value = '';

    switchView('auth');
}

async function openTransferConfirmation() {
    const receiver = document.getElementById('tx-receiver').value;
    const amount = document.getElementById('tx-amount').value;

    if (!receiver || !amount || isNaN(amount) || amount <= 0) {
        showToast("Vui lòng nhập người nhận và số tiền hợp lệ.", 'warning');
        return;
    }

    // Default message logic
    const defaultMsg = `${currentUser.username} chuyển tiền`;

    const result = await showSecureModal(
        `Authorize Transfer`,
        receiver,
        amount,
        defaultMsg
    );

    if (result && result.pin) {
        sendTransfer(receiver, amount, result.message, result.pin);
    }
}

async function sendTransfer(receiver, amount, msg, pin) {
    const btn = document.getElementById('btn-transfer');

    // Disable button to prevent double clicks
    btn.disabled = true;
    btn.innerText = "Processing Security Protocols...";

    try {
        const response = await fetch(`${API_BASE}/api/transfer`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                receiver_username: receiver,
                amount: parseFloat(amount),
                message: msg,
                payment_pin: pin
            })
        });

        if (response.ok) {
            showToast("Giao dịch thành công!", 'success');

            // Clear Inputs
            if (document.getElementById('tx-receiver')) document.getElementById('tx-receiver').value = '';
            if (document.getElementById('tx-amount')) document.getElementById('tx-amount').value = '';
            if (document.getElementById('tx-msg')) document.getElementById('tx-msg').value = '';
            if (document.getElementById('tx-pin')) document.getElementById('tx-pin').value = '';
            if (document.getElementById('tx-2fa')) document.getElementById('tx-2fa').value = '';

            switchView('home');
            refreshAppData();
        } else {
            const err = await response.json();
            showToast("Giao dịch bị chặn bởi Security Core! " + (err.detail || "Lỗi bảo mật."), 'error');
            refreshAppData();
        }
    } catch (e) {
        showToast("Giao dịch thất bại. Hệ thống bận. Thử lại.", 'error');
    } finally {
        // Re-enable button
        btn.disabled = false;
        btn.innerText = "Sign & Send Securely";
    }
}

async function refreshAppData() {
    if (!currentToken) return;
    fetchBalance();
    fetchTransactions();
    fetchIncomingRequests();
    fetchLogs();
}

async function openRequestConfirmation() {
    const target = document.getElementById('req-target').value.trim();
    const amount = document.getElementById('req-amount').value;

    if (!target || !amount || parseFloat(amount) <= 0) {
        showToast("Vui lòng nhập đầy đủ tên người dùng và số tiền hợp lệ.", 'warning');
        return;
    }

    if (target.toLowerCase() === currentUser?.username?.toLowerCase()) {
        showToast("Không thể gửi yêu cầu cho chính mình.", 'warning');
        return;
    }

    const defaultMsg = `${currentUser.username} yêu cầu chuyển tiền`;
    const result = await showSecureModal(
        'Xác Nhận Yêu Cầu Tiền',
        target,
        parseFloat(amount),
        defaultMsg
    );

    if (!result) return; // user cancelled

    try {
        const response = await fetch(`${API_BASE}/api/transactions/request`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                target_username: target,
                amount: parseFloat(amount),
                message: result.message || defaultMsg
            })
        });

        if (response.ok) {
            showToast(`Đã gửi yêu cầu ฿${parseFloat(amount).toLocaleString('vi-VN')} tới "${target}" thành công!`, 'success');
            switchView('home');
            refreshAppData();
        } else {
            const err = await response.json();
            showToast("Lỗi: " + (err.detail || "Yêu cầu thất bại"), 'error');
        }
    } catch (e) {
        showToast("Lỗi kết nối: " + (e.message || "Không thể gửi yêu cầu."), 'error');
    }
}

// Legacy alias (kept for safety)
async function sendPaymentRequest() { await openRequestConfirmation(); }

async function fetchIncomingRequests() {
    try {
        const response = await fetch(`${API_BASE}/api/transactions/requests/incoming`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const reqs = await response.json();
        const listContainer = document.getElementById('pending-requests-list');
        const section = document.getElementById('incoming-requests-section');

        if (reqs.length === 0) {
            section.style.display = 'none';
            return;
        }

        section.style.display = 'block';
        listContainer.innerHTML = '';

        reqs.forEach(req => {
            const div = document.createElement('div');
            div.className = 'card-white';
            div.style = 'display: flex; align-items: center; gap: 1rem; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid var(--primary);';

            div.innerHTML = `
                <div style="flex: 1;">
                    <div style="font-weight: 600; font-size: 0.9rem;">From: ${req.requester_username}</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">${req.message || 'No message'}</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-weight: 700; color: var(--text-dark); margin-bottom: 0.25rem;">฿${req.amount}</div>
                    <button class="btn-primary" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;" onclick="fulfillRequest('${req.id}', ${req.amount}, '${req.requester_username}')">Pay Now</button>
                </div>
            `;
            listContainer.appendChild(div);
        });
    } catch (e) {
        console.error("Failed to fetch requests");
    }
}

// --- SECURE MODAL LOGIC ---
let modalResolver = null;

function showSecureModal(title, recipient, amount, defaultMsg) {
    document.getElementById('modal-title').innerText = title;

    // Summary
    const summary = document.getElementById('modal-summary');
    if (recipient && amount) {
        summary.style.display = 'block';
        document.getElementById('summary-amount').innerText = amount;
        document.getElementById('summary-recipient').innerText = recipient;
    } else {
        summary.style.display = 'none';
    }

    // Message
    const msgInput = document.getElementById('modal-msg');
    msgInput.value = defaultMsg || '';

    // PIN
    document.getElementById('modal-pass').value = '';
    document.getElementById('secure-modal').style.display = 'flex';

    return new Promise((resolve) => {
        modalResolver = resolve;
    });
}

function closeSecureModal(confirmed) {
    const pin = document.getElementById('modal-pass').value;
    const message = document.getElementById('modal-msg').value;

    if (confirmed) {
        if (pin.length !== 6 || isNaN(pin)) {
            showToast("Mã PIN phải đúng 6 chữ số.", 'warning');
            return;
        }
    }

    document.getElementById('secure-modal').style.display = 'none';
    if (modalResolver) {
        modalResolver(confirmed ? { pin, message } : null);
        modalResolver = null;
    }
}

async function fulfillRequest(txId, amount, requester) {
    const defaultMsg = `Thanh toán yêu cầu cho ${requester}`;
    const result = await showSecureModal(
        `Confirm Payment`,
        requester,
        amount,
        defaultMsg
    );

    if (!result || !result.pin) return;

    try {
        const response = await fetch(`${API_BASE}/api/transactions/requests/fulfill/${txId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                payment_pin: result.pin
            })
        });

        if (response.ok) {
            showToast(`Đã thanh toán ฿${amount} cho "${requester}" thành công!`, 'success');
            refreshAppData();
        } else {
            const err = await response.json();
            const detail = err.detail || "Xác minh thất bại";
            // Show the backend message directly — it already has proper Vietnamese text
            showToast(detail, 'error');
        }
    } catch (e) {
        showToast("Lỗi kết nối. Vui lòng thử lại.", 'error');
    }
}

async function fetchBalance() {
    try {
        const response = await fetch(`${API_BASE}/api/wallet/balance`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await response.json();
        const balanceEl = document.querySelector('.card-balance');
        if (balanceEl) {
            balanceEl.innerText = `฿ ${data.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}`;
        }
    } catch (e) {
        console.error("Balance fetch failed");
    }
}

async function fetchTransactions() {
    try {
        const response = await fetch(`${API_BASE}/api/transactions/history`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const txs = await response.json();

        // Populate Recent List (Home)
        const recentList = document.getElementById('recent-tx-list');
        const fullList = document.getElementById('full-tx-list');

        const renderTx = (tx) => {
            const div = document.createElement('div');
            div.className = 'card-white';
            div.style = 'display: flex; align-items: center; gap: 1rem; padding: 1rem; margin-bottom: 0.75rem;';

            let icon, color, prefix, amountText;

            if (tx.tx_status === "Requested") {
                icon = '⌛'; // Pending icon
                color = '#94a3b8'; // Slate/Grey for pending
                prefix = '';
                amountText = 'Pending';
            } else {
                icon = tx.is_sender ? '📤' : '📥';
                color = tx.is_sender ? '#ef4444' : '#10b981';
                prefix = tx.is_sender ? '-' : '+';
                amountText = `${prefix}฿${tx.amount}`;
            }

            div.innerHTML = `
                <div style="width: 40px; height: 40px; background: #f1f5f9; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">${icon}</div>
                <div style="flex: 1;">
                    <div style="font-weight: 600; font-size: 0.9rem;">${tx.is_sender ? 'To: ' + tx.receiver_username : 'From: ' + tx.sender_username}</div>
                    <div style="font-size: 0.75rem; color: var(--text-muted);">${new Date(tx.timestamp).toLocaleDateString()} ${new Date(tx.timestamp).toLocaleTimeString()}</div>
                </div>
                <div style="font-weight: 700; color: ${color}">${amountText}</div>
            `;
            return div;
        };

        if (recentList) {
            recentList.innerHTML = '';
            if (txs.length === 0) {
                recentList.innerHTML = `
                <div class="card-white" style="display: flex; align-items: center; gap: 1rem; padding: 1rem;">
                    <div style="width: 40px; height: 40px; background: #f1f5f9; border-radius: 50%; display: flex; align-items: center; justify-content: center;">👤</div>
                    <div style="flex: 1;">
                        <div style="font-weight: 600; font-size: 0.9rem;">No transactions yet</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">Start by sending some ฿</div>
                    </div>
                </div>`;
            } else {
                txs.slice(0, 3).forEach(tx => {
                    recentList.appendChild(renderTx(tx));
                });
            }
        }

        if (fullList) {
            fullList.innerHTML = '';
            if (txs.length === 0) {
                fullList.innerHTML = '<div class="card-white" style="text-align: center; color: var(--text-muted); padding: 2rem;">No transaction history found.</div>';
            } else {
                txs.forEach(tx => {
                    fullList.appendChild(renderTx(tx));
                });
            }
        }
    } catch (e) {
        console.error("Transaction fetch failed");
    }
}

async function fetchLogs() {
    try {
        const response = await fetch(`${API_BASE}/api/logs`);
        const logs = await response.json();
        const container = document.getElementById('log-container');

        container.innerHTML = '';

        if (logs.length === 0) {
            container.innerHTML = '<div class="log-entry">No security events recorded.</div>';
            return;
        }

        logs.forEach(log => {
            const div = document.createElement('div');
            div.className = 'log-entry' + (['REPLAY', 'TAMPER', 'FORGERY'].includes(log.event_type) ? ' log-critical' : '');

            const time = new Date(log.timestamp).toLocaleTimeString();
            div.innerHTML = `[${time}] ${log.event_type}: ${log.description}`;
            container.appendChild(div);
        });
    } catch (e) {
        console.error("Log fetch failed");
    }
}

// Polling for data
setInterval(refreshAppData, 5000);

// SECURITY TESTING CENTER LOGIC
async function runBenchmark() {
    const btn = document.getElementById('btn-run-benchmark');
    const resultsDiv = document.getElementById('benchmark-results');

    btn.innerText = "Running Security Profile...";
    btn.disabled = true;
    resultsDiv.style.display = 'none';

    try {
        const response = await fetch(`${API_BASE}/api/test/benchmark`);
        const data = await response.json();

        document.getElementById('bench-pbkdf2').innerText = data.pbkdf2_time + "s";
        document.getElementById('bench-ecdh').innerText = data.ecdh_time + "s";
        document.getElementById('bench-aes').innerText = data.aes_gcm_time_1mb + "s";

        resultsDiv.style.display = 'block';
    } catch (e) {
        showToast("Benchmark thất bại. Kiểm tra kết nối server.", 'error');
    } finally {
        btn.innerText = "Run Performance Profile";
        btn.disabled = false;
    }
}

async function simulateAttack(type) {
    if (!confirm(`Trigger ${type} Attack simulation? This will attempt to break security protocols on the latest transaction.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/test/attack?type=${type}`, {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            // This case should technically only happen if the attack succeeded (which is bad for security)
            showToast("⚠️ CẢNH BÁO: " + data.msg, 'warning');
        } else {
            // 400 or 500 errors mean the attack was caught or something went wrong
            showToast("🛡️ BẢO MẬT: " + (data.detail || "Tấn công bị chặn thành công."), 'success');
        }

        fetchLogs(); // Refresh logs to show the detection
    } catch (e) {
        showToast("Không thể kết nối tới server để mô phỏng tấn công.", 'error');
    }
}

// --- SYSTEM ADMINISTRATION LOGIC ---
async function loadAdminPanel() {
    const tableDiv = document.getElementById('admin-users-table');
    tableDiv.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 1rem;">Loading security directory...</td></tr>';

    try {
        const res = await fetch(`${API_BASE}/api/admin/users`);
        const data = await res.json();

        tableDiv.innerHTML = '';
        data.users.forEach(u => {
            let bruteStatus = u.locked_until ? `<span style="color:red; font-weight:600">LOCKED</span>` : (u.failed_login_count > 0 ? `<span style="color:orange; font-weight:600">${u.failed_login_count} Fails</span>` : `<span style="color:green; font-weight:600">Safe</span>`);
            let keyStatus = u.keys_revoked ? `<span style="color:red; font-weight:600">Revoked</span>` : `<span style="color:green; font-weight:600">${u.keys_status}</span>`;

            tableDiv.innerHTML += `
            <tr style="border-bottom: 1px solid #f1f5f9;">
                <td style="padding: 0.5rem 1rem;"><strong>${u.username}</strong><br><small style="color:var(--text-muted)">Role: ${u.role}</small></td>
                <td style="padding: 0.5rem 1rem;">${bruteStatus}</td>
                <td style="padding: 0.5rem 1rem;">${keyStatus}</td>
                <td style="padding: 0.5rem 1rem; white-space: nowrap;">
                    <button class="btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; margin-right: 0.5rem;" onclick="adminUnlockUser('${u.id}')">Unlock</button>
                    <button class="btn-primary" style="padding: 0.2rem 0.5rem; font-size: 0.7rem; background: var(--danger); border-color: var(--danger);" onclick="adminRevokeKeys('${u.id}')">Revoke</button>
                </td>
            </tr>
            `;
        });
    } catch (e) {
        tableDiv.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 1rem; color:red;">Failed to retrieve admin data. Secure Backend Offline?</td></tr>';
    }
}

async function adminUnlockUser(id) {
    if (!confirm('Xác nhận: Gỡ khóa chặn và reset số lần sai mật khẩu cho tài khoản này?')) return;
    try {
        await fetch(`${API_BASE}/api/admin/unlock/${id}`, { method: 'POST' });
        loadAdminPanel();
    } catch (e) { showToast("Lỗi khi thực thi lệnh Admin.", 'error'); }
}

async function adminRevokeKeys(id) {
    if (!confirm('NGUY HIỂM: Bạn có chắc chắn muốn thu hồi Cặp khóa Mã hóa của người này?')) return;
    try {
        await fetch(`${API_BASE}/api/admin/revoke/${id}`, { method: 'POST' });
        loadAdminPanel();
    } catch (e) { showToast("Lỗi khi thực thi lệnh Admin.", 'error'); }
}

// --- PASSWORD RECOVERY LOGIC ---
async function requestOTP() {
    const username = document.getElementById('recovery-username').value;
    if (!username) {
        showToast("Vui lòng nhập tên đăng nhập trước.", 'warning');
        return;
    }
    try {
        const response = await fetch(`${API_BASE}/api/auth/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username })
        });
        const data = await response.json();
        showToast(data.msg + " – Kiểm tra Terminal để lấy mã OTP!", 'info', 8000);
    } catch (e) {
        showToast("Lỗi kết nối khi gửi yêu cầu đặt lại mật khẩu.", 'error');
    }
}

async function confirmPasswordReset() {
    const username = document.getElementById('recovery-username').value;
    const otp = document.getElementById('recovery-otp').value;
    const newPassword = document.getElementById('recovery-new-password').value;

    if (!username || !otp || !newPassword) {
        showToast("Vui lòng điền đầy đủ Username, mã OTP và Mật khẩu mới.", 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/auth/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                otp_code: otp,
                new_password: newPassword
            })
        });

        if (response.ok) {
            const data = await response.json();
            showToast(data.msg, 'success');

            // Clear inputs & switch to auth view
            document.getElementById('recovery-username').value = '';
            document.getElementById('recovery-otp').value = '';
            document.getElementById('recovery-new-password').value = '';
            switchView('auth');
        } else {
            const err = await response.json();
            showToast("Lỗi: " + (err.detail || "Không thể khôi phục mật khẩu."), 'error');
        }
    } catch (e) {
        showToast("Lỗi kết nối với Security Core.", 'error');
    }
}

async function changePassword() {
    const oldPassword = document.getElementById('settings-old-pass').value;
    const newPassword = document.getElementById('settings-new-pass').value;

    if (!oldPassword || !newPassword) {
        showToast("Vui lòng nhập mật khẩu cũ và mật khẩu mới.", 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/auth/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                old_password: oldPassword,
                new_password: newPassword
            })
        });

        if (response.ok) {
            const data = await response.json();
            showToast(data.msg, 'success');
            document.getElementById('settings-old-pass').value = '';
            document.getElementById('settings-new-pass').value = '';
        } else {
            const err = await response.json();
            showToast("Lỗi: " + (err.detail || "Không thể cập nhật mật khẩu."), 'error');
        }
    } catch (e) {
        showToast("Lỗi kết nối với Security Core.", 'error');
    }
}
