// State
let currentUser = null;
let currentToken = null;
let authMode = 'login';
// API Base configuration for cross-origin development (e.g., Live Server on 5501)
const API_BASE = (window.location.port === '5501' || window.location.port === '5500') 
    ? 'http://127.0.0.1:8000' 
    : '';

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
    } else {
        title.innerText = 'Initialize Wallet';
        btn.innerText = 'Create Secure Wallet';
        desc.innerText = 'Your keys will be protected by 600K PBKDF2 rounds.';
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
}

// Actions
async function loginUser() {
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;

    if (!username || !password) {
        alert("Enter your credentials to unlock your wallet.");
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
            alert("Security Portal: " + (err.detail || "Authentication Failed."));
        }
    } catch (e) {
        alert("Security core connection lost.");
    }
}

async function registerUser() {
    const username = document.getElementById('auth-username').value;
    const password = document.getElementById('auth-password').value;

    if (!username || !password) {
        alert("Enter a username and password to create your secure wallet.");
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();
            
            // Populate 2FA elements
            if(data.totp_secret) {
                 document.getElementById('totp-secret-text').innerText = data.totp_secret;
                 document.getElementById('totp-qr').src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(data.totp_uri)}`;
            } else {
                 document.getElementById('totp-qr').style.display = 'none';
                 document.getElementById('totp-secret-text').innerText = "2FA Not Configured";
            }
            // Navigate to Setup View
            switchView('setup');

        } else {
            const err = await response.json();
            alert("Registration failed: " + err.detail);
        }
    } catch (e) {
        alert("Could not connect to the security core.");
    }
}

function loginSuccess() {
    // UI Transitions
    document.getElementById('view-auth').style.display = 'none';
    document.getElementById('app-header').style.display = 'flex';
    
    // Set Profile
    document.getElementById('display-username').innerText = currentUser.username;
    
    // Admin vs Normal User Interface Routing
    if (currentUser.role === 'Admin') {
        document.getElementById('user-avatar').innerText = '👮';
        document.getElementById('main-nav').style.display = 'none';
        switchView('admin');
    } else {
        document.getElementById('user-avatar').innerText = currentUser.username[0].toUpperCase();
        document.getElementById('main-nav').style.display = 'flex';
        switchView('home');
    }
    
    refreshAppData();
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

async function sendTransfer() {
    const receiver = document.getElementById('tx-receiver').value;
    const amount = document.getElementById('tx-amount').value;
    const msg = document.getElementById('tx-msg').value;
    const pass = document.getElementById('tx-pass').value;
    const btn = document.getElementById('btn-transfer');

    if (!receiver || !amount || !pass) {
        alert("Please fill in the transfer details.");
        return;
    }

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
                passphrase: pass
            })
        });

        if (response.ok) {
            alert("Transfer Signed & Encrypted Successfully! ✅");
            
            // Clear Inputs
            document.getElementById('tx-receiver').value = '';
            document.getElementById('tx-amount').value = '';
            document.getElementById('tx-msg').value = '';
            document.getElementById('tx-pass').value = '';
            if(document.getElementById('tx-2fa')) document.getElementById('tx-2fa').value = '';

            switchView('home');
            refreshAppData();
        } else {
            const err = await response.json();
            alert("Security Alert: Transaction Blocked! ❌\n" + (err.detail || "Error"));
            refreshAppData();
        }
    } catch (e) {
        alert("Transaction failed. System busy.");
    } finally {
        // Re-enable button
        btn.disabled = false;
        btn.innerText = "Sign & Send Securely";
    }
}

async function refreshAppData() {
    fetchBalance();
    fetchTransactions();
    fetchLogs();
}

async function fetchBalance() {
    try {
        const response = await fetch(`${API_BASE}/api/wallet/balance`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });
        const data = await response.json();
        const balanceEl = document.querySelector('.card-balance');
        if (balanceEl) {
            balanceEl.innerText = `฿ ${data.balance.toLocaleString('en-US', {minimumFractionDigits: 2})}`;
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
                    const div = document.createElement('div');
                    div.className = 'card-white';
                    div.style = 'display: flex; align-items: center; gap: 1rem; padding: 1rem; margin-bottom: 0.75rem;';
                    const icon = tx.is_sender ? '📤' : '📥';
                    const color = tx.is_sender ? '#ef4444' : '#10b981';
                    const prefix = tx.is_sender ? '-' : '+';
                    
                    div.innerHTML = `
                        <div style="width: 40px; height: 40px; background: #f1f5f9; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">${icon}</div>
                        <div style="flex: 1;">
                            <div style="font-weight: 600; font-size: 0.9rem;">${tx.is_sender ? 'To: ' + tx.receiver_username : 'From: ' + tx.sender_username}</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">${new Date(tx.timestamp).toLocaleDateString()}</div>
                        </div>
                        <div style="font-weight: 700; color: ${color}">${prefix}฿${tx.amount}</div>
                    `;
                    recentList.appendChild(div);
                });
            }
        }

        // Populate Full History (History Tab) - Reusing log-container or separate
        // Let's keep them separate in the UI for clarity if possible, but for now I'll inject at top of logs or similar.
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
        alert("Benchmark failed. Check backend connectivity.");
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
            alert("⚠️ WARNING: " + data.msg);
        } else {
            // 400 or 500 errors mean the attack was caught or something went wrong
            alert("🛡️ SECURED: " + (data.detail || "Attack intercepted by Security Core."));
        }
        
        fetchLogs(); // Refresh logs to show the detection
    } catch (e) {
        alert("Attack simulation failed to reach server.");
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
    } catch(e) {
        tableDiv.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 1rem; color:red;">Failed to retrieve admin data. Secure Backend Offline?</td></tr>';
    }
}

async function adminUnlockUser(id) {
    if(!confirm('Xác nhận: Gỡ khóa chặn và reset số lần sai mật khẩu cho tài khoản này?')) return;
    try {
        await fetch(`${API_BASE}/api/admin/unlock/${id}`, { method: 'POST' });
        loadAdminPanel();
    } catch(e) { alert("Failed to execute admin command."); }
}

async function adminRevokeKeys(id) {
    if(!confirm('NGUY HIỂM: Bạn có chắc chắn muốn thu hồi Cặp khóa Mã hóa của người này?')) return;
    try {
        await fetch(`${API_BASE}/api/admin/revoke/${id}`, { method: 'POST' });
        loadAdminPanel();
    } catch(e) { alert("Failed to execute admin command."); }
}
