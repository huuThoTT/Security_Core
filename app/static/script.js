// State
let currentUser = null;
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
            currentUser = await response.json();
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
            currentUser = await response.json();
            loginSuccess();
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
    document.getElementById('main-nav').style.display = 'flex';
    
    // Set Profile
    document.getElementById('display-username').innerText = currentUser.username;
    document.getElementById('user-avatar').innerText = currentUser.username[0].toUpperCase();
    
    // Switch to Home
    switchView('home');
    fetchLogs();
}

async function sendTransfer() {
    const receiver = document.getElementById('tx-receiver').value;
    const amount = document.getElementById('tx-amount').value;
    const msg = document.getElementById('tx-msg').value;
    const pass = document.getElementById('tx-pass').value;

    if (!receiver || !amount || !pass) {
        alert("Please fill in the transfer details.");
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                receiver_username: receiver,
                amount: parseFloat(amount),
                message: msg,
                passphrase: pass
            })
        });

        if (response.ok) {
            alert("Transfer Signed & Encrypted Successfully! ✅");
            switchView('home');
            fetchLogs();
        } else {
            const err = await response.json();
            alert("Security Alert: Transaction Blocked! ❌\n" + err.detail);
            fetchLogs();
        }
    } catch (e) {
        alert("Transaction failed. System busy.");
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

// Polling for logs
setInterval(fetchLogs, 5000);

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
