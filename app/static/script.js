async function registerUser() {
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;

    if (!username || !password) {
        alert("Please enter both username and password.");
        return;
    }

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            alert("Security Core Initialized! Keys generated successfully.");
            fetchLogs();
        } else {
            const err = await response.json();
            alert("Error: " + err.detail);
        }
    } catch (e) {
        console.error(e);
        alert("Server connection failed.");
    }
}

async function sendTransfer() {
    const receiver = document.getElementById('tx-receiver').value;
    const amount = document.getElementById('tx-amount').value;
    const msg = document.getElementById('tx-msg').value;
    const pass = document.getElementById('tx-pass').value;

    if (!receiver || !amount || !pass) {
        alert("Please fill all required fields.");
        return;
    }

    try {
        const response = await fetch('/api/transfer', {
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
            alert("Transaction Signed & Encrypted! Envelope saved to database.");
            fetchLogs();
        } else {
            const err = await response.json();
            alert("Security Alert: " + err.detail);
            fetchLogs(); // Refresh logs to see the alert
        }
    } catch (e) {
        console.error(e);
        alert("Transaction failed.");
    }
}

async function fetchLogs() {
    try {
        const response = await fetch('/api/logs');
        const logs = await response.json();
        const container = document.getElementById('log-container');
        const alertCount = document.getElementById('alert-count');
        
        container.innerHTML = '';
        alertCount.innerText = logs.length;

        logs.forEach(log => {
            const div = document.createElement('div');
            div.className = 'log-item' + (log.event_type !== 'INFO' ? ' log-critical' : '');
            
            const time = new Date(log.timestamp).toLocaleTimeString();
            div.innerHTML = `<strong>[${time}] ${log.event_type}</strong>: ${log.description}`;
            container.appendChild(div);
        });
    } catch (e) {
        console.error("Failed to fetch logs", e);
    }
}

// Initial fetch and start polling
fetchLogs();
setInterval(fetchLogs, 3000);
