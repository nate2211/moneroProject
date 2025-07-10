    const modal = document.getElementById('startMinerModal');
    const form = document.getElementById('startMinerForm');
    function openStartModal(clientId) {
        form.action = '/start_miner/' + clientId;
        modal.style.display = 'block';
    }
    function closeStartModal() {
        modal.style.display = 'none';
    }
    window.onclick = function(event) {
        if (event.target == modal) {
            closeStartModal();
        }
    }

    // NEW: JavaScript function to handle the stop command
    function stopMiner(clientId) {
        if (!confirm(`Are you sure you want to stop miner: ${clientId}?`)) {
            return;
        }
        fetch(`/stop_miner/${clientId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            console.log(data.message);
            // Reload the page to see the updated status
            window.location.reload();
        })
        .catch(error => {
            console.error('Error stopping miner:', error);
            alert('Failed to stop the miner.');
        });
    }
        function connectToWifi() {
        const ssid = document.getElementById('wifi-ssid').value.trim();
        const password = document.getElementById('wifi-password').value.trim();

        if (!ssid || !password) {
            alert("Please enter both Wi-Fi SSID and Password.");
            return;
        }

        if (!confirm(`Attempt to connect to Wi-Fi network "${ssid}"? This might temporarily disconnect your current connection.`)) {
            return;
        }

        const connectBtn = document.querySelector('#wifi-ssid ~ button'); // Select the connect button
        connectBtn.disabled = true;
        connectBtn.textContent = 'Connecting...';

        fetch('/connect_wifi', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ssid: ssid, password: password })
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            console.log(data.message);
        })
        .catch(error => {
            console.error('Error connecting to Wi-Fi:', error);
            alert('Failed to connect to Wi-Fi. Check console for details and ensure the script has administrative privileges.');
        })
        .finally(() => {
            connectBtn.disabled = false;
            connectBtn.textContent = 'Connect';
            // You might want to automatically refresh status or wait a bit
            // and then check connectivity
            // setTimeout(fetchStatus, 5000);
        });
    }

    function restartP2Pool() {
    if (!confirm("Are you sure you want to restart P2Pool? This will temporarily stop mining.")) {
        return;
    }

    const restartBtn = document.getElementById('restart-p2pool-btn');
    restartBtn.disabled = true;
    restartBtn.textContent = 'Restarting...';

    fetch('/restart_p2pool', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        console.log(data.message);
        // You might want to automatically fetch status after a short delay
        // to see the new P2Pool status
        setTimeout(fetchStatus, 3000); // Fetch status after 3 seconds
    })
    .catch(error => {
        console.error('Error restarting P2Pool:', error);
        alert('Failed to restart P2Pool. Check console for details.');
    })
    .finally(() => {
        restartBtn.disabled = false;
        restartBtn.textContent = 'Restart P2Pool';
    });
}

function renderStatus(data) {
    const container = document.getElementById('status-container');
    container.innerHTML = ''; // Clear previous content

    if (data.error || data.message) {
        container.innerHTML = `<div class="status-section"><p>${data.error || data.message}</p></div>`;
        return;
    }

    const sectionTitles = {
        sidechain: "SideChain Status",
        stratum: "Stratum Server Status",
        p2p: "P2P Server Status"
    };

    for (const sectionKey in data) {
        const sectionData = data[sectionKey];
        if (Object.keys(sectionData).length === 0) continue;

        const sectionDiv = document.createElement('div');
        sectionDiv.className = 'status-section';

        const title = document.createElement('h3');
        title.textContent = sectionTitles[sectionKey] || sectionKey;
        sectionDiv.appendChild(title);

        const gridDiv = document.createElement('div');
        gridDiv.className = 'status-grid';

        for (const key in sectionData) {
            const keySpan = document.createElement('span');
            keySpan.className = 'key';
            keySpan.textContent = key;

            const valueSpan = document.createElement('span');
            valueSpan.className = 'value';
            valueSpan.textContent = sectionData[key];

            gridDiv.appendChild(keySpan);
            gridDiv.appendChild(valueSpan);
        }

        sectionDiv.appendChild(gridDiv);
        container.appendChild(sectionDiv);
    }
}

function fetchStatus() {
    const statusBtn = document.getElementById('status-btn');
    const container = document.getElementById('status-container');

    statusBtn.disabled = true;
    statusBtn.textContent = 'Fetching...';

    fetch('/status', { method: 'POST' })
        .then(response => {
            if (!response.ok) {
                // If response is not OK, try to read error message from body
                return response.json().then(errorData => {
                    throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
                });
            }
            return response.json(); // Expect a JSON response
        })
        .then(data => {
            renderStatus(data); // Render the data into a beautiful table
        })
        .catch(error => {
            renderStatus({ error: "Failed to fetch or parse status. " + error.message });
        })
        .finally(() => {
            statusBtn.disabled = false;
            statusBtn.textContent = 'Get Status';
        });
}
function updateClientDashboard() {
    fetch("/api/clients")
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector("table tbody");
            if (!tbody) return;

            tbody.innerHTML = ""; // Clear current rows

            const keys = Object.keys(data.hashrates);
            if (keys.length === 0) {
                tbody.innerHTML = `<tr><td colspan="10" style="text-align: center;" class="text-muted">No clients have connected yet.</td></tr>`;
                return;
            }

            keys.forEach(cid => {
                const row = document.createElement("tr");
                const hashrate = data.hashrates[cid]?.toFixed(2) || "0.00";
                const temp = data.temps[cid] || "N/A";
                const threads = data.threads[cid] || "N/A";
                const power = data.power_draws[cid] || "N/A";
                const cost = data.costs[cid]?.toFixed(4) || "0.0000";
                const lastSeen = data.last_seen[cid] || "N/A";
                const cpuShares = data.cpu_shares[cid] || 0;
                const gpuShares = data.nvidia_shares[cid] || 0;
                const gpuTemp = data.gpu_stats[cid]?.temp || "N/A";
                const gpuFan = data.gpu_stats[cid]?.fan || "N/A";
                const job = data.newjobs[cid] || {};

                row.innerHTML = `
                    <td><span class="status-online">●</span> ${cid}</td>
                    <td><strong>${hashrate} H/s</strong></td>
                    <td>${temp}</td>
                    <td>${threads}</td>
                    <td>${power}</td>
                    <td>$${cost}</td>
                    <td>${lastSeen}</td>
                    <td>${cpuShares} / ${gpuShares}</td>
                    <td>${gpuTemp} | ${gpuFan}</td>
                    <td>${job.difficulty || '—'}</td>
                    <td>${job.height || '—'}</td>
                    <td>${job.algo || '—'}</td>
                    <td>${job.tx_count || '—'}</td>
                    <td>${job.ip || '—'}</td>
                    <td>
                        <form action="/set_threads/${cid}" method="post">
                            <input type="number" name="threads" min="1" placeholder="${threads}" required>
                            <button type="submit">Set</button>
                        </form>
                    </td>
                    <td>
                        ${data.status[cid] === 'Started'
                            ? `<button class="action-button stop" onclick="stopMiner('${cid}')">Stop</button>`
                            : `<button class="action-button" onclick="openStartModal('${cid}')">Start</button>`}
                    </td>
                `;
                tbody.appendChild(row);
            });
        })
        .catch(err => {
            console.error("Failed to update dashboard:", err);
        });
}

setInterval(updateClientDashboard, 5000); // Poll every 5 seconds
// Initial render for the placeholder message
