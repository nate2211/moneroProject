import React, { useState, useEffect, useCallback } from 'react';
import './App.css'; // Make sure to have styles for .container, table, .modal etc.

function App() {
  // State for all dynamic data
  const [p2poolStatus, setP2poolStatus] = useState(null);
  const [systemTotals, setSystemTotals] = useState({});
  const [clients, setClients] = useState({});
  const [events, setEvents] = useState({});

  // State for UI interactions
  const [loading, setLoading] = useState({});
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalClientId, setModalClientId] = useState('');
  const [wifi, setWifi] = useState({ ssid: 'ARRIS-7D41-5G', password: '' });
  const [startMinerForm, setStartMinerForm] = useState({ pool: '', threads: '' });
  const [threadInputs, setThreadInputs] = useState({});


  // === API Abstraction ===
  const apiCall = async (endpoint, options = {}) => {
    setLoading(prev => ({ ...prev, [endpoint]: true }));
    try {
      const response = await fetch(endpoint, options);
      if (!response.ok) {
        const errData = await response.json().catch(() => ({ message: `HTTP Error: ${response.status}` }));
        throw new Error(errData.message || 'An unknown error occurred.');
      }
      return await response.json();
    } catch (error) {
      alert(`Error with ${endpoint}: ${error.message}`);
      console.error(`Error with ${endpoint}:`, error);
      throw error; // re-throw to handle in specific functions if needed
    } finally {
      setLoading(prev => ({ ...prev, [endpoint]: false }));
    }
  };

  // === Data Fetching ===
  const fetchData = useCallback(async () => {
    try {
      const [totalsData, clientsData, eventsData] = await Promise.all([
        apiCall('/api/totals'),
        apiCall('/api/clients'),
        apiCall('/api/events'),
      ]);
      setSystemTotals(totalsData);
      setClients(clientsData);
      setEvents(eventsData);
    } catch (error) {
      console.error("Failed to fetch primary dashboard data:", error);
    }
  }, []);

  useEffect(() => {
    fetchData(); // Fetch initial data
    const intervalId = setInterval(fetchData, 5000); // Refresh every 5 seconds
    return () => clearInterval(intervalId); // Cleanup on unmount
  }, [fetchData]);


  // === Event Handlers ===
  const handleFetchStatus = async () => {
    const statusData = await apiCall('/status', { method: 'POST' });
    if (statusData) setP2poolStatus(statusData);
  };

  const handleRestartP2Pool = async () => {
    if (window.confirm("Are you sure you want to restart P2Pool?")) {
      await apiCall('/restart_p2pool', { method: 'POST' });
      setTimeout(handleFetchStatus, 3000); // Re-fetch status after a delay
    }
  };

  const handleConnectToWifi = async (e) => {
    e.preventDefault();
    if (!wifi.ssid || !wifi.password) return alert("SSID and Password are required.");
    if (window.confirm(`Attempt to connect to Wi-Fi network "${wifi.ssid}"?`)) {
        await apiCall('/connect_wifi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wifi),
      });
    }
  };

  const handleStopMiner = async (clientId) => {
    if (window.confirm(`Are you sure you want to stop miner: ${clientId}?`)) {
      await apiCall(`/stop_miner/${clientId}`, { method: 'POST' });
      fetchData(); // Refresh data
    }
  };

  const handleUpdateClient = async (clientId) => {
    if (window.confirm(`Are you sure you want to update client: ${clientId}?`)) {
        await apiCall(`/update_client/${clientId}`, { method: 'POST' });
        fetchData(); // Refresh data
    }
  };

  const handleSetThreads = async (e, clientId) => {
    e.preventDefault();
    const threads = threadInputs[clientId];
    if (!threads || threads < 1) return alert("Please enter a valid thread count.");

    const formData = new FormData();
    formData.append('threads', threads);

    await apiCall(`/set_threads/${clientId}`, { method: 'POST', body: formData });
    fetchData();
  };

  const handleStartMiner = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append('pool', startMinerForm.pool);
    formData.append('threads', startMinerForm.threads);

    await apiCall(`/start_miner/${modalClientId}`, { method: 'POST', body: formData });
    setIsModalOpen(false);
    fetchData();
  };

  // === UI Helpers ===
  const openStartModal = (clientId) => {
    setModalClientId(clientId);
    setStartMinerForm({ pool: '', threads: '' });
    setIsModalOpen(true);
  };

  const renderStatus = (data) => {
    if (!data) return null;
    if (data.error || data.message) return <p>{data.error || data.message}</p>;

    const titles = { sidechain: "SideChain Status", stratum: "Stratum Server Status", p2p: "P2P Server Status" };
    return Object.entries(data).map(([sectionKey, sectionData]) => (
      Object.keys(sectionData).length > 0 && (
        <div key={sectionKey} className="status-section">
          <h3>{titles[sectionKey] || sectionKey}</h3>
          <div className="status-grid">
            {Object.entries(sectionData).map(([key, value]) => (
              <React.Fragment key={key}>
                <span className="key">{key}</span>
                <span className="value">{value}</span>
              </React.Fragment>
            ))}
          </div>
        </div>
      )
    ));
  };

  const EventTable = ({ title, events = [] }) => (
    <>
      <h2>{title}</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            {events[0] && events[0].type && <th>Type</th>}
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {events.length > 0 ? (
            events.map((event, index) => (
              <tr key={index}>
                <td>{event.time}</td>
                {event.type && <td>{event.type}</td>}
                <td><pre>{event.message}</pre></td>
              </tr>
            ))
          ) : (
            <tr><td colSpan="3">No events to show.</td></tr>
          )}
        </tbody>
      </table>
    </>
  );

  return (
    <div className="container">
      <h2>P2Pool Status</h2>
      <button onClick={handleFetchStatus} disabled={loading['/status']}>
        {loading['/status'] ? 'Fetching...' : 'Get Status'}
      </button>
      <div id="status-container">{renderStatus(p2poolStatus)}</div>

      <h2>System Totals</h2>
      <table>
        <tbody>
            <tr><th>Total Hashrate</th><td>{systemTotals.total_hashrate?.toFixed(2) || 'N/A'} H/s</td></tr>
            <tr><th>Total CPU Shares</th><td>{systemTotals.total_cpu_shares || 'N/A'}</td></tr>
            <tr><th>Total GPU Shares</th><td>{systemTotals.total_gpu_shares || 'N/A'}</td></tr>
            <tr><th>Total Power Draw</th><td>{systemTotals.total_power_draw || 'N/A'} W</td></tr>
            <tr><th>Total Cost</th><td>${systemTotals.total_cost?.toFixed(4) || 'N/A'}</td></tr>
            <tr><th>Average CPU Temp</th><td>{systemTotals.total_temp || 'N/A'}°C</td></tr>
        </tbody>
      </table>

      <h2>Client Dashboard</h2>
      <table>
        <thead>
          <tr>
            <th>Client ID</th><th>Hashrate</th><th>CPU Temp</th><th>Threads</th>
            <th>Power Draw</th><th>Cost</th><th>Last Seen</th><th>Shares (CPU/GPU)</th>
            <th>GPU Stats</th><th>Job Difficulty</th><th>Job Height</th><th>Algo</th>
            <th>TXs</th><th>Pool IP</th><th>Set Threads</th><th>Control Pool</th><th>Update</th>
          </tr>
        </thead>
        <tbody>
          {clients.hashrates && Object.keys(clients.hashrates).length > 0 ? (
            Object.keys(clients.hashrates).map(cid => (
              <tr key={cid}>
                <td><span className={clients.status?.[cid] === 'Started' ? 'status-online' : 'status-offline'}>●</span> {cid}</td>
                <td><strong>{clients.hashrates?.[cid]?.toFixed(2) || 'N/A'} H/s</strong></td>
                <td>{clients.temps?.[cid] || 'N/A'}</td>
                <td>{clients.threads?.[cid] || 'N/A'}</td>
                <td>{clients.power_draws?.[cid] || 'N/A'} W</td>
                <td>${clients.costs?.[cid]?.toFixed(4) || '0.00'}</td>
                <td>{clients.last_seen?.[cid] || 'N/A'}</td>
                <td>{clients.cpu_shares?.[cid] || 0} / {clients.nvidia_shares?.[cid] || 0}</td>
                <td>{clients.gpu_stats?.[cid]?.temp || 'N/A'} | {clients.gpu_stats?.[cid]?.fan || 'N/A'}</td>
                <td>{clients.newjobs?.[cid]?.difficulty || '—'}</td>
                <td>{clients.newjobs?.[cid]?.height || '—'}</td>
                <td>{clients.newjobs?.[cid]?.algo || '—'}</td>
                <td>{clients.newjobs?.[cid]?.tx_count || '—'}</td>
                <td>{clients.newjobs?.[cid]?.ip || '—'}</td>
                <td>
                  <form onSubmit={(e) => handleSetThreads(e, cid)} className="form-inline">
                    <input type="number" min="1" placeholder={clients.threads?.[cid] || '1'} required
                           onChange={e => setThreadInputs({...threadInputs, [cid]: e.target.value})} />
                    <button type="submit">Set</button>
                  </form>
                </td>
                <td>
                  {clients.status?.[cid] === 'Started' ?
                    <button className="action-button stop" onClick={() => handleStopMiner(cid)}>Stop</button> :
                    <button className="action-button start" onClick={() => openStartModal(cid)}>Start</button>
                  }
                </td>
                <td><button className="action-button update" onClick={() => handleUpdateClient(cid)}>Update</button></td>
              </tr>
            ))
          ) : (
            <tr><td colSpan="17">No clients have connected yet.</td></tr>
          )}
        </tbody>
      </table>

      <EventTable title="Shares Found" events={events.shares_found} />
      <EventTable title="Blocks Found" events={events.blocks_found} />

      <h2>System Control</h2>
      <table>
        <tbody>
            <tr>
              <th>Restart P2Pool</th>
              <td>
                <button onClick={handleRestartP2Pool} disabled={loading['/restart_p2pool']}>
                  {loading['/restart_p2pool'] ? 'Restarting...' : 'Restart'}
                </button>
              </td>
            </tr>
            <tr>
              <th>Connect to Wi-Fi</th>
              <td>
                <form onSubmit={handleConnectToWifi} className="form-inline">
                  <input type="text" placeholder="Network SSID" value={wifi.ssid} onChange={e => setWifi({...wifi, ssid: e.target.value})} />
                  <input type="password" placeholder="Password" value={wifi.password} onChange={e => setWifi({...wifi, password: e.target.value})} />
                  <button type="submit" disabled={loading['/connect_wifi']}>{loading['/connect_wifi'] ? 'Connecting...' : 'Connect'}</button>
                </form>
              </td>
            </tr>
        </tbody>
      </table>

      <EventTable title="New Miner Data" events={events.miner_data} />
      <EventTable title="Jobs Sent" events={events.jobs_sent} />

      {isModalOpen && (
        <div className="modal">
          <div className="modal-content">
            <div className="modal-header">
              <span className="close-button" onClick={() => setIsModalOpen(false)}>&times;</span>
              <h3>Start Miner: {modalClientId}</h3>
            </div>
            <form onSubmit={handleStartMiner}>
              <div className="modal-body">
                <div className="form-group">
                  <label htmlFor="pool_url">Pool URL</label>
                  <input type="text" id="pool_url" name="pool" placeholder="e.g., 192.168.0.10:3333" required
                         value={startMinerForm.pool} onChange={e => setStartMinerForm({...startMinerForm, pool: e.target.value})} />
                </div>
                <div className="form-group">
                  <label htmlFor="threads">Threads</label>
                  <input type="number" id="threads" name="threads" min="1" placeholder="e.g., 4" required
                         value={startMinerForm.threads} onChange={e => setStartMinerForm({...startMinerForm, threads: e.target.value})} />
                </div>
              </div>
              <div className="modal-footer">
                <button type="submit" className="action-button">Send Start Command</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;