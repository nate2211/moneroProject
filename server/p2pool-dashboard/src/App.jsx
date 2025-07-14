import React, { useState, useEffect, useCallback } from 'react';
import {
    Container,
    Typography,
    Grid,
    Card,
    CardContent,
    Button,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    CircularProgress,
    TextField,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    ThemeProvider,
    createTheme,
    CssBaseline,
    Box,
    IconButton,
    Tooltip, Divider
} from '@mui/material';
import {
  RestartAlt,
  Wifi,
  PlayArrow,
  Stop,
  Update,
  Settings,
  Info,
  BarChart,
  Lan,
  Memory,
  Speed,
  Power,
  AttachMoney,
  Thermostat,
  Share,
  Dns,
  EventNote // Icon for Other Events
} from '@mui/icons-material';
import './App.css';

// A dark theme for the dashboard
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#bb86fc',
    },
    secondary: {
      main: '#03dac6',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e', // This ensures Paper components have a dark background
    },
    text: {
        primary: '#ffffff', // Ensures primary text is white
        secondary: '#b3b3b3', // Softer white for secondary text
    }
  },
  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: 'linear-gradient(rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.05))',
        },
      },
    },
  },
});

// Main App Component
function App() {
  // State for all dynamic data
  const [p2poolStatus, setP2poolStatus] = useState(null);
  const [systemTotals, setSystemTotals] = useState({});
  const [clients, setClients] = useState({});
  const [events, setEvents] = useState({});
  const [lastSeenData, setLastSeenData] = useState({});

  // State for UI interactions
  const [loading, setLoading] = useState({});
  const [isStartModalOpen, setIsStartModalOpen] = useState(false);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [confirmDialogContent, setConfirmDialogContent] = useState({ title: '', message: '', onConfirm: () => {} });

  const [modalClientId, setModalClientId] = useState('');
  const [wifi, setWifi] = useState({ ssid: 'ARRIS-7D41-5G', password: '535102108332' });
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
      console.error(`Error with ${endpoint}:`, error);
    } finally {
      setLoading(prev => ({ ...prev, [endpoint]: false }));
    }
  };

  // === Data Fetching ===
  const fetchData = useCallback(async () => {
    try {
      const [totalsData, clientsData, eventsData, lastSeenData] = await Promise.all([
        apiCall('/api/totals'),
        apiCall('/api/clients'),
        apiCall('/api/events'),
        apiCall('/api/lastseen')
      ]);
      if (totalsData) setSystemTotals(totalsData);
      if (clientsData) setClients(clientsData);
      if (eventsData) setEvents(eventsData);
      if (lastSeenData) setLastSeenData(lastSeenData);
    } catch (error) {
      console.error("Failed to fetch primary dashboard data:", error);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const intervalId = setInterval(fetchData, 5000);
    return () => clearInterval(intervalId);
  }, [fetchData]);

  // === Confirmation Dialog Logic ===
  const openConfirmDialog = (title, message, onConfirm) => {
    setConfirmDialogContent({ title, message, onConfirm });
    setConfirmDialogOpen(true);
  };

  const handleConfirm = () => {
    confirmDialogContent.onConfirm();
    setConfirmDialogOpen(false);
  };

  // === Event Handlers ===
  const handleFetchStatus = async () => {
    const statusData = await apiCall('/status', { method: 'POST' });
    if (statusData) setP2poolStatus(statusData);
  };

  const handleRestartP2Pool = () => {
    openConfirmDialog("Restart P2Pool?", "Are you sure you want to restart the P2Pool server process?", async () => {
        await apiCall('/restart_p2pool', { method: 'POST' });
        setTimeout(handleFetchStatus, 3000);
    });
  };

  const handleConnectToWifi = async (e) => {
    e.preventDefault();
    if (!wifi.ssid || !wifi.password) return;
    openConfirmDialog("Connect to Wi-Fi?", `Attempt to connect to network "${wifi.ssid}"?`, async () => {
        await apiCall('/connect_wifi', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(wifi),
        });
    });
  };

  const handleStopMiner = (clientId) => {
    openConfirmDialog("Stop Miner?", `Are you sure you want to stop miner: ${clientId}?`, async () => {
        await apiCall(`/stop_miner/${clientId}`, { method: 'POST' });
        fetchData();
    });
  };

  const handleUpdateClient = (clientId) => {
    openConfirmDialog("Update Client?", `Are you sure you want to update client: ${clientId}?`, async () => {
        await apiCall(`/update_client/${clientId}`, { method: 'POST' });
        fetchData();
    });
  };

  const handleSetThreads = async (e, clientId) => {
    e.preventDefault();
    const threads = threadInputs[clientId];
    if (!threads || threads < 1) return;
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
    setIsStartModalOpen(false);
    fetchData();
  };

  const openStartModal = (clientId) => {
    setModalClientId(clientId);
    setStartMinerForm({ pool: '', threads: '' });
    setIsStartModalOpen(true);
  };

  // === UI Helper Components ===
  const renderStatus = (data) => {
    if (!data) return <Typography variant="body2" color="text.secondary">Click 'Get Status' to load P2Pool details.</Typography>;
    if (data.error || data.message) return <Typography color="error">{data.error || data.message}</Typography>;

    const titles = { sidechain: "SideChain Status", stratum: "Stratum Server Status", p2p: "P2P Server Status" };
    return (
        <Grid container spacing={2} display={"flex"} justifyContent={"center"}>
            {Object.entries(data).map(([sectionKey, sectionData]) => (
                Object.keys(sectionData).length > 0 && (
                    <Grid item xs={12} md={4} key={sectionKey}>
                        <Typography variant="h6" gutterBottom>{titles[sectionKey] || sectionKey}</Typography>
                        <Paper elevation={3} sx={{ p: 1.5 }}>
                            {Object.entries(sectionData).map(([key, value]) => (
                                <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.1)', py: 0.5 }}>
                                    <Typography variant="body2" color="text.secondary">{key}</Typography>
                                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>{value}</Typography>
                                </Box>
                            ))}
                        </Paper>
                    </Grid>
                )
            ))}
        </Grid>
    );
  };

  const EventTable = ({ title, events = [] }) => (
    <Card sx={{ mb: 3 }}>
        <CardContent>
            <Typography variant="h5" component="div" gutterBottom>{title}</Typography>
            <TableContainer component={Paper}>
                <Table size="small">
                    <TableHead>
                        <TableRow sx={{ backgroundColor: 'rgba(255, 255, 255, 0.08)' }}>
                            <TableCell>Time</TableCell>
                            {events[0] && events[0].type && <TableCell>Type</TableCell>}
                            <TableCell>Message</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {events.length > 0 ? (
                            events.map((event, index) => (
                                <TableRow key={index} hover>
                                    <TableCell>{event.time}</TableCell>
                                    {event.type && <TableCell>{event.type}</TableCell>}
                                    <TableCell><pre>{event.message}</pre></TableCell>
                                </TableRow>
                            ))
                        ) : (
                            <TableRow><TableCell colSpan={3} align="center">No events to show.</TableCell></TableRow>
                        )}
                    </TableBody>
                </Table>
            </TableContainer>
        </CardContent>
    </Card>
  );

  const StatCard = ({ icon, title, value, unit }) => (
      <Grid item xs={6} sm={4} md={2}>
          <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                  <Box sx={{ color: 'primary.main', mb: 1 }}>{icon}</Box>
                  <Typography variant="h6">{value ?? 'N/A'}</Typography>
                  <Typography variant="caption" color="text.secondary">{title} {unit}</Typography>
              </CardContent>
          </Card>
      </Grid>
  );

  return (
    <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <div>
            <Typography variant="h3" gutterBottom component="h1" sx={{ fontWeight: 'bold', textAlign: 'center', mb: 4 }}>
                Miner Dashboard
            </Typography>

            <Card sx={{ mb: 3 }}>
                <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                        <Typography variant="h5" component="div">P2Pool Status</Typography>
                        <Button onClick={handleFetchStatus} startIcon={loading['/status'] ? <CircularProgress size={20} /> : <Info />}>
                            Get Status
                        </Button>
                    </Box>
                    {renderStatus(p2poolStatus)}
                </CardContent>
            </Card>

            <Card sx={{ mb: 3 }}>
                <CardContent>
                    <Typography variant="h5" component="div" gutterBottom>System Totals</Typography>
                    <Grid container spacing={2} justifyContent="center">
                        <StatCard icon={<Speed />} title="Total Hashrate" value={systemTotals.total_hashrate?.toFixed(2)} unit="H/s" />
                        <StatCard icon={<Share />} title="CPU Shares" value={systemTotals.total_cpu_shares} />
                        <StatCard icon={<Share />} title="GPU Shares" value={systemTotals.total_gpu_shares} />
                        <StatCard icon={<Power />} title="Total Power" value={systemTotals.total_power_draw} unit="W" />
                        <StatCard icon={<AttachMoney />} title="Total Cost" value={`$${systemTotals.total_cost?.toFixed(4) ?? 'N/A'}`} />
                        <StatCard icon={<Thermostat />} title="Avg CPU Temp" value={systemTotals.total_temp} unit="°C" />
                    </Grid>
                </CardContent>
            </Card>

            <Box sx={{ mb: 3 }} >
                <Typography variant="h5" component="div" gutterBottom textAlign={"center"}>Client Dashboard</Typography>
                <Grid container spacing={3} display={"flex"} justifyContent={"center"} flexWrap={"wrap"}>
                    {clients.hashrates && Object.keys(clients.hashrates).length > 0 ? (
                        Object.keys(clients.hashrates).map(cid => (
                            <Grid item xs={12} md={6} lg={4} key={cid}>
                                <Card sx={{ display: 'flex', flexDirection: 'column' }}>
                                    <CardContent sx={{ flexGrow: 1 }}>
                                        {/* Client Header */}
                                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                                                <Box component="span" sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: clients.status?.[cid] === 'Started' ? 'success.main' : 'error.main', boxShadow: `0 0 8px ${clients.status?.[cid] === 'Started' ? 'green' : 'red'}` }} />
                                                <Typography variant="h6" component="div" noWrap title={cid}>{cid}</Typography>
                                            </Box>
                                            <Button variant="outlined" color="secondary" size="small" onClick={() => handleUpdateClient(cid)} startIcon={<Update />}>Update</Button>
                                        </Box>
                                        <Divider sx={{ mb: 2 }} />

                                        {/* Primary Stats */}
                                        <Grid container spacing={2} sx={{ mb: 2 }}>
                                            <Grid item xs={4} sx={{ textAlign: 'center' }}>
                                                <Typography variant="h5" component="div"><strong>{clients.hashrates?.[cid]?.toFixed(1) || 'N/A'}</strong></Typography>
                                                <Typography variant="caption" color="text.secondary">H/s</Typography>
                                            </Grid>
                                            <Grid item xs={4} sx={{ textAlign: 'center' }}>
                                                <Typography variant="h5" component="div">{clients.temps?.[cid] || 'N/A'}</Typography>
                                                <Typography variant="caption" color="text.secondary">CPU Temp</Typography>
                                            </Grid>
                                            <Grid item xs={4} sx={{ textAlign: 'center' }}>
                                                <Typography variant="h5" component="div">{clients.power_draws?.[cid] || 'N/A'}W</Typography>
                                                <Typography variant="caption" color="text.secondary">Power</Typography>
                                            </Grid>
                                        </Grid>

                                        {/* Secondary Info */}
                                        <Paper variant="outlined" sx={{ display: 'flex', justifyContent: 'space-around', mb: 2, p: 1, borderRadius: 1 }}>
                                            <Typography variant="body2" title="CPU / GPU Shares">Shares: {clients.cpu_shares?.[cid] || 0}/{clients.nvidia_shares?.[cid] || 0}</Typography>
                                            <Typography variant="body2">Cost: ${clients.costs?.[cid]?.toFixed(3) || '0.00'}</Typography>
                                            <Typography variant="body2">Seen: {lastSeenData.client_last_seen_formatted?.[cid] || 'N/A'}</Typography>
                                        </Paper>

                                        {/* Job Details */}
                                        <Box>
                                            <Typography variant="overline" color="text.secondary">Current Job</Typography>
                                            <Paper variant="outlined" sx={{ p: 1.5, fontSize: '0.8rem' }}>
                                                <Typography variant="body2">Pool: {clients.newjobs?.[cid]?.ip || '—'}</Typography>
                                                <Typography variant="body2">Difficulty: {clients.newjobs?.[cid]?.difficulty || '—'}</Typography>
                                                <Typography variant="body2">Height: {clients.newjobs?.[cid]?.height || '—'}</Typography>
                                                <Typography variant="body2">Algo: {clients.newjobs?.[cid]?.algo || "-"}</Typography>
                                                <Typography variant="body2">Tx Count (ms): {clients.newjobs?.[cid]?.tx_count || "-"}</Typography>
                                            </Paper>
                                        </Box>
                                    </CardContent>

                                    {/* Actions */}
                                    <Box sx={{ p: 2, pt: 1, borderTop: '1px solid rgba(255, 255, 255, 0.12)' }}>
                                        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', justifyContent: 'space-between' }}>
                                            <form onSubmit={(e) => handleSetThreads(e, cid)} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                <TextField size="small" type="number" variant="outlined" sx={{ width: '85px' }} label="Threads" InputLabelProps={{ shrink: true }} placeholder={String(clients.threads?.[cid] || '1')} onChange={e => setThreadInputs({...threadInputs, [cid]: e.target.value})} />
                                                <Button type="submit" size="small" variant="contained">Set</Button>
                                            </form>
                                            {clients.status?.[cid] === 'Started' ?
                                                <Button variant="contained" color="error" size="small" onClick={() => handleStopMiner(cid)} startIcon={<Stop />}>Stop</Button> :
                                                <Button variant="contained" color="success" size="small" onClick={() => openStartModal(cid)} startIcon={<PlayArrow />}>Start</Button>
                                            }
                                        </Box>
                                    </Box>
                                </Card>
                            </Grid>
                        ))
                    ) : (
                        <Grid item xs={12}>
                            <Typography sx={{ textAlign: 'center', p: 4, color: 'text.secondary' }}>No clients have connected yet.</Typography>
                        </Grid>
                    )}
                </Grid>
            </Box>

            <Card sx={{ mb: 3 }}>
                <CardContent>
                    <Typography variant="h5" component="div" gutterBottom>System Control</Typography>
                    <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
                        <Button variant="contained" onClick={handleRestartP2Pool} startIcon={<RestartAlt />} disabled={loading['/restart_p2pool']}>
                            {loading['/restart_p2pool'] ? 'Restarting...' : 'Restart P2Pool'}
                        </Button>
                        <Typography variant="h5" component="div" gutterBottom>Connect to Wifi</Typography>
                        <form onSubmit={handleConnectToWifi} style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
                            <TextField label="Network SSID" variant="outlined" size="small" value={wifi.ssid} onChange={e => setWifi({...wifi, ssid: e.target.value})} />
                            <TextField label="Password" type="password" variant="outlined" size="small" value={wifi.password} onChange={e => setWifi({...wifi, password: e.target.value})} />
                            <Button type="submit" variant="contained" startIcon={<Wifi />} disabled={loading['/connect_wifi']}>{loading['/connect_wifi'] ? 'Connecting...' : 'Connect'}</Button>
                        </form>
                    </Box>
                </CardContent>
            </Card>

            <Typography variant="h4" gutterBottom sx={{ textAlign: 'center', mt: 4 }}>Event Logs</Typography>
            <Grid container spacing={3} sx={{display: "flex", justifyContent: "center"}}>
                <Grid item xs={12} lg={6}><EventTable title="Shares Found" events={events.shares_found} /></Grid>
                <Grid item xs={12} lg={6}><EventTable title="Blocks Found" events={events.blocks_found} /></Grid>
                <Grid item xs={12} lg={6}><EventTable title="New Miner Data" events={events.miner_data} /></Grid>
                <Grid item xs={12} lg={6}><EventTable title="Jobs Sent" events={events.jobs_sent} /></Grid>
                <Grid item xs={12}><EventTable title="Other Events" events={events.other_events} /></Grid>
            </Grid>

            <Dialog open={isStartModalOpen} onClose={() => setIsStartModalOpen(false)}>
                <DialogTitle>Start Miner: {modalClientId}</DialogTitle>
                <form onSubmit={handleStartMiner}>
                    <DialogContent>
                        <TextField autoFocus margin="dense" label="Pool URL" type="text" fullWidth variant="standard" required value={startMinerForm.pool} onChange={e => setStartMinerForm({...startMinerForm, pool: e.target.value})} />
                        <TextField margin="dense" label="Threads" type="number" fullWidth variant="standard" required value={startMinerForm.threads} onChange={e => setStartMinerForm({...startMinerForm, threads: e.target.value})} />
                    </DialogContent>
                    <DialogActions>
                        <Button onClick={() => setIsStartModalOpen(false)}>Cancel</Button>
                        <Button type="submit">Send Start Command</Button>
                    </DialogActions>
                </form>
            </Dialog>

            <Dialog open={confirmDialogOpen} onClose={() => setConfirmDialogOpen(false)}>
                <DialogTitle>{confirmDialogContent.title}</DialogTitle>
                <DialogContent>
                    <DialogContentText>{confirmDialogContent.message}</DialogContentText>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setConfirmDialogOpen(false)}>Cancel</Button>
                    <Button onClick={handleConfirm} autoFocus>Confirm</Button>
                </DialogActions>
            </Dialog>

        </div>
    </ThemeProvider>
  );
}

export default App;