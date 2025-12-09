# --- UI (FULL PROFESSIONAL) ---
HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Anomaly Detection // Sentinel</title>
    
    <!-- Fonts & Icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet">
    
    <!-- Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        :root {
            --bg-dark: #050505;
            --panel-bg: #111111;
            --panel-border: #333;
            --neon-green: #00ff41;
            --neon-red: #ff003c;
            --neon-blue: #00f3ff;
            --text-muted: #a0a0a0; 
            --text-main: #f0f0f0;
        }
        
        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Rajdhani', sans-serif;
            overflow-x: hidden;
            background-image: radial-gradient(circle at 50% 50%, #111 0%, #000 100%);
        }

        /* --- TYPOGRAPHY --- */
        .mono { font-family: 'JetBrains Mono', monospace; }
        .text-neon-green { color: var(--neon-green); text-shadow: 0 0 5px rgba(0,255,65,0.5); }
        .text-neon-red { color: var(--neon-red); text-shadow: 0 0 5px rgba(255,0,60,0.5); }
        .text-neon-blue { color: var(--neon-blue); text-shadow: 0 0 5px rgba(0,243,255,0.5); }
        .text-muted { color: var(--text-muted) !important; }

        /* --- CARDS & PANELS --- */
        .cyber-card {
            background: rgba(20, 20, 20, 0.85);
            border: 1px solid var(--panel-border);
            border-radius: 4px;
            backdrop-filter: blur(10px);
            box-shadow: 0 0 15px rgba(0,0,0,0.5);
            position: relative;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .cyber-card:hover {
            box-shadow: 0 0 25px rgba(0, 243, 255, 0.1);
            border-color: #444;
        }
        .cyber-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent, var(--neon-blue), transparent);
            opacity: 0.5;
        }

        /* --- TOP HEADER --- */
        .top-bar {
            border-bottom: 1px solid var(--panel-border);
            padding: 15px 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(0,0,0,0.5);
        }

        /* --- ACTION BUTTONS --- */
        .btn-init {
            background: transparent;
            border: 1px solid var(--neon-green);
            color: var(--neon-green);
            font-family: 'JetBrains Mono';
            padding: 12px 30px;
            text-transform: uppercase;
            letter-spacing: 2px;
            transition: 0.3s;
            position: relative;
            overflow: hidden;
            font-weight: 700;
        }
        .btn-init:hover {
            background: var(--neon-green);
            color: black;
            box-shadow: 0 0 20px rgba(0,255,65,0.4);
        }
        .btn-init:disabled {
            border-color: #555;
            color: #777;
            cursor: not-allowed;
            box-shadow: none;
            background: transparent;
        }

        /* --- DATA TABLES --- */
        .table-cyber {
            width: 100%;
            font-family: 'JetBrains Mono';
            font-size: 0.85rem;
            border-collapse: collapse;
        }
        .table-cyber th {
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 700;
            padding: 12px 10px;
            border-bottom: 1px solid var(--panel-border);
            text-align: left;
        }
        .table-cyber td {
            padding: 10px;
            border-bottom: 1px solid #222;
            color: #e0e0e0;
        }
        .table-cyber tr:hover td {
            background: rgba(0, 243, 255, 0.05);
        }
        
        /* --- ANIMATIONS --- */
        .row-animate { animation: fadeIn 0.3s ease-in; }
        @keyframes fadeIn { 
            from { opacity: 0; transform: translateX(-10px); } 
            to { opacity: 1; transform: translateX(0); } 
        }

        /* --- ALERTS SYSTEM --- */
        .alert-item {
            border-left: 3px solid var(--neon-red);
            background: rgba(255, 0, 60, 0.1);
            padding: 12px;
            margin-bottom: 8px;
            font-family: 'JetBrains Mono';
            font-size: 0.85rem;
            animation: flash 0.5s;
            transition: 0.2s;
        }
        .alert-item:hover {
            background: rgba(255, 0, 60, 0.2);
        }
        @keyframes flash { 
            0% { background: rgba(255,0,60,0.4); } 
            100% { background: rgba(255,0,60,0.1); } 
        }

        /* --- STATUS INDICATOR --- */
        .status-dot {
            height: 10px; width: 10px;
            background-color: #444;
            border-radius: 50%;
            display: inline-block;
            margin-right: 10px;
        }
        .status-active .status-dot {
            background-color: var(--neon-green);
            box-shadow: 0 0 10px var(--neon-green);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse { 
            0% { opacity: 1; transform: scale(1); } 
            50% { opacity: 0.5; transform: scale(1.2); } 
            100% { opacity: 1; transform: scale(1); } 
        }
        
        /* --- PROGRESS BAR --- */
        .progress-container {
            height: 6px;
            background: #333;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 5px;
        }
        .progress-bar-custom {
            height: 100%;
            background: var(--neon-blue);
            width: 0%;
            box-shadow: 0 0 10px cyan;
            transition: width 0.5s ease;
        }
    </style>
</head>
<body>

    <!-- TOP HEADER -->
    <div class="top-bar">
        <div class="d-flex align-items-center">
            <i class="fas fa-shield-alt text-neon-blue fa-2x me-3"></i>
            <div>
                <h3 class="m-0 text-uppercase" style="letter-spacing: 2px; font-weight: 700;">
                    Anomaly <span class="text-neon-blue">Detection</span>
                </h3>
                <small class="text-muted mono">v5.0.0 | PRECISION CORE</small>
            </div>
        </div>
        <div id="statusIndicator" class="d-flex align-items-center status-idle">
            <span class="status-dot"></span>
            <span id="statusText" class="mono fw-bold">SYSTEM OFFLINE</span>
        </div>
    </div>

    <div class="container-fluid px-4">
        
        <!-- KEY METRICS -->
        <div class="row mb-4">
            <!-- Total Packets -->
            <div class="col-md-3">
                <div class="cyber-card p-3 d-flex justify-content-between align-items-center h-100">
                    <div>
                        <small class="text-muted text-uppercase fw-bold">Total Packets</small>
                        <h2 id="pktCount" class="m-0 mono text-white">0</h2>
                    </div>
                    <i class="fas fa-search text-muted fa-2x opacity-50"></i>
                </div>
            </div>
            
            <!-- Active Threats -->
            <div class="col-md-3">
                <div class="cyber-card p-3 d-flex justify-content-between align-items-center h-100">
                    <div>
                        <small class="text-muted text-uppercase fw-bold">Active Threats</small>
                        <h2 id="threatCount" class="m-0 mono text-neon-red">0</h2>
                    </div>
                    <i class="fas fa-biohazard text-neon-red fa-2x opacity-75"></i>
                </div>
            </div>
            
            <!-- System Status & Controls -->
            <div class="col-md-6">
                <div class="cyber-card p-3 h-100 d-flex flex-column justify-content-center">
                    <div class="d-flex justify-content-between mb-2">
                        <span class="text-muted text-uppercase fw-bold">System Status</span>
                        <span id="modelPercent" class="mono text-neon-blue fw-bold">STANDBY</span>
                    </div>
                    <div class="progress-container">
                        <div id="progBar" class="progress-bar-custom"></div>
                    </div>
                    <button id="btnStart" onclick="startSystem()" class="btn-init mt-3 w-100">
                        <i class="fas fa-play me-2"></i> Activate Sentinel
                    </button>
                    <!-- Force Demo Controls for Cloud -->
                    <div id="cloudMsg" class="text-center mt-2 d-none">
                        <small class="text-muted mono">CLOUD ENV DETECTED: RUNNING SIMULATION</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- MAIN DASHBOARD CONTENT -->
        <div class="row">
            
            <!-- LEFT COLUMN: VISUALIZATION & FEED -->
            <div class="col-lg-8 mb-4">
                
                <!-- Live Graph -->
                <div class="cyber-card p-3 mb-4">
                    <h6 class="text-muted text-uppercase mb-3 fw-bold">
                        <i class="fas fa-wave-square me-2"></i> Threat Probability Flow
                    </h6>
                    <div style="height: 300px;">
                        <canvas id="chart"></canvas>
                    </div>
                </div>

                <!-- Packet Table -->
                <div class="cyber-card p-0">
                    <div class="p-3 border-bottom border-dark d-flex justify-content-between align-items-center">
                        <h6 class="text-muted text-uppercase m-0 fw-bold">
                            <i class="fas fa-network-wired me-2"></i> Live Interface Feed
                        </h6>
                        <small class="mono text-neon-green" id="captureStatus">LIVE CAPTURE</small>
                    </div>
                    <div style="height: 300px; overflow-y: auto;">
                        <table class="table-cyber">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Source</th>
                                    <th>Dest</th>
                                    <th>Proto</th>
                                    <th>Size</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody id="pktTable">
                                <tr>
                                    <td colspan="6" class="text-center text-muted py-4">
                                        System Offline. Waiting for initialization...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- RIGHT COLUMN: ALERTS LOG -->
            <div class="col-lg-4">
                <div class="cyber-card h-100 d-flex flex-column">
                    <div class="p-3 border-bottom border-dark">
                        <h6 class="text-neon-red text-uppercase m-0 fw-bold">
                            <i class="fas fa-exclamation-triangle me-2"></i> Intrusion Logs
                        </h6>
                    </div>
                    <div id="alerts" class="p-3 flex-grow-1" style="overflow-y: auto; max-height: 650px;">
                        <div class="text-center text-muted mt-5 opacity-75">
                            <i class="fas fa-shield-alt fa-3x mb-3"></i>
                            <p class="mt-2">No anomalies detected.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- FRONTEND LOGIC -->
    <script>
        const ctx = document.getElementById('chart').getContext('2d');
        
        // Dynamic Risk Gradient (Stroke)
        const borderGradient = ctx.createLinearGradient(0, 250, 0, 0); 
        borderGradient.addColorStop(0, '#00f3ff');   // Safe
        borderGradient.addColorStop(0.5, '#ffcc00'); // Warning
        borderGradient.addColorStop(1, '#ff003c');   // Critical

        // Glowing Fill Gradient
        const fillGradient = ctx.createLinearGradient(0, 0, 0, 300);
        fillGradient.addColorStop(0, 'rgba(255, 0, 60, 0.4)'); 
        fillGradient.addColorStop(0.5, 'rgba(0, 243, 255, 0.1)'); 
        fillGradient.addColorStop(1, 'rgba(0, 243, 255, 0)'); 

        const chart = new Chart(ctx, {
            type: 'line',
            data: { 
                labels: [], 
                datasets: [{ 
                    label: 'Threat Probability', 
                    data: [], 
                    borderColor: borderGradient, 
                    borderWidth: 3,
                    backgroundColor: fillGradient,
                    fill: true,
                    tension: 0.4, 
                    cubicInterpolationMode: 'monotone',
                    pointRadius: 0,
                    pointHoverRadius: 6
                }] 
            },
            options: { 
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 800, easing: 'linear' },
                plugins: { legend: { display: false } },
                scales: { 
                    x: { display: false }, 
                    y: { 
                        grid: { color: '#333' }, 
                        min: 0, 
                        max: 1.1 
                    } 
                }
            }
        });

        function startSystem() {
            fetch('/api/start', {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if (data.mode === 'DEMO') {
                        document.getElementById('cloudMsg').classList.remove('d-none');
                        document.getElementById('captureStatus').innerText = "SIMULATION";
                        document.getElementById('captureStatus').classList.remove('text-neon-green');
                        document.getElementById('captureStatus').classList.add('text-warning');
                    }
                });
            
            const btn = document.getElementById('btnStart');
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-check-circle me-2"></i> SYSTEM ACTIVE';
            setInterval(updateStats, 1000);
        }

        async function updateStats() {
            try {
                const res = await fetch('/api/stats');
                if (!res.ok) return;
                const data = await res.json();

                // Update Header Stats
                document.getElementById('pktCount').innerText = data.count.toLocaleString();
                document.getElementById('threatCount').innerText = data.threats;
                
                // Update Status & Progress
                document.getElementById('modelPercent').innerText = "ONLINE";
                document.getElementById('progBar').style.width = "100%";
                document.getElementById('progBar').style.opacity = "1";

                const statusDiv = document.getElementById('statusIndicator');
                const statusText = document.getElementById('statusText');

                if (data.status === 'ACTIVE') {
                    statusDiv.className = 'd-flex align-items-center status-active';
                    statusText.innerText = 'PROTECTION ACTIVE';
                    statusText.classList.add('text-neon-green');
                }

                // Update Graph
                if(data.data.length > 0) {
                    chart.data.labels = data.data.map(d => d.time);
                    chart.data.datasets[0].data = data.data.map(d => d.score);
                    chart.update();
                }

                // Update Table Feed
                const tableBody = document.getElementById('pktTable');
                if (data.packets.length > 0) {
                    tableBody.innerHTML = data.packets.map(p => `
                        <tr class="row-animate">
                            <td class="text-muted">${p.time}</td>
                            <td>${p.src}</td>
                            <td>${p.dst}</td>
                            <td><span class="badge ${p.proto === 'TCP' ? 'bg-primary' : 'bg-warning text-dark'}">${p.proto}</span></td>
                            <td class="mono">${p.size} B</td>
                            <td>${p.is_risk ? '<span class="text-neon-red fw-bold"><i class="fas fa-exclamation-circle"></i> THREAT</span>' : '<span class="text-muted"><i class="fas fa-check"></i> OK</span>'}</td>
                        </tr>
                    `).join('');
                }

                // Update Alerts Feed
                const alertsDiv = document.getElementById('alerts');
                if (data.alerts.length > 0) {
                    alertsDiv.innerHTML = data.alerts.map(a => `
                        <div class="alert-item">
                            <div class="d-flex justify-content-between mb-1">
                                <strong class="text-neon-red">THREAT DETECTED</strong>
                                <small class="text-muted">${a.time}</small>
                            </div>
                            <div class="d-flex justify-content-between align-items-end">
                                <span>${a.details}</span>
                                <small class="text-muted">Prob: ${Math.round(a.score * 100)}%</small>
                            </div>
                        </div>
                    `).join('');
                }
            } catch (e) { console.error(e); }
        }
    </script>
</body>
</html>
"""
