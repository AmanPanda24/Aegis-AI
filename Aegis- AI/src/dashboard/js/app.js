// Every REST call and the WebSocket handshake now require an API key
// (see src/core/auth.py). window.AEGIS_API_KEY is injected server-side by
// the "/" route in src/api/main.py so the bundled dashboard keeps working
// without the user having to configure anything by hand.
(function () {
    const originalFetch = window.fetch.bind(window);
    window.fetch = (input, init = {}) => {
        const headers = new Headers(init.headers || {});
        if (window.AEGIS_API_KEY) {
            headers.set('X-API-Key', window.AEGIS_API_KEY);
        }
        return originalFetch(input, { ...init, headers });
    };
})();

// DPI-derived fields (http_host, dns_query, tls_sni, http_uri, http_method,
// http_user_agent) come straight from parsed attacker-controlled bytes
// (dpi_engine.py does no sanitization - that's not its job, DPI should
// report exactly what's on the wire). Every place one of those fields is
// interpolated into an innerHTML template MUST go through this first, or
// a crafted HTTP Host header / DNS query name / TLS SNI containing
// markup executes in the analyst's authenticated dashboard session -
// which is exactly the traffic this tool exists to show you.
function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

class AegisDashboard {
    constructor() {
        this.ws = null;
        this.reconnectInterval = 3000;
        this.flows = [];
        this.alerts = [];
        this.filteredAlerts = [];
        this.packets = [];
        this.packetStreamPaused = false;
        this.stats = {};
        this.currentPage = 1;
        this.pageSize = 20;
        this.chartMetric = 'packets';
        this.filters = {};
        this.charts = {};
        this.trafficData = {
            labels: [],
            packets: [],
            bytes: []
        };
        // Backend can push several 'flow'/'alert' WebSocket messages in a
        // tight burst (e.g. right after a blocking DB write finally clears -
        // see src/api/main.py processing_loop). Calling the innerHTML-rebuild
        // render functions once per message thrashes the DOM and makes the
        // UI feel laggy even once data is arriving. Coalesce same-frame
        // updates into a single render per table via requestAnimationFrame.
        this._pendingRenders = new Set();
        this._renderHandle = null;
        this.init();
    }

    scheduleRender(name) {
        this._pendingRenders.add(name);
        if (this._renderHandle) return;
        const flush = () => {
            this._renderHandle = null;
            const pending = this._pendingRenders;
            this._pendingRenders = new Set();
            if (pending.has('flow')) this.renderFlowTable();
            if (pending.has('packet')) this.renderPacketStream();
            if (pending.has('alert')) this.renderAlerts();
        };
        this._renderHandle = (typeof requestAnimationFrame === 'function')
            ? requestAnimationFrame(flush)
            : setTimeout(flush, 100);
    }

    init() {
        this.initCharts();
        this.connectWebSocket();
        this.setupEventListeners();
        this.startClock();
        this.fetchInitialData();
        this.refreshCaptureStatus();
        setInterval(() => this.refreshTalkers(), 12000);
    }

    initCharts() {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = '#1e293b';
        Chart.defaults.font.family = "'Inter', sans-serif";

        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        this.charts.traffic = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/sec',
                    data: [],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true, grid: { color: '#1e293b' } }
                },
                animation: { duration: 0 }
            }
        });

        const gaugeCtx = document.getElementById('threatGauge').getContext('2d');
        this.charts.gauge = new Chart(gaugeCtx, {
            type: 'doughnut',
            data: {
                labels: ['Threat', 'Safe'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#ef4444', '#1e293b'],
                    borderWidth: 0,
                    cutout: '75%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                rotation: -90,
                circumference: 180
            }
        });

        const attackCtx = document.getElementById('attackChart').getContext('2d');
        this.charts.attack = new Chart(attackCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#06b6d4', '#ef4444', '#f59e0b', '#8b5cf6', '#10b981', '#ec4899', '#6366f1', '#14b8a6',
                        '#84cc16', '#f97316', '#a855f7', '#0ea5e9', '#eab308', '#f43f5e', '#22c55e', '#64748b'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 } } }
                }
            }
        });

        const protoCtx = document.getElementById('protocolChart').getContext('2d');
        this.charts.protocol = new Chart(protoCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Flows',
                    data: [],
                    backgroundColor: ['#06b6d4', '#8b5cf6', '#f59e0b'],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { display: false }
                }
            }
        });
    }

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const keyParam = window.AEGIS_API_KEY ? `?api_key=${encodeURIComponent(window.AEGIS_API_KEY)}` : '';
        const wsUrl = `${protocol}//${window.location.host}/ws${keyParam}`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('[AEGIS] WebSocket connected');
            this.showToast('Connected to Aegis-AI Engine', 'success');
        };

        this.ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                this.handleMessage(msg);
            } catch (e) {
                console.error('WebSocket message error:', e);
            }
        };

        this.ws.onclose = () => {
            console.log('[AEGIS] WebSocket disconnected, reconnecting...');
            setTimeout(() => this.connectWebSocket(), this.reconnectInterval);
        };

        this.ws.onerror = (err) => {
            console.error('WebSocket error:', err);
        };
    }

    handleMessage(msg) {
        switch(msg.type) {
            case 'stats':
                this.updateStats(msg.data);
                break;
            case 'flow':
                this.addFlow(msg.data);
                break;
            case 'alert':
                this.addAlert(msg.data);
                break;
            case 'pong':
                break;
        }
    }

    updateStats(data) {
        this.stats = data;

        document.getElementById('kpi-packets').textContent = this.formatNumber(data.total_packets || 0);
        document.getElementById('kpi-pps').textContent = this.formatNumber(data.packets_per_sec || 0);
        document.getElementById('kpi-alerts').textContent = this.formatNumber(data.total_alerts ?? data.alert_count ?? 0);
        document.getElementById('kpi-alert-rate').textContent = `${data.recent_alerts ?? data.alert_count ?? 0} in last hour`;
        document.getElementById('kpi-flows').textContent = this.formatNumber(data.active_flows || 0);
        document.getElementById('kpi-threat').textContent = (data.avg_threat_score || 0).toFixed(1);

        const trend = (data.avg_threat_score || 0) > 50 ? 'Elevated' : 'Baseline';
        const trendColor = (data.avg_threat_score || 0) > 50 ? 'text-rose-400' : 'text-emerald-400';
        const trendEl = document.getElementById('kpi-threat-trend');
        trendEl.textContent = trend;
        trendEl.className = `text-xs mt-1 ${trendColor}`;

        const score = Math.min(100, Math.max(0, data.avg_threat_score || 0));
        this.charts.gauge.data.datasets[0].data = [score, 100 - score];

        let gaugeColor = '#10b981';
        let gaugeLabel = 'BENIGN';
        if (score >= 75) {
            gaugeColor = '#ef4444';
            gaugeLabel = 'HIGH RISK';
        } else if (score >= 45) {
            gaugeColor = '#f59e0b';
            gaugeLabel = 'MEDIUM RISK';
        } else if (score >= 20) {
            gaugeColor = '#fbbf24';
            gaugeLabel = 'LOW RISK';
        }

        this.charts.gauge.data.datasets[0].backgroundColor = [gaugeColor, '#1e293b'];
        this.charts.gauge.update('none');

        document.getElementById('gauge-label').textContent = gaugeLabel;
        document.getElementById('gauge-label').className = `text-lg font-bold ${gaugeColor === '#ef4444' ? 'text-rose-400' : gaugeColor === '#f59e0b' ? 'text-amber-400' : gaugeColor === '#fbbf24' ? 'text-yellow-400' : 'text-emerald-400'}`;
        document.getElementById('gauge-score').textContent = Math.round(score);

        if (data.attack_distribution) {
            this.charts.attack.data.labels = data.attack_distribution.map(d => d.attack_type);
            this.charts.attack.data.datasets[0].data = data.attack_distribution.map(d => d.count);
            this.charts.attack.update('none');
        }

        if (data.protocol_distribution) {
            this.charts.protocol.data.labels = data.protocol_distribution.map(d => d.protocol);
            this.charts.protocol.data.datasets[0].data = data.protocol_distribution.map(d => d.count);
            this.charts.protocol.update('none');
        }

        this.updateTrafficChart(data);
    }

    updateTrafficChart(data) {
        const now = new Date();
        const timeLabel = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

        this.trafficData.labels.push(timeLabel);
        this.trafficData.packets.push(data.packets_per_sec || 0);
        this.trafficData.bytes.push(data.bytes_per_sec || 0);

        if (this.trafficData.labels.length > 60) {
            this.trafficData.labels.shift();
            this.trafficData.packets.shift();
            this.trafficData.bytes.shift();
        }

        this.charts.traffic.data.labels = this.trafficData.labels;
        this.charts.traffic.data.datasets[0].data = this.chartMetric === 'packets' ? this.trafficData.packets : this.trafficData.bytes;
        this.charts.traffic.data.datasets[0].label = this.chartMetric === 'packets' ? 'Packets/sec' : 'Bytes/sec';
        this.charts.traffic.data.datasets[0].borderColor = this.chartMetric === 'packets' ? '#06b6d4' : '#8b5cf6';
        this.charts.traffic.data.datasets[0].backgroundColor = this.chartMetric === 'packets' ? 'rgba(6, 182, 212, 0.1)' : 'rgba(139, 92, 246, 0.1)';
        this.charts.traffic.update('none');
    }

    addFlow(flow) {
        this.flows.unshift(flow);
        if (this.flows.length > 1000) this.flows.pop();
        this.scheduleRender('flow');
        this.ingestPacketSample(flow);
    }

    addAlert(alert) {
        this.alerts.unshift(alert);
        if (this.alerts.length > 500) this.alerts.pop();
        this.scheduleRender('alert');
        const origin = alert.src_ip || alert.src_mac || 'unknown source';
        this.showToast(`Alert: ${alert.attack_type} from ${origin}`, 'warning');
    }

    renderAlerts() {
        const container = document.getElementById('alert-feed');
        const filter = document.getElementById('alert-filter').value;

        let displayAlerts = this.alerts;
        if (filter !== 'all') {
            displayAlerts = this.alerts.filter(a => {
                const score = a.threat_score;
                if (filter === 'HIGH RISK / ATTACK') return score >= 75;
                if (filter === 'MEDIUM RISK') return score >= 45 && score < 75;
                if (filter === 'LOW RISK') return score >= 20 && score < 45;
                return true;
            });
        }

        if (displayAlerts.length === 0) {
            container.innerHTML = '<div class="text-center text-slate-500 py-8 text-sm">No alerts match current filter</div>';
            return;
        }

        container.innerHTML = displayAlerts.slice(0, 50).map(alert => {
            const time = new Date(alert.timestamp * 1000).toLocaleTimeString();
            let severityClass = 'risk-benign';
            let severityLabel = 'BENIGN';
            if (alert.threat_score >= 75) {
                severityClass = 'risk-high';
                severityLabel = 'CRITICAL';
            } else if (alert.threat_score >= 45) {
                severityClass = 'risk-medium';
                severityLabel = 'MEDIUM';
            } else if (alert.threat_score >= 20) {
                severityClass = 'risk-low';
                severityLabel = 'LOW';
            }

            const isL2 = alert.layer === 'L2';
            const clickHandler = alert.flow_id ? `onclick="app.openFlowDetail(${alert.flow_id})"` : '';
            const cursorClass = alert.flow_id ? 'cursor-pointer' : '';
            const endpointLine = isL2
                ? `${alert.src_mac || 'unknown MAC'}${alert.src_ip ? ' (' + alert.src_ip + ')' : ''}`
                : `${alert.src_ip} → ${alert.dst_ip}`;

            return `
                <div class="alert-item bg-slate-800/50 border border-slate-700 rounded-lg p-3 hover:bg-slate-800 transition ${cursorClass}" ${clickHandler}>
                    <div class="flex items-start justify-between mb-1">
                        <div class="flex items-center gap-2">
                            <span class="px-2 py-0.5 rounded text-xs font-medium ${severityClass}">${severityLabel}</span>
                            ${isL2 ? '<span class="px-2 py-0.5 rounded text-xs font-medium bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">L2</span>' : ''}
                            <span class="text-xs text-slate-400 font-mono">${time}</span>
                        </div>
                        <span class="text-lg font-bold text-white font-mono">${Math.round(alert.threat_score)}</span>
                    </div>
                    <div class="text-sm text-white mb-1">${escapeHtml(alert.attack_type)}</div>
                    <div class="text-xs text-slate-400 mb-2">
                        ${escapeHtml(endpointLine)}
                    </div>
                    <div class="text-xs text-slate-500 bg-slate-900/50 rounded px-2 py-1">
                        ${escapeHtml(alert.recommended_action)}
                    </div>
                </div>
            `;
        }).join('');
    }

    renderFlowTable() {
        const tbody = document.getElementById('flow-table-body');
        const start = (this.currentPage - 1) * this.pageSize;
        const end = start + this.pageSize;
        const pageFlows = this.flows.slice(start, end);

        if (pageFlows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="12" class="px-3 py-8 text-center text-slate-500">No flows captured yet...</td></tr>';
        } else {
            tbody.innerHTML = pageFlows.map(flow => {
                const time = new Date(flow.timestamp * 1000).toLocaleTimeString();
                const riskClass = this.riskClass(flow.risk_level);
                const dpi = flow.dpi_result || {};
                const appProto = dpi.application_protocol || 'UNKNOWN';
                const indicators = dpi.anomaly_indicators || [];
                const indicatorsHtml = indicators.length
                    ? indicators.slice(0, 2).map(i => `<span class="indicator-chip">${this.indicatorLabel(i)}</span>`).join('') +
                      (indicators.length > 2 ? `<span class="indicator-chip">+${indicators.length - 2}</span>` : '')
                    : '<span class="text-slate-700">—</span>';

                return `
                    <tr class="border-b border-slate-800/50 row-clickable" onclick="app.openFlowDetail(${flow.id})">
                        <td class="px-3 py-2 text-xs text-slate-400 font-mono">${time}</td>
                        <td class="px-3 py-2 text-xs text-slate-300 font-mono">${flow.src_ip}:${flow.src_port}</td>
                        <td class="px-3 py-2 text-xs text-slate-300 font-mono">${flow.dst_ip}:${flow.dst_port}</td>
                        <td class="px-3 py-2"><span class="px-1.5 py-0.5 rounded text-xs bg-slate-800 text-slate-300">${flow.protocol}</span></td>
                        <td class="px-3 py-2"><span class="badge ${this.protocolBadgeClass(appProto)}">${appProto}</span></td>
                        <td class="px-3 py-2 text-xs text-slate-400 font-mono">${flow.packet_count}</td>
                        <td class="px-3 py-2 text-xs text-slate-400 font-mono">${this.formatBytes(flow.total_bytes)}</td>
                        <td class="px-3 py-2 text-xs text-slate-400 font-mono">${flow.duration.toFixed(2)}s</td>
                        <td class="px-3 py-2 text-xs text-slate-300">${escapeHtml(flow.attack_type)}</td>
                        <td class="px-3 py-2">${indicatorsHtml}</td>
                        <td class="px-3 py-2 text-xs font-mono font-bold ${flow.threat_score >= 75 ? 'text-rose-400' : flow.threat_score >= 45 ? 'text-amber-400' : 'text-emerald-400'}">${flow.threat_score.toFixed(1)}</td>
                        <td class="px-3 py-2"><span class="px-2 py-0.5 rounded text-xs ${riskClass}">${flow.risk_level}</span></td>
                    </tr>
                `;
            }).join('');
        }

        document.getElementById('flow-count').textContent = `Showing ${this.flows.length} flows (Page ${this.currentPage} of ${Math.ceil(this.flows.length / this.pageSize)})`;
        document.getElementById('page-info').textContent = `Page ${this.currentPage}`;
        document.getElementById('btn-prev').disabled = this.currentPage === 1;
        document.getElementById('btn-next').disabled = end >= this.flows.length;
    }

    // ---------- Live Packet Stream ----------

    ingestPacketSample(flow) {
        if (this.packetStreamPaused) return;
        const sample = flow.packets_sample || [];
        if (!sample.length) return;
        for (let i = sample.length - 1; i >= 0; i--) {
            this.packets.unshift(sample[i]);
        }
        if (this.packets.length > 500) this.packets.length = 500;
        this.scheduleRender('packet');
    }

    togglePacketStream() {
        this.packetStreamPaused = !this.packetStreamPaused;
        const btn = document.getElementById('packet-stream-toggle');
        const dot = document.getElementById('packet-stream-dot');
        if (this.packetStreamPaused) {
            btn.textContent = 'Resume';
            dot.classList.add('paused');
        } else {
            btn.textContent = 'Pause';
            dot.classList.remove('paused');
        }
    }

    renderPacketStream() {
        const tbody = document.getElementById('packet-stream-body');
        const filter = document.getElementById('packet-stream-filter')?.value || '';
        let list = this.packets;
        if (filter) list = list.filter(p => p.protocol === filter);
        const display = list.slice(0, 150);

        if (display.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="px-3 py-8 text-center text-slate-500">Waiting for packets...</td></tr>';
        } else {
            tbody.innerHTML = display.map(p => {
                const protoClass = p.protocol === 'TCP' ? 'packet-tcp' : p.protocol === 'UDP' ? 'packet-udp' : p.protocol === 'ICMP' ? 'packet-icmp' : 'packet-other';
                const entropy = (p.payload_entropy || 0);
                return `
                    <tr class="border-b border-slate-800/30">
                        <td class="px-2 py-1 text-slate-500 font-mono">${this.formatPacketTime(p.timestamp)}</td>
                        <td class="px-2 py-1 text-slate-300 font-mono">${p.src_ip}:${p.src_port}</td>
                        <td class="px-2 py-1 text-slate-300 font-mono">${p.dst_ip}:${p.dst_port}</td>
                        <td class="px-2 py-1 font-mono font-semibold ${protoClass}">${p.protocol}</td>
                        <td class="px-2 py-1 text-slate-400 font-mono">${p.length}B</td>
                        <td class="px-2 py-1 text-slate-500 font-mono">${escapeHtml(p.flags) || '—'}</td>
                        <td class="px-2 py-1 font-mono ${entropy > 7 ? 'text-rose-400' : 'text-slate-500'}">${entropy.toFixed(2)}</td>
                    </tr>
                `;
            }).join('');
        }
        document.getElementById('packet-stream-count').textContent =
            `${list.length} packets buffered${filter ? ' · filtered: ' + filter : ''}${this.packetStreamPaused ? ' · PAUSED' : ''}`;
    }

    formatPacketTime(ts) {
        if (!ts) return '—';
        const d = new Date(ts * 1000);
        return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
    }

    // ---------- Top Talkers ----------

    async refreshTalkers() {
        try {
            const res = await fetch('/api/network/talkers?minutes=60');
            const data = await res.json();
            this.renderTopTalkers(data);
        } catch (err) {
            console.error('Talkers fetch error:', err);
        }
    }

    renderTopTalkers(data) {
        if (!data) return;
        const sources = data.top_sources || [];
        const ports = data.top_ports || [];

        const srcContainer = document.getElementById('talkers-sources');
        if (sources.length === 0) {
            srcContainer.innerHTML = '<div class="text-xs text-slate-500">No data yet...</div>';
        } else {
            const maxBytes = Math.max(...sources.map(s => s.bytes || 0), 1);
            srcContainer.innerHTML = sources.map(s => `
                <div>
                    <div class="flex items-center justify-between text-xs mb-1">
                        <span class="text-slate-300 font-mono">${s.ip}</span>
                        <span class="text-slate-500 font-mono">${this.formatBytes(s.bytes || 0)}</span>
                    </div>
                    <div class="talker-bar-track"><div class="talker-bar-fill" style="width: ${((s.bytes || 0) / maxBytes * 100).toFixed(0)}%"></div></div>
                </div>
            `).join('');
        }

        const portContainer = document.getElementById('talkers-ports');
        if (ports.length === 0) {
            portContainer.innerHTML = '<div class="text-xs text-slate-500">No data yet...</div>';
        } else {
            const maxFlows = Math.max(...ports.map(p => p.flows || 0), 1);
            portContainer.innerHTML = ports.map(p => `
                <div>
                    <div class="flex items-center justify-between text-xs mb-1">
                        <span class="text-slate-300 font-mono">${p.port} <span class="text-slate-600">/${p.protocol}</span></span>
                        <span class="text-slate-500 font-mono">${p.flows} flows</span>
                    </div>
                    <div class="talker-bar-track"><div class="talker-bar-fill" style="width: ${((p.flows || 0) / maxFlows * 100).toFixed(0)}%"></div></div>
                </div>
            `).join('');
        }
    }

    // ---------- Flow Detail Drawer ----------

    async openFlowDetail(id) {
        if (!id && id !== 0) return;
        const overlay = document.getElementById('flow-detail-overlay');
        const panel = document.getElementById('flow-detail-panel');
        overlay.classList.add('open');
        panel.classList.add('open');
        document.getElementById('fd-body').innerHTML = '<div class="text-center text-slate-500 py-12 text-sm">Loading flow detail...</div>';

        try {
            const res = await fetch(`/api/flows/${id}`);
            if (!res.ok) throw new Error('Flow not found');
            const flow = await res.json();
            this.renderFlowDetail(flow);
        } catch (err) {
            document.getElementById('fd-body').innerHTML = '<div class="text-center text-rose-400 py-12 text-sm">Could not load flow detail. It may have aged out of the database.</div>';
        }
    }

    closeFlowDetail() {
        document.getElementById('flow-detail-overlay').classList.remove('open');
        document.getElementById('flow-detail-panel').classList.remove('open');
    }

    renderFlowDetail(flow) {
        document.getElementById('fd-title').textContent = `${flow.src_ip}:${flow.src_port} → ${flow.dst_ip}:${flow.dst_port}`;
        const time = new Date(flow.timestamp * 1000).toLocaleString();
        document.getElementById('fd-subtitle').textContent = `${flow.protocol} · Flow #${flow.id} · ${time}`;

        const dpi = flow.dpi_result || {};
        const features = flow.features || {};
        const packets = flow.packets || [];
        const scoreColor = flow.threat_score >= 75 ? '#f87171' : flow.threat_score >= 45 ? '#fb923c' : flow.threat_score >= 20 ? '#fbbf24' : '#34d399';
        const indicators = dpi.anomaly_indicators || [];

        let html = '';

        html += `
            <div>
                <div class="flex items-center justify-between mb-2">
                    <span class="text-xs text-slate-400 uppercase tracking-wide">Threat Assessment</span>
                    <span class="px-2 py-0.5 rounded text-xs ${this.riskClass(flow.risk_level)}">${flow.risk_level}</span>
                </div>
                <div class="flex items-center gap-3 mb-2">
                    <span class="text-3xl font-bold font-mono" style="color:${scoreColor}">${flow.threat_score.toFixed(1)}</span>
                    <span class="text-sm text-slate-300">${flow.attack_type} <span class="text-slate-500">· ${((flow.classification_confidence || 0) * 100).toFixed(0)}% confidence</span></span>
                </div>
                <div class="threat-bar-track"><div class="threat-bar-fill" style="width:${Math.min(100, flow.threat_score)}%; background:${scoreColor}"></div></div>
            </div>
        `;

        html += `
            <div class="grid grid-cols-3 gap-2">
                <div class="feature-chip"><span class="fc-label">Packets</span><span class="fc-value">${flow.packet_count}</span></div>
                <div class="feature-chip"><span class="fc-label">Bytes</span><span class="fc-value">${this.formatBytes(flow.total_bytes)}</span></div>
                <div class="feature-chip"><span class="fc-label">Duration</span><span class="fc-value">${flow.duration.toFixed(2)}s</span></div>
            </div>
        `;

        html += `
            <div>
                <span class="text-xs text-slate-400 uppercase tracking-wide block mb-2">Deep Packet Inspection</span>
                <div class="flex flex-wrap items-center gap-2 mb-2">
                    <span class="badge ${this.protocolBadgeClass(dpi.application_protocol)}">${dpi.application_protocol || 'UNKNOWN'}</span>
                    ${indicators.length ? indicators.map(i => `<span class="indicator-chip">${this.indicatorLabel(i)}</span>`).join('') : '<span class="text-xs text-slate-600">No anomaly indicators</span>'}
                </div>
                <div class="grid grid-cols-2 gap-2 text-xs">
                    <div class="feature-chip"><span class="fc-label">HTTP Host</span><span class="fc-value">${escapeHtml(dpi.http_host) || '—'}</span></div>
                    <div class="feature-chip"><span class="fc-label">HTTP Method</span><span class="fc-value">${escapeHtml(dpi.http_method) || '—'}</span></div>
                    <div class="feature-chip"><span class="fc-label">DNS Query</span><span class="fc-value">${escapeHtml(dpi.dns_query) || '—'}</span></div>
                    <div class="feature-chip"><span class="fc-label">TLS SNI</span><span class="fc-value">${escapeHtml(dpi.tls_sni) || '—'}</span></div>
                </div>
                <!-- http_uri deliberately not rendered here: it's the field the
                     DPI engine's own SUSPICIOUS_HTTP_URI check targets (SQLi/XSS/
                     path-traversal payloads), i.e. the single most likely field
                     to contain a deliberate markup payload. escapeHtml() above
                     neutralizes it either way, but showing it only as an escaped
                     indicator chip below (which already happens via the
                     'indicators' array above) avoids displaying raw attacker payloads
                     verbatim in the main detail view. -->
                <p class="text-[10px] text-slate-600 mt-1">HTTP Method above reflects the raw request line as parsed - values outside GET/POST/PUT/etc. indicate a malformed or crafted request.</p>
                <p class="text-[10px] text-slate-600 mt-2">Prototype DPI infers the application protocol from port + traffic heuristics; payload-level HTTP/DNS/TLS parsing is not implemented, so those fields stay empty until that module is extended.</p>
            </div>
        `;

        const groups = this.groupFeatures(features);
        const featureCount = Object.keys(features).length;
        html += `<div><span class="text-xs text-slate-400 uppercase tracking-wide block mb-2">Extracted Flow Features (${featureCount})</span>`;
        for (const [groupName, entries] of Object.entries(groups)) {
            if (entries.length === 0) continue;
            html += `<div class="mb-3"><div class="text-[10px] text-slate-600 uppercase mb-1">${groupName}</div><div class="feature-grid">`;
            html += entries.map(([k, v]) => `
                <div class="feature-chip">
                    <span class="fc-label">${this.formatFeatureLabel(k)}</span>
                    <span class="fc-value">${this.formatFeatureValue(v)}</span>
                </div>
            `).join('');
            html += `</div></div>`;
        }
        html += `</div>`;

        html += `<div><span class="text-xs text-slate-400 uppercase tracking-wide block mb-2">Packets in this Flow (${packets.length})</span>`;
        if (packets.length === 0) {
            html += '<div class="text-xs text-slate-600">No packet-level detail stored for this flow.</div>';
        } else {
            html += `<div class="overflow-y-auto border border-slate-800 rounded-lg" style="max-height:220px;">
                <table class="w-full text-left text-[11px]">
                    <thead class="text-slate-500 uppercase bg-slate-800/50 sticky top-0"><tr>
                        <th class="px-2 py-1">Time</th><th class="px-2 py-1">Dir</th><th class="px-2 py-1">Len</th><th class="px-2 py-1">Flags</th><th class="px-2 py-1">Entropy</th>
                    </tr></thead>
                    <tbody class="divide-y divide-slate-800/50">`;
            html += packets.map(p => {
                const dir = p.src_ip === flow.src_ip ? '→ fwd' : '← bwd';
                return `<tr>
                    <td class="px-2 py-1 text-slate-500 font-mono">${this.formatPacketTime(p.timestamp)}</td>
                    <td class="px-2 py-1 font-mono text-slate-400">${dir}</td>
                    <td class="px-2 py-1 text-slate-400 font-mono">${p.length}B</td>
                    <td class="px-2 py-1 text-slate-500 font-mono">${p.flags || '—'}</td>
                    <td class="px-2 py-1 text-slate-500 font-mono">${(p.payload_entropy || 0).toFixed(2)}</td>
                </tr>`;
            }).join('');
            html += `</tbody></table></div>`;
        }
        html += `</div>`;

        document.getElementById('fd-body').innerHTML = html;
    }

    riskClass(riskLevel) {
        if (riskLevel === 'HIGH RISK / ATTACK') return 'risk-high';
        if (riskLevel === 'MEDIUM RISK') return 'risk-medium';
        if (riskLevel === 'LOW RISK') return 'risk-low';
        return 'risk-benign';
    }

    protocolBadgeClass(proto) {
        const map = { HTTP: 'proto-http', HTTPS: 'proto-https', DNS: 'proto-dns', SSH: 'proto-ssh', FTP: 'proto-ftp', SMTP: 'proto-smtp' };
        return map[proto] || 'proto-unknown';
    }

    indicatorLabel(code) {
        const map = {
            SYN_FLOOD_PATTERN: 'SYN Flood',
            HIGH_PACKET_RATE: 'High Packet Rate',
            HIGH_ENTROPY_PAYLOAD: 'High Entropy Payload',
            ASYMMETRIC_FLOW: 'Asymmetric Flow',
            PORT_SCAN_PATTERN: 'Port Scan Pattern'
        };
        return map[code] || code;
    }

    formatFeatureLabel(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }

    formatFeatureValue(v) {
        if (typeof v !== 'number') return v ?? '—';
        if (Number.isInteger(v)) return v.toLocaleString();
        return v.toFixed(Math.abs(v) < 10 ? 3 : 2);
    }

    groupFeatures(features) {
        const groups = { 'Volume & Size': [], 'Timing': [], 'TCP Flags': [], 'Rate & Ratio': [], 'Other': [] };
        for (const [k, v] of Object.entries(features)) {
            if (/flag/.test(k)) groups['TCP Flags'].push([k, v]);
            else if (/(iat|duration|active|idle)/.test(k)) groups['Timing'].push([k, v]);
            else if (/(byte|packet|length|size|win|header)/.test(k)) groups['Volume & Size'].push([k, v]);
            else if (/(ratio|per_sec|entropy)/.test(k)) groups['Rate & Ratio'].push([k, v]);
            else groups['Other'].push([k, v]);
        }
        return groups;
    }

    async fetchInitialData() {
        try {
            const [statsRes, flowsRes, alertsRes, packetsRes, talkersRes] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/flows?limit=100'),
                fetch('/api/alerts?limit=50'),
                fetch('/api/packets?limit=150'),
                fetch('/api/network/talkers?minutes=60')
            ]);

            const stats = await statsRes.json();
            const flows = await flowsRes.json();
            const alerts = await alertsRes.json();
            const packets = await packetsRes.json();
            const talkers = await talkersRes.json();

            this.stats = stats;
            this.flows = flows;
            this.alerts = alerts;
            this.packets = packets;

            this.updateStats(stats);
            this.renderFlowTable();
            this.renderAlerts();
            this.renderPacketStream();
            this.renderTopTalkers(talkers);
        } catch (err) {
            console.error('Failed to fetch initial data:', err);
        }
    }

    setChartMetric(metric) {
        this.chartMetric = metric;
        this.updateTrafficChart(this.stats);
    }

    filterAlerts() {
        this.renderAlerts();
    }

    applyFilters() {
        const srcIp = document.getElementById('filter-src-ip').value;
        const dstIp = document.getElementById('filter-dst-ip').value;
        const protocol = document.getElementById('filter-protocol').value;
        const risk = document.getElementById('filter-risk').value;

        let url = '/api/flows?limit=100';
        if (srcIp) url += `&src_ip=${encodeURIComponent(srcIp)}`;
        if (dstIp) url += `&dst_ip=${encodeURIComponent(dstIp)}`;
        if (protocol) url += `&protocol=${encodeURIComponent(protocol)}`;
        if (risk) url += `&risk_level=${encodeURIComponent(risk)}`;

        fetch(url)
            .then(r => r.json())
            .then(flows => {
                this.flows = flows;
                this.currentPage = 1;
                this.renderFlowTable();
            })
            .catch(err => console.error('Filter error:', err));
    }

    clearFilters() {
        document.getElementById('filter-src-ip').value = '';
        document.getElementById('filter-dst-ip').value = '';
        document.getElementById('filter-protocol').value = '';
        document.getElementById('filter-risk').value = '';
        this.fetchInitialData();
    }

    prevPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.renderFlowTable();
        }
    }

    nextPage() {
        if (this.currentPage * this.pageSize < this.flows.length) {
            this.currentPage++;
            this.renderFlowTable();
        }
    }

    updateThreshold(value) {
        document.getElementById('threshold-value').textContent = value;

        fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_threshold: parseInt(value) })
        }).catch(err => console.error('Threshold update error:', err));
    }

    async setMode(mode) {
        // Previously this only toggled CSS classes on the two buttons -
        // it never called the backend, so clicking "Live" changed nothing
        // about what was actually capturing traffic. This now calls the
        // real /api/capture/mode endpoint, which pre-flight-checks live
        // capture (permissions, interface) before switching, and reports
        // back whether it actually worked.
        const btnSim = document.getElementById('mode-sim');
        const btnLive = document.getElementById('mode-live');
        const statusEl = document.getElementById('capture-status');
        const interfaceInput = document.getElementById('capture-interface');
        const requestedInterface = interfaceInput ? interfaceInput.value.trim() : '';

        btnSim.disabled = true;
        btnLive.disabled = true;
        statusEl.textContent = mode === 'live' ? 'Checking live capture permissions/interface...' : 'Switching...';
        statusEl.className = 'text-xs mt-1 text-slate-400';

        try {
            const res = await fetch('/api/capture/mode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    mode,
                    interface: requestedInterface || null
                })
            });
            const data = await res.json();

            if (!res.ok) {
                // The switch was rejected (bad permissions, no such
                // interface, etc.) - show the REAL reason, and leave the
                // button state reflecting what's actually still running,
                // not what the user clicked.
                statusEl.textContent = `Failed: ${data.detail || 'unknown error'}`;
                statusEl.className = 'text-xs mt-1 text-red-400';
                this.showToast('Could not switch capture mode', 'error');
                await this.refreshCaptureStatus();
                return;
            }

            this._applyModeButtonState(data.mode);
            statusEl.textContent = `Running in ${data.mode} mode` + (data.mode === 'live' ? ` on ${data.interface}` : '');
            statusEl.className = 'text-xs mt-1 text-emerald-400';
            if (data.l2_warning) {
                statusEl.textContent += ` (L2 sidecar warning: ${data.l2_warning})`;
                statusEl.className = 'text-xs mt-1 text-amber-400';
            }
            this.showToast(`Capture mode: ${data.mode}`, 'success');
        } catch (e) {
            statusEl.textContent = `Request failed: ${e}`;
            statusEl.className = 'text-xs mt-1 text-red-400';
        } finally {
            btnSim.disabled = false;
            btnLive.disabled = false;
        }
    }

    _applyModeButtonState(mode) {
        document.getElementById('mode-sim').className = mode === 'simulation'
            ? 'flex-1 px-3 py-2 text-xs rounded bg-cyan-600 text-white font-medium'
            : 'flex-1 px-3 py-2 text-xs rounded bg-slate-800 text-slate-400 hover:bg-slate-700';
        document.getElementById('mode-live').className = mode === 'live'
            ? 'flex-1 px-3 py-2 text-xs rounded bg-cyan-600 text-white font-medium'
            : 'flex-1 px-3 py-2 text-xs rounded bg-slate-800 text-slate-400 hover:bg-slate-700';
    }

    async refreshCaptureStatus() {
        // Polls the real backend state on load (and after any failed
        // switch) so the buttons always reflect what's actually running,
        // never just what was last clicked.
        try {
            const res = await fetch('/api/capture/status');
            if (!res.ok) return;
            const data = await res.json();
            const statusEl = document.getElementById('capture-status');
            this._applyModeButtonState(data.requested_mode);

            if (data.requested_mode === 'live' && !data.capture_thread_alive) {
                statusEl.textContent = `Live mode requested but capture thread is not running` +
                    (data.last_error ? `: ${data.last_error}` : '.');
                statusEl.className = 'text-xs mt-1 text-red-400';
            } else if (data.requested_mode === 'live') {
                statusEl.textContent = `Running in live mode on ${data.interface}`;
                statusEl.className = 'text-xs mt-1 text-emerald-400';
            } else {
                statusEl.textContent = 'Running in simulation mode';
                statusEl.className = 'text-xs mt-1 text-slate-500';
            }
        } catch (e) {
            const statusEl = document.getElementById('capture-status');
            if (statusEl) {
                statusEl.textContent = 'Could not reach capture status endpoint.';
                statusEl.className = 'text-xs mt-1 text-red-400';
            }
        }
    }

    refreshData() {
        this.fetchInitialData();
        this.showToast('Data refreshed', 'success');
    }

    async clearAll() {
        if (!confirm('Clear all data? This resets the dashboard to a fresh state. Nothing is deleted — the current data is archived and stays viewable via the session history.')) {
            return;
        }
        try {
            const res = await fetch('/api/session/clear', { method: 'POST' });
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            const result = await res.json();

            // Wipe local buffers so nothing stale renders before the
            // authoritative, zeroed data below takes over.
            this.flows = [];
            this.alerts = [];
            this.packets = [];
            this.trafficData = { labels: [], packets: [], bytes: [] };

            // Reset the gauge/KPIs/charts to zero immediately, rather than
            // waiting for the next periodic WebSocket "stats" push - the
            // backend has already reset its own counters at this point, so
            // this reflects real (not just locally-faked) zero state.
            this.updateStats({
                total_packets: 0,
                total_bytes: 0,
                active_flows: 0,
                alert_count: 0,
                packets_per_sec: 0,
                bytes_per_sec: 0,
                avg_threat_score: 0,
                attack_distribution: [],
                protocol_distribution: []
            });
            this.renderFlowTable();
            this.renderAlerts();
            this.renderPacketStream();

            const archived = result.archived_summary || {};
            this.showToast(
                `Dashboard cleared — ${archived.total_alerts ?? 0} alerts and ${archived.total_flows ?? 0} flows archived (session #${result.archived_session_id})`,
                'success'
            );
        } catch (err) {
            console.error('Clear failed:', err);
            this.showToast('Clear failed — dashboard was not reset. See console for details.', 'error');
        }
    }

    async exportAlerts(format) {
        try {
            const response = await fetch(`/api/export/alerts?format=${format}`);
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `aegis_alerts.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            this.showToast(`Alerts exported as ${format.toUpperCase()}`, 'success');
        } catch (err) {
            this.showToast('Export failed', 'error');
        }
    }

    startClock() {
        const updateClock = () => {
            const now = new Date();
            document.getElementById('clock').textContent = now.toLocaleTimeString('en-US', { hour12: false });
            document.getElementById('date').textContent = now.toLocaleDateString('en-US', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
        };
        updateClock();
        setInterval(updateClock, 1000);
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        const colors = {
            success: 'bg-emerald-500',
            warning: 'bg-amber-500',
            error: 'bg-rose-500',
            info: 'bg-cyan-500'
        };
        toast.className = `fixed bottom-4 right-4 ${colors[type] || colors.info} text-white px-4 py-2 rounded-lg shadow-lg text-sm font-medium z-50 animate-bounce`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    formatNumber(num) {
        if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
        if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
        if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
        return num.toString();
    }

    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    setupEventListeners() {
        document.getElementById('filter-src-ip')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.applyFilters();
        });
        document.getElementById('filter-dst-ip')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.applyFilters();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeFlowDetail();
        });
    }
}

const app = new AegisDashboard();
