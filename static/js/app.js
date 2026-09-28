// Aetheris Platform Master Application State
const state = {
    currentPerspective: 'analyst', // 'analyst' | 'personal' | 'executive'
    currentTenant: 'tenant-corp-acme',
    metrics: null,
    wsConnected: false,
    selectedIncident: null,
    selectedEvent: null
};

// WebSocket Telemetry Connection
let ws = null;
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    
    try {
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            state.wsConnected = true;
            updateConnectionBadge(true);
            console.log("[WebSocket] Real-time telemetry bus connected.");
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'NEW_EVENT') {
                    // Update SIEM stream if active
                    if (window.handleNewStreamEvent) {
                        window.handleNewStreamEvent(data.event);
                    }
                    // Refresh metrics periodically
                    fetchPlatformMetrics();
                }
            } catch (err) {
                console.error("[WebSocket] Parse error:", err);
            }
        };

        ws.onclose = () => {
            state.wsConnected = false;
            updateConnectionBadge(false);
            setTimeout(initWebSocket, 3000);
        };
        
        ws.onerror = () => {
            state.wsConnected = false;
            updateConnectionBadge(false);
        };
    } catch (e) {
        console.warn("[WebSocket] Could not connect:", e);
    }
}

function updateConnectionBadge(connected) {
    const dot = document.getElementById('ws-status-dot');
    const label = document.getElementById('ws-status-label');
    if (!dot || !label) return;

    if (connected) {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-500 pulse-emerald';
        label.textContent = 'TELEMETRY LIVE';
        label.className = 'text-xs font-mono font-medium text-emerald-400';
    } else {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-rose-500 pulse-rose';
        label.textContent = 'CONNECTING...';
        label.className = 'text-xs font-mono font-medium text-rose-400';
    }
}

// Fetch Metrics
async function fetchPlatformMetrics() {
    try {
        const res = await fetch('/api/risk/posture/metrics');
        if (res.ok) {
            state.metrics = await res.json();
            renderMetrics();
        }
    } catch (e) {
        console.error("Error fetching metrics:", e);
    }
}

function renderMetrics() {
    if (!state.metrics) return;
    const m = state.metrics;
    
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setVal('kpi-health-score', `${m.overall_security_score}%`);
    setVal('kpi-mttd', `${m.mean_time_to_detect_mins}m`);
    setVal('kpi-mttr', `${m.mean_time_to_respond_mins}m`);
    setVal('kpi-events', m.total_events_processed.toLocaleString());
    setVal('kpi-active-incidents', m.active_incidents_count);
    setVal('kpi-critical-alerts', m.critical_alerts_last_24h);
    setVal('kpi-identity-score', `${m.identity_hygiene}%`);
    setVal('kpi-device-score', `${m.endpoint_compliance}%`);
}

// Perspective Switcher
function switchPerspective(mode) {
    state.currentPerspective = mode;

    document.querySelectorAll('.view-mode-btn').forEach(btn => {
        btn.classList.remove('bg-cyan-500/20', 'text-cyan-400', 'border-cyan-500/50');
        btn.classList.add('text-slate-400', 'border-transparent');
    });

    const activeBtn = document.getElementById(`btn-mode-${mode}`);
    if (activeBtn) {
        activeBtn.classList.remove('text-slate-400', 'border-transparent');
        activeBtn.classList.add('bg-cyan-500/20', 'text-cyan-400', 'border-cyan-500/50');
    }

    document.getElementById('view-analyst').classList.toggle('hidden', mode !== 'analyst');
    document.getElementById('view-personal').classList.toggle('hidden', mode !== 'personal');
    document.getElementById('view-executive').classList.toggle('hidden', mode !== 'executive');

    if (mode === 'analyst') {
        if (window.loadSIEMEvents) window.loadSIEMEvents();
        if (window.loadIncidents) window.loadIncidents();
        if (window.renderEntityGraph) window.renderEntityGraph();
    } else if (mode === 'personal') {
        if (window.loadPersonalSecurity) window.loadPersonalSecurity();
    } else if (mode === 'executive') {
        if (window.loadExecutiveCharts) window.loadExecutiveCharts();
    }
}

// Global Toast Notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    const colorClass = type === 'success' ? 'border-emerald-500/80 text-emerald-300 bg-slate-900/90' :
                       type === 'error' ? 'border-rose-500/80 text-rose-300 bg-slate-900/90' :
                       'border-cyan-500/80 text-cyan-300 bg-slate-900/90';
    
    toast.className = `fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl backdrop-blur-md transition-all duration-300 transform translate-y-2 opacity-0 ${colorClass}`;
    toast.innerHTML = `
        <span class="text-sm font-medium">${message}</span>
        <button onclick="this.parentElement.remove()" class="text-xs opacity-60 hover:opacity-100">✕</button>
    `;

    document.body.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
    });

    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-2');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Initialization on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    fetchPlatformMetrics();
    switchPerspective('analyst');
});
