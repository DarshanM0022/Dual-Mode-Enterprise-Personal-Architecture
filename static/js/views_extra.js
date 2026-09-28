// Personal Security Mode & Executive CISO Mode Controllers

let riskChartInstance = null;

// ================= PERSONAL SECURITY MODE =================
async function loadPersonalSecurity() {
    try {
        const [usersRes, devicesRes, expRes] = await Promise.all([
            fetch('/api/entities/users?tenant_id=tenant-personal-darsh'),
            fetch('/api/entities/devices?tenant_id=tenant-personal-darsh'),
            fetch('/api/entities/exposures?tenant_id=tenant-personal-darsh')
        ]);

        const users = await usersRes.json();
        const devices = await devicesRes.json();
        const exposures = await expRes.json();

        const user = users[0] || {};
        renderPersonalDashboard(user, devices, exposures);

    } catch (e) {
        console.error("Error loading personal security mode:", e);
    }
}

function renderPersonalDashboard(user, devices, exposures) {
    // Health score
    const healthScore = Math.max(30, Math.min(96, Math.round(100 - (user.risk_score || 16))));
    const scoreEl = document.getElementById('personal-health-score');
    if (scoreEl) scoreEl.textContent = `${healthScore}%`;

    // Exposures / Action items
    const expContainer = document.getElementById('personal-exposures-container');
    if (expContainer) {
        if (!exposures || exposures.length === 0) {
            expContainer.innerHTML = `<div class="p-6 text-center text-emerald-400 font-medium">✓ No personal exposures or leaked credentials found!</div>`;
        } else {
            expContainer.innerHTML = exposures.map(exp => `
                <div class="p-4 rounded-xl bg-slate-900/70 border ${exp.status === 'RESOLVED' ? 'border-emerald-500/30' : 'border-rose-500/40'} flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-3">
                    <div>
                        <div class="flex items-center gap-2 mb-1">
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${exp.status === 'RESOLVED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}">${exp.category}</span>
                            <span class="text-xs text-slate-400">${exp.discovered_at.substring(0, 10)}</span>
                        </div>
                        <h4 class="text-sm font-semibold text-slate-100">${exp.title}</h4>
                        <p class="text-xs text-slate-400 mt-1">${exp.details}</p>
                    </div>
                    ${exp.status === 'OPEN' ? `
                        <button onclick="resolvePersonalExposure('${exp.item_id}')" class="whitespace-nowrap px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all">
                            Resolve & Secure
                        </button>
                    ` : `
                        <span class="text-xs font-mono text-emerald-400 font-semibold">✓ Resolved</span>
                    `}
                </div>
            `).join('');
        }
    }

    // Devices
    const devContainer = document.getElementById('personal-devices-container');
    if (devContainer) {
        devContainer.innerHTML = (devices || []).map(dev => `
            <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center text-lg">
                        ${dev.os_type.includes('iOS') ? '📱' : '💻'}
                    </div>
                    <div>
                        <div class="text-sm font-semibold text-slate-200">${dev.hostname}</div>
                        <div class="text-xs text-slate-400">${dev.os_type} • IP: ${dev.ip_address}</div>
                    </div>
                </div>
                <div class="text-right">
                    <span class="inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold ${dev.patch_status === 'COMPLIANT' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'}">
                        ${dev.patch_status}
                    </span>
                    <div class="text-[10px] text-slate-500 mt-1">BitLocker: ${dev.disk_encryption ? 'ON' : 'OFF'}</div>
                </div>
            </div>
        `).join('');
    }
}

async function resolvePersonalExposure(itemId) {
    try {
        const res = await fetch(`/api/entities/exposures/${itemId}/resolve`, { method: 'POST' });
        if (res.ok) {
            showToast("Exposure resolved! Security health score updated.", "success");
            loadPersonalSecurity();
        }
    } catch (e) {
        showToast("Error updating exposure", "error");
    }
}

// ================= EXECUTIVE CISO MODE =================
async function loadExecutiveCharts() {
    const ctx = document.getElementById('ciso-risk-trend-canvas');
    if (!ctx) return;

    if (riskChartInstance) {
        riskChartInstance.destroy();
    }

    riskChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Day 1', 'Day 5', 'Day 10', 'Day 15', 'Day 20', 'Day 25', 'Today'],
            datasets: [
                {
                    label: 'Enterprise Risk Index (0-100)',
                    data: [28, 30, 26, 35, 42, 38, 31],
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.08)',
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true
                },
                {
                    label: 'Critical Alert Count',
                    data: [1, 2, 0, 3, 5, 2, 4],
                    borderColor: '#f43f5e',
                    backgroundColor: 'rgba(244, 63, 94, 0.05)',
                    borderWidth: 2,
                    borderDash: [5, 5],
                    tension: 0.35,
                    fill: false
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(51, 65, 85, 0.3)' },
                    ticks: { color: '#64748b', font: { family: 'Inter' } }
                },
                y: {
                    grid: { color: 'rgba(51, 65, 85, 0.3)' },
                    ticks: { color: '#64748b', font: { family: 'Inter' } }
                }
            }
        }
    });
}

window.loadPersonalSecurity = loadPersonalSecurity;
window.resolvePersonalExposure = resolvePersonalExposure;
window.loadExecutiveCharts = loadExecutiveCharts;
