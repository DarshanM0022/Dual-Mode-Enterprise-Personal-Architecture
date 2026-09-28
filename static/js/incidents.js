// Incident Response & SOAR Playbook Controller

async function loadIncidents() {
    try {
        const res = await fetch('/api/incidents');
        if (res.ok) {
            const incidents = await res.json();
            renderIncidentCards(incidents);
        }
    } catch (e) {
        console.error("Error loading incidents:", e);
    }
}

function renderIncidentCards(incidents) {
    const container = document.getElementById('incidents-list-container');
    if (!container) return;

    if (!incidents || incidents.length === 0) {
        container.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">No active security incidents recorded.</div>`;
        return;
    }

    container.innerHTML = incidents.map(inc => {
        const sevClass = inc.severity === 'CRITICAL' ? 'badge-critical' : (inc.severity === 'HIGH' ? 'badge-high' : 'badge-medium');
        const statusBadge = inc.status === 'CONTAINMENT' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30' :
                            inc.status === 'INVESTIGATING' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                            'bg-slate-700 text-slate-300';

        const pendingActionsCount = (inc.containment_actions || []).filter(a => a.status === 'PENDING_APPROVAL').length;

        return `
            <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer shadow-md mb-3" onclick="openIncidentDetails('${inc.incident_id}')">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${sevClass}">${inc.severity}</span>
                        <span class="text-xs font-mono text-slate-400">${inc.incident_id}</span>
                    </div>
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono border ${statusBadge}">${inc.status}</span>
                </div>
                <h4 class="text-sm font-semibold text-slate-100 mb-1.5">${inc.title}</h4>
                <p class="text-xs text-slate-400 line-clamp-2 mb-3">${inc.ai_summary || 'Incident under investigation.'}</p>
                
                <div class="flex items-center justify-between text-xs pt-2 border-t border-slate-800/80">
                    <span class="text-slate-500">Lead: <strong class="text-slate-300">${inc.lead_analyst}</strong></span>
                    ${pendingActionsCount > 0 ? `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] font-mono font-semibold animate-pulse">⚡ ${pendingActionsCount} Actions Awaiting Sign-off</span>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

async function openIncidentDetails(incidentId) {
    try {
        const res = await fetch(`/api/incidents/${incidentId}`);
        if (!res.ok) return;
        const inc = await res.json();
        state.selectedIncident = inc;

        document.getElementById('inc-modal-id').textContent = inc.incident_id;
        document.getElementById('inc-modal-title').textContent = inc.title;
        document.getElementById('inc-modal-severity').textContent = inc.severity;
        document.getElementById('inc-modal-status').textContent = inc.status;
        document.getElementById('inc-modal-summary').textContent = inc.ai_summary || 'No AI summary available.';

        // Timeline
        const timelineList = document.getElementById('inc-modal-timeline');
        timelineList.innerHTML = (inc.timeline || []).map(t => `
            <li class="relative pl-6 pb-3 border-l border-slate-800 last:border-0">
                <div class="absolute -left-1.5 top-1.5 w-3 h-3 rounded-full bg-cyan-500/80"></div>
                <div class="font-mono text-[10px] text-cyan-400">${t.time ? t.time.substring(11, 19) : ''}</div>
                <div class="text-xs text-slate-200 mt-0.5">${t.event}</div>
            </li>
        `).join('');

        // Containment Actions
        const actionsList = document.getElementById('inc-modal-actions');
        actionsList.innerHTML = (inc.containment_actions || []).map(act => {
            const isExecuted = act.status === 'EXECUTED';
            return `
                <div class="p-3 rounded-lg border ${isExecuted ? 'bg-emerald-950/20 border-emerald-500/30' : 'bg-slate-900/80 border-slate-700/80'} mb-2.5">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="font-mono text-xs font-bold ${isExecuted ? 'text-emerald-400' : 'text-amber-400'}">${act.action_type}</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded ${isExecuted ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'}">${act.status}</span>
                    </div>
                    <p class="text-xs text-slate-300 mb-2">${act.description}</p>
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] text-slate-500">Target: <code class="text-cyan-400">${act.target_entity_id}</code></span>
                        ${!isExecuted ? `
                            <button onclick="executeAction('${act.action_id}')" class="py-1 px-3 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-md transition-all">
                                Authorize & Execute
                            </button>
                        ` : `
                            <span class="text-[10px] font-mono text-emerald-400">✓ Executed by ${act.approved_by || 'Analyst'}</span>
                        `}
                    </div>
                </div>
            `;
        }).join('');

        document.getElementById('incident-details-modal').classList.remove('hidden');

    } catch (e) {
        console.error("Error opening incident:", e);
    }
}

async function executeAction(actionId) {
    try {
        const res = await fetch(`/api/incidents/actions/${actionId}/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approved_by: 'Marcus Vance (Lead Analyst)' })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`SOAR Action ${data.action_type} executed successfully!`, 'success');
            if (state.selectedIncident) {
                openIncidentDetails(state.selectedIncident.incident_id);
            }
            loadIncidents();
            fetchPlatformMetrics();
        } else {
            showToast(`Failed: ${data.detail}`, 'error');
        }
    } catch (e) {
        showToast("Error executing containment action", "error");
    }
}

async function transitionIncidentStatus(newStatus) {
    if (!state.selectedIncident) return;
    try {
        const res = await fetch(`/api/incidents/${state.selectedIncident.incident_id}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus, analyst: 'Marcus Vance (Lead Analyst)' })
        });
        if (res.ok) {
            showToast(`Incident status updated to ${newStatus}`, 'success');
            openIncidentDetails(state.selectedIncident.incident_id);
            loadIncidents();
        }
    } catch (e) {
        console.error("Error transitioning status:", e);
    }
}

function closeIncidentModal() {
    const modal = document.getElementById('incident-details-modal');
    if (modal) modal.classList.add('hidden');
}

window.loadIncidents = loadIncidents;
window.openIncidentDetails = openIncidentDetails;
window.executeAction = executeAction;
window.transitionIncidentStatus = transitionIncidentStatus;
window.closeIncidentModal = closeIncidentModal;
