// SIEM & Real-Time Log Stream Controller

async function loadSIEMEvents() {
    const q = document.getElementById('siem-search-input')?.value || '';
    const sev = document.getElementById('siem-filter-severity')?.value || '';
    const type = document.getElementById('siem-filter-type')?.value || '';

    let url = `/api/siem/events?limit=40`;
    if (q) url += `&q=${encodeURIComponent(q)}`;
    if (sev) url += `&severity=${encodeURIComponent(sev)}`;
    if (type) url += `&event_type=${encodeURIComponent(type)}`;

    try {
        const res = await fetch(url);
        if (res.ok) {
            const data = await res.json();
            renderEventTable(data.events);
            const totalEl = document.getElementById('siem-total-count');
            if (totalEl) totalEl.textContent = `${data.total} Total Events`;
        }
    } catch (e) {
        console.error("Error loading SIEM events:", e);
    }
}

function renderEventTable(events) {
    const tbody = document.getElementById('siem-events-tbody');
    if (!tbody) return;

    if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500 font-mono text-sm">No telemetry events match query criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map(e => createEventRowHtml(e)).join('');
}

function createEventRowHtml(e, isNew = false) {
    const timeFormatted = e.timestamp ? e.timestamp.replace('T', ' ').substring(11, 19) : '--:--:--';
    const actorName = e.actor?.name || e.actor?.id || 'SYSTEM';
    const sourceIp = e.network?.source_ip || e.source?.ip || 'Internal';
    const targetName = e.destination?.name || e.source?.hostname || 'Perimeter';
    const actionName = e.action || 'Unknown';
    const vendor = e.raw_source_vendor || 'Collector';
    
    const sevClass = {
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low',
        'INFORMATIONAL': 'badge-info'
    }[e.severity] || 'badge-info';

    return `
        <tr class="log-row border-b border-slate-800/60 cursor-pointer ${isNew ? 'highlight-new' : ''}" onclick="inspectEvent('${e.event_id}')">
            <td class="py-2.5 px-3 font-mono text-xs text-slate-400 whitespace-nowrap">${timeFormatted}</td>
            <td class="py-2.5 px-3">
                <span class="inline-block px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${sevClass}">${e.severity}</span>
            </td>
            <td class="py-2.5 px-3 font-medium text-xs text-slate-200">${actorName}</td>
            <td class="py-2.5 px-3 font-mono text-xs text-cyan-400">${actionName}</td>
            <td class="py-2.5 px-3 font-mono text-xs text-slate-400">${sourceIp}</td>
            <td class="py-2.5 px-3 text-xs text-slate-300 truncate max-w-[180px]">${targetName}</td>
            <td class="py-2.5 px-3 text-right font-mono text-[11px] text-slate-500">${vendor}</td>
        </tr>
    `;
}

// Live WebSocket Stream Hook
window.handleNewStreamEvent = function(event) {
    const tbody = document.getElementById('siem-events-tbody');
    if (!tbody) return;

    // Prepend new row
    const tempDiv = document.createElement('tbody');
    tempDiv.innerHTML = createEventRowHtml(event, true);
    const newRow = tempDiv.firstElementChild;
    tbody.insertBefore(newRow, tbody.firstChild);

    // Keep max 60 rows in DOM
    if (tbody.children.length > 60) {
        tbody.removeChild(tbody.lastChild);
    }

    // Flash live stream badge
    const badge = document.getElementById('live-stream-badge');
    if (badge) {
        badge.classList.add('bg-cyan-500/30', 'text-cyan-300');
        setTimeout(() => badge.classList.remove('bg-cyan-500/30', 'text-cyan-300'), 500);
    }
};

// Inspect Event Modal
async function inspectEvent(eventId) {
    try {
        const res = await fetch(`/api/siem/events?q=${eventId}&limit=1`);
        if (res.ok) {
            const data = await res.json();
            if (data.events && data.events.length > 0) {
                const ev = data.events[0];
                document.getElementById('modal-event-id').textContent = ev.event_id;
                document.getElementById('modal-event-type').textContent = `${ev.event_type} (${ev.action})`;
                document.getElementById('modal-event-severity').textContent = ev.severity;
                document.getElementById('modal-event-actor').textContent = JSON.stringify(ev.actor, null, 2);
                document.getElementById('modal-event-source').textContent = JSON.stringify(ev.source, null, 2);
                document.getElementById('modal-event-network').textContent = JSON.stringify(ev.network || {}, null, 2);
                document.getElementById('modal-event-json').textContent = JSON.stringify(ev, null, 2);
                
                document.getElementById('event-inspector-modal').classList.remove('hidden');
            }
        }
    } catch (e) {
        console.error("Error inspecting event:", e);
    }
}

function closeEventModal() {
    const modal = document.getElementById('event-inspector-modal');
    if (modal) modal.classList.add('hidden');
}

window.loadSIEMEvents = loadSIEMEvents;
window.inspectEvent = inspectEvent;
window.closeEventModal = closeEventModal;
