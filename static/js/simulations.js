// Interactive Attack Scenario Simulation Controller

let isSimulating = false;

async function triggerAttackScenario(scenarioType) {
    if (isSimulating) {
        showToast("Simulation already in progress...", "info");
        return;
    }

    isSimulating = true;
    const banner = document.getElementById('sim-active-banner');
    const simName = document.getElementById('sim-active-name');
    if (banner) banner.classList.remove('hidden');
    if (simName) simName.textContent = scenarioType.replace(/_/g, ' ');

    showToast(`Launching attack scenario: ${scenarioType}... Watch live stream!`, 'info');

    try {
        const res = await fetch(`/api/simulations/run/${scenarioType}`, {
            method: 'POST'
        });
        const data = await res.json();

        if (res.ok) {
            showToast(`Scenario completed! ${data.events_streamed} events generated, ${data.alerts_triggered.length} alerts triggered.`, 'success');
            
            // Refresh data across platform
            if (window.loadSIEMEvents) window.loadSIEMEvents();
            if (window.loadIncidents) window.loadIncidents();
            if (window.renderEntityGraph) window.renderEntityGraph();
            if (window.fetchPlatformMetrics) window.fetchPlatformMetrics();
        } else {
            showToast(`Simulation failed: ${data.detail}`, 'error');
        }
    } catch (e) {
        showToast("Error running attack scenario", "error");
    } finally {
        isSimulating = false;
        setTimeout(() => {
            if (banner) banner.classList.add('hidden');
        }, 3000);
    }
}

window.triggerAttackScenario = triggerAttackScenario;
