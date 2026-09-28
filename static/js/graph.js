// Entity Relationship Graph & Blast Radius Controller
let network = null;

async function renderEntityGraph() {
    const container = document.getElementById('network-graph-canvas');
    if (!container) return;

    try {
        const res = await fetch('/api/risk/graph');
        if (!res.ok) return;
        const data = await res.json();

        const visData = {
            nodes: new vis.DataSet(data.nodes),
            edges: new vis.DataSet(data.edges)
        };

        const options = {
            nodes: {
                borderWidth: 2,
                font: {
                    color: '#f8fafc',
                    face: 'Inter',
                    size: 11
                },
                scaling: {
                    min: 15,
                    max: 40
                }
            },
            edges: {
                width: 1.5,
                font: {
                    color: '#94a3b8',
                    size: 9,
                    align: 'middle'
                },
                smooth: {
                    type: 'continuous'
                }
            },
            physics: {
                barnesHut: {
                    gravitationalConstant: -3000,
                    centralGravity: 0.3,
                    springLength: 120,
                    springConstant: 0.04
                },
                stabilization: { iterations: 150 }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200
            }
        };

        network = new vis.Network(container, visData, options);

        network.on("selectNode", function (params) {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                inspectGraphNode(nodeId);
            }
        });

    } catch (e) {
        console.error("Error rendering entity graph:", e);
    }
}

async function inspectGraphNode(nodeId) {
    const infoPanel = document.getElementById('graph-node-details');
    if (!infoPanel) return;

    infoPanel.innerHTML = `
        <div class="p-4 rounded-lg bg-slate-800/80 border border-slate-700/60">
            <div class="flex items-center justify-between mb-3">
                <span class="text-xs font-mono text-cyan-400 font-semibold">${nodeId}</span>
                <span class="text-[10px] px-2 py-0.5 rounded bg-slate-700 text-slate-300">Selected Node</span>
            </div>
            <p class="text-xs text-slate-300 mb-4">Querying blast radius and reachable dependencies...</p>
            <button onclick="runBlastRadiusCalculation('${nodeId}')" class="w-full py-2 px-3 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all">
                Evaluate Blast Radius & Exposure
            </button>
        </div>
    `;

    // Automatically run blast radius
    runBlastRadiusCalculation(nodeId);
}

async function runBlastRadiusCalculation(nodeId) {
    try {
        const res = await fetch(`/api/risk/blast-radius/${nodeId}?max_hops=2`);
        if (res.ok) {
            const data = await res.json();
            const panel = document.getElementById('graph-node-details');
            if (!panel) return;

            const reachableHtml = (data.reachable_assets || []).map(a => `
                <div class="flex items-center justify-between py-1.5 border-b border-slate-800 text-xs">
                    <span class="text-slate-300 truncate max-w-[140px]">${a.label}</span>
                    <span class="font-mono text-[10px] ${a.risk > 50 ? 'text-rose-400' : 'text-emerald-400'}">Risk ${a.risk} (${a.hops} hop)</span>
                </div>
            `).join('');

            panel.innerHTML = `
                <div class="p-4 rounded-lg bg-slate-900/90 border border-cyan-500/40 shadow-xl">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-mono font-bold text-cyan-400">${data.target}</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${data.blast_radius_score > 60 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'}">
                            Blast Score: ${data.blast_radius_score}/100
                        </span>
                    </div>
                    <p class="text-[11px] text-slate-400 mb-3">
                        Compromise of this entity exposes <strong>${data.exposed_asset_count} connected assets</strong> within 2 network hops.
                    </p>
                    <div class="max-h-48 overflow-y-auto pr-1 mb-3">
                        ${reachableHtml}
                    </div>
                    <button onclick="triggerAICopilotInvestigation('${data.target}')" class="w-full py-1.5 px-3 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition-all">
                        Ask AI Copilot to Plan Containment
                    </button>
                </div>
            `;
        }
    } catch (e) {
        console.error("Error computing blast radius:", e);
    }
}

function triggerAICopilotInvestigation(entityId) {
    const input = document.getElementById('ai-chat-input');
    if (input) {
        input.value = `Investigate entity ${entityId}, analyze its blast radius, and recommend containment.`;
        if (window.toggleAICopilot) window.toggleAICopilot(true);
        if (window.submitAICopilotMessage) window.submitAICopilotMessage();
    }
}

window.renderEntityGraph = renderEntityGraph;
window.runBlastRadiusCalculation = runBlastRadiusCalculation;
window.triggerAICopilotInvestigation = triggerAICopilotInvestigation;
