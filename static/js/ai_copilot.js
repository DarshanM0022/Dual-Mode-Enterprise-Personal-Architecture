// Guardrailed AI Security Copilot Controller

let copilotDrawerOpen = false;

function toggleAICopilot(forceState = null) {
    copilotDrawerOpen = forceState !== null ? forceState : !copilotDrawerOpen;
    const drawer = document.getElementById('ai-copilot-drawer');
    if (drawer) {
        if (copilotDrawerOpen) {
            drawer.classList.remove('translate-x-full');
            document.getElementById('ai-chat-input')?.focus();
        } else {
            drawer.classList.add('translate-x-full');
        }
    }
}

async function submitAICopilotMessage(customPrompt = null) {
    const input = document.getElementById('ai-chat-input');
    const prompt = (customPrompt || input.value || '').trim();
    if (!prompt) return;

    if (!customPrompt && input) input.value = '';

    appendChatMessage('user', prompt);

    // Typing indicator
    const typingId = appendTypingIndicator();

    try {
        const res = await fetch('/api/ai/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                prompt: prompt,
                role: 'SecOps Analyst',
                tenant_id: state.currentTenant
            })
        });

        removeTypingIndicator(typingId);

        if (res.ok) {
            const data = await res.json();
            appendChatMessage('assistant', data.content, data.tool_invocations, data.action_request);
        } else {
            appendChatMessage('assistant', '⚠️ Unable to process query with the security pipeline. Please try again.');
        }
    } catch (e) {
        removeTypingIndicator(typingId);
        appendChatMessage('assistant', '⚠️ Network error communicating with the AI Copilot service.');
    }
}

function appendChatMessage(role, text, tools = [], actionRequest = null) {
    const container = document.getElementById('ai-chat-messages');
    if (!container) return;

    const msgDiv = document.createElement('div');
    msgDiv.className = `flex flex-col mb-4 ${role === 'user' ? 'items-end' : 'items-start'}`;

    let toolBadges = '';
    if (tools && tools.length > 0) {
        toolBadges = `
            <div class="flex flex-wrap gap-1.5 mb-2">
                ${tools.map(t => `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/60 border border-cyan-500/40 text-cyan-300">⚙️ ${t}</span>`).join('')}
            </div>
        `;
    }

    let actionCard = '';
    if (actionRequest) {
        actionCard = `
            <div class="mt-3 p-3 rounded-lg bg-rose-950/30 border border-rose-500/40 shadow-lg">
                <div class="flex items-center justify-between mb-1.5">
                    <span class="text-xs font-mono font-bold text-rose-400">🚨 ACTION AUTHORIZATION REQUIRED</span>
                    <span class="text-[10px] font-mono bg-rose-500/20 text-rose-300 px-2 py-0.5 rounded">${actionRequest.status}</span>
                </div>
                <div class="text-xs text-slate-300 mb-2">
                    Action: <strong>${actionRequest.action_type}</strong> on <code>${actionRequest.target_entity}</code>
                </div>
                <button onclick="approveDirectAction('${actionRequest.action_type}', '${actionRequest.target_entity}')" class="w-full py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition-all">
                    Authorize Execution (Sign with Marcus Vance)
                </button>
            </div>
        `;
    }

    // Markdown render simulation
    let formattedText = text
        .replace(/\n\n/g, '<br><br>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code class="px-1 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px]">$1</code>');

    msgDiv.innerHTML = `
        <div class="max-w-[85%] rounded-2xl px-4 py-3 ${role === 'user' ? 'bg-cyan-600 text-white rounded-br-none' : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-bl-none shadow-md'}">
            ${toolBadges}
            <div class="text-xs leading-relaxed">${formattedText}</div>
            ${actionCard}
        </div>
    `;

    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
}

function appendTypingIndicator() {
    const container = document.getElementById('ai-chat-messages');
    if (!container) return null;
    const id = 'typing-' + Date.now();
    const div = document.createElement('div');
    div.id = id;
    div.className = 'flex items-center gap-1.5 p-3 rounded-2xl bg-slate-900 border border-slate-800 text-slate-400 text-xs w-28 mb-4';
    div.innerHTML = `
        <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
        <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse delay-75"></span>
        <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse delay-150"></span>
        <span class="text-[10px] font-mono ml-1">THINKING</span>
    `;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return id;
}

function removeTypingIndicator(id) {
    if (!id) return;
    const el = document.getElementById(id);
    if (el) el.remove();
}

function approveDirectAction(type, target) {
    showToast(`Action ${type} authorized by Marcus Vance! Perimeter updated.`, 'success');
    if (window.loadIncidents) window.loadIncidents();
}

window.toggleAICopilot = toggleAICopilot;
window.submitAICopilotMessage = submitAICopilotMessage;
window.approveDirectAction = approveDirectAction;
