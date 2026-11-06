/**
 * vpnban • Server Health Checker
 * Frontend Application Controller
 * Supports both Wails Desktop App and Web GUI modes seamlessly.
 */

// Application State
const state = {
  currentView: 'map',
  providers: [],
  selectedProvider: 'nordvpn',
  servers: [],
  filteredServers: [],
  selectedServerIds: new Set(),
  activeProtocols: ['wireguard', 'ikev2', 'openvpn'],
  results: [],
  filteredResults: [],
  resultFilter: 'all',
  customNodes: [],
  inspectedServer: null,
  isProbing: false,
  terminalLogs: [],
  terminalPaused: false,
  mapRegion: 'all',
  countryFilter: '',
  maxLoad: 100,
  sortBy: 'load'
};

// Check runtime environment
function isWails() {
  return typeof window.go !== 'undefined' && 
         typeof window.go.main !== 'undefined' && 
         typeof window.go.main.App !== 'undefined';
}

async function waitForWails(timeoutMs = 800) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (isWails() && window.runtime && window.runtime.EventsOn) return true;
    await new Promise(r => setTimeout(r, 25));
  }
  return isWails();
}

// Initialization
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupDropzone();
  await waitForWails();
  setupEvents();
  await loadProviders();
  await loadServers();
  renderMapNodes();
  logTerminal("vpnban CORE.V4 engine initialized. Ready for protocol auditing.");
});

// Setup top tab navigation
function setupNavigation() {
  document.querySelectorAll('.nav-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.getAttribute('data-view');
      switchView(view);
    });
  });
}

function switchView(viewName) {
  state.currentView = viewName;

  document.querySelectorAll('.view-container').forEach(v => {
    v.classList.remove('active-view');
  });
  const target = document.getElementById(`view-${viewName}`);
  if (target) {
    target.classList.add('active-view');
  }

  document.querySelectorAll('.nav-tab').forEach(btn => {
    if (btn.getAttribute('data-view') === viewName) {
      btn.classList.add('active-nav-tab');
      btn.classList.remove('text-outline');
    } else {
      btn.classList.remove('active-nav-tab');
      btn.classList.add('text-outline');
    }
  });

  if (viewName === 'map') {
    renderMapNodes();
  }
}

// Setup Wails runtime events or SSE
function setupEvents() {
  if (isWails() && window.runtime && window.runtime.EventsOn) {
    try {
      window.runtime.EventsOn('probe_event', onProbeEvent);
      logTerminal("Core event stream attached.");
      return;
    } catch (e) {
      console.warn("Wails EventsOn error:", e);
    }
  }

  // SSE fallback for Web GUI mode
  try {
    const evtSource = new EventSource('/api/events');
    evtSource.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);
        onProbeEvent(ev);
      } catch (err) {}
    };
  } catch (e) {}
}

function onProbeEvent(ev) {
  if (!ev) return;

  if (ev.type === 'log' && ev.message) {
    logTerminal(ev.message);
  } else if (ev.type === 'result' && ev.result) {
    const res = ev.result;
    upsertResult(res);
    logTerminal(`[${res.verdict}] ${res.server.hostname} (${res.server.ip}) : Ping ${res.ping_ms}ms | IKE:${res.ike} WG:${res.wg} OVPN:${res.ovpn}`);
    updateMapNodeStatus(res.server.id, res.verdict, res.ping_ms);
  } else if (ev.type === 'done') {
    state.isProbing = false;
    updateEngineState(false);
    showToast(ev.message || "Probing cycle complete", "success");
    logTerminal(ev.message || "Audit cycle finished.");
  }
}

// Terminal Console Logging
function logTerminal(msg) {
  if (state.terminalPaused) return;

  const feed = document.getElementById('terminal-feed');
  if (!feed) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
  const line = document.createElement('div');
  line.className = 'hover:bg-white/5 px-1 py-0.5 rounded transition-colors';

  let colorClass = 'text-on-surface-variant';
  if (msg.includes('[REAL]')) colorClass = 'text-secondary font-semibold';
  else if (msg.includes('[P1]')) colorClass = 'text-tertiary';
  else if (msg.includes('[SILENT]')) colorClass = 'text-outline/60';
  else if (msg.includes('🚀') || msg.includes('✅')) colorClass = 'text-primary font-semibold';

  line.innerHTML = `<span class="text-outline/60">[${timeStr}]</span> <span class="${colorClass}">${escapeHtml(msg)}</span>`;
  feed.appendChild(line);

  // Auto-scroll
  feed.scrollTop = feed.scrollHeight;

  // Keep last 150 lines
  while (feed.children.length > 150) {
    feed.removeChild(feed.firstChild);
  }
}

function clearTerminalLogs() {
  const feed = document.getElementById('terminal-feed');
  if (feed) feed.innerHTML = '';
}

function toggleTerminalPause() {
  state.terminalPaused = !state.terminalPaused;
  const btn = document.getElementById('btn-terminal-pause');
  if (btn) {
    btn.innerHTML = `<span class="material-symbols-outlined text-[15px]">${state.terminalPaused ? 'play_arrow' : 'pause'}</span>`;
  }
}

// Providers & Catalogs
async function loadProviders() {
  try {
    let providers = [];
    if (isWails()) {
      providers = await window.go.main.App.GetProviders();
    } else {
      const resp = await fetch('/api/providers');
      providers = await resp.json();
    }
    state.providers = providers;

    const select = document.getElementById('select-provider');
    if (select) {
      select.innerHTML = '';
      providers.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = `${p.name} (${p.type === 'official' ? 'Official API' : 'gluetun'})`;
        select.appendChild(opt);
      });
      select.value = state.selectedProvider;
    }
  } catch (err) {
    console.error('Failed to load providers:', err);
  }
}

async function onProviderChanged() {
  const select = document.getElementById('select-provider');
  if (!select) return;
  state.selectedProvider = select.value;
  await loadServers();
}

async function refreshCatalog() {
  showToast("Refreshing provider catalog cache...", "info");
  await loadServers(true);
}

async function loadServers(refresh = false) {
  const statusHint = document.getElementById('grid-status-hint');
  if (statusHint) statusHint.textContent = 'Fetching servers...';

  try {
    let servers = [];
    if (isWails()) {
      servers = await window.go.main.App.FetchServers(state.selectedProvider, state.countryFilter, state.maxLoad, refresh);
    } else {
      const resp = await fetch(`/api/servers?provider=${encodeURIComponent(state.selectedProvider)}&country=${encodeURIComponent(state.countryFilter)}&maxLoad=${state.maxLoad}&refresh=${refresh}`);
      servers = await resp.json();
    }
    state.servers = servers || [];
    filterServers();

    const providerObj = state.providers.find(p => p.id === state.selectedProvider);
    const mapProvName = document.getElementById('map-provider-name');
    if (mapProvName) mapProvName.textContent = providerObj ? providerObj.name : state.selectedProvider;

    const mapCount = document.getElementById('map-servers-count');
    if (mapCount) mapCount.textContent = `${state.servers.length} Servers`;

    logTerminal(`Loaded ${state.servers.length} server nodes for ${providerObj ? providerObj.name : state.selectedProvider}`);
  } catch (err) {
    console.error('Failed to fetch servers:', err);
    showToast("Error loading servers: " + err, "error");
  }
}

// Filtering & Matrix
function filterServers() {
  const input = document.getElementById('input-country-filter');
  const query = input ? input.value.trim().toLowerCase() : '';

  state.filteredServers = state.servers.filter(s => {
    if (state.maxLoad < 100 && s.load > state.maxLoad) return false;
    if (query) {
      const matchName = s.name.toLowerCase().includes(query);
      const matchHost = s.hostname.toLowerCase().includes(query);
      const matchCountry = s.country.toLowerCase().includes(query) || s.country_code.toLowerCase().includes(query);
      const matchCity = s.city.toLowerCase().includes(query);
      if (!matchName && !matchHost && !matchCountry && !matchCity) return false;
    }
    return true;
  });

  sortServerCards();
  renderServerCards();
  updateCounts();
  renderMapNodes();
}

function setCountryFilter(code) {
  const input = document.getElementById('input-country-filter');
  if (input) input.value = code;
  filterServers();
}

function onLoadSliderChanged(val) {
  state.maxLoad = parseInt(val, 10);
  const text = document.getElementById('load-val-text');
  if (text) text.textContent = `${state.maxLoad}%`;
  filterServers();
}

function sortServerCards() {
  const select = document.getElementById('select-sort');
  const sortMode = select ? select.value : 'load';

  state.filteredServers.sort((a, b) => {
    if (sortMode === 'load') return a.load - b.load;
    if (sortMode === 'country') return a.country.localeCompare(b.country);
    return a.name.localeCompare(b.name);
  });
}

function renderServerCards() {
  const grid = document.getElementById('server-cards-grid');
  if (!grid) return;

  if (state.filteredServers.length === 0) {
    grid.innerHTML = `
      <div class="col-span-full py-16 text-center text-outline font-mono text-xs">
        No servers found matching the filter criteria.
      </div>
    `;
    return;
  }

  // Display top 120 servers for buttery-smooth performance
  const displayList = state.filteredServers.slice(0, 120);

  grid.innerHTML = displayList.map(s => {
    const isSelected = state.selectedServerIds.has(s.id);
    const flag = getCountryFlag(s.country_code);

    let loadColor = 'bg-secondary';
    if (s.load > 70) loadColor = 'bg-error';
    else if (s.load > 45) loadColor = 'bg-tertiary';

    return `
      <div class="server-card bg-surface-container-low border ${isSelected ? 'border-primary/80 ring-1 ring-primary/40' : 'border-white/10'} hover:border-white/25 rounded-2xl p-4 transition-all cursor-pointer shadow-lg group relative" onclick="openInspector('${s.id}')">
        
        <div class="flex items-start justify-between gap-2 pb-2">
          <div class="flex items-center gap-2">
            <input type="checkbox" ${isSelected ? 'checked' : ''} onclick="event.stopPropagation(); toggleServerSelect('${s.id}')" class="accent-primary cursor-pointer mt-0.5"/>
            <div>
              <div class="font-bold text-on-surface text-sm flex items-center gap-1.5">
                <span>${flag}</span>
                <span class="truncate max-w-[170px]">${escapeHtml(s.name)}</span>
              </div>
              <div class="text-[11px] font-mono text-outline truncate max-w-[210px]">${escapeHtml(s.hostname)}</div>
            </div>
          </div>
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-surface-container-high text-outline uppercase">${escapeHtml(s.country_code || 'VPN')}</span>
        </div>

        <!-- Load & Ping -->
        <div class="space-y-1.5 py-2 border-t border-white/5">
          <div class="flex justify-between text-[11px] font-mono">
            <span class="text-outline">Server Load:</span>
            <span class="font-semibold text-on-surface">${s.load}%</span>
          </div>
          <div class="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
            <div class="${loadColor} h-full rounded-full transition-all" style="width: ${Math.min(s.load, 100)}%"></div>
          </div>
        </div>

        <!-- Protocols & City -->
        <div class="flex items-center justify-between pt-2 border-t border-white/5 text-[10px] font-mono">
          <span class="text-outline truncate max-w-[130px]">${escapeHtml(s.region || s.city || 'Global')}</span>
          <div class="flex gap-1">
            ${s.protocols.map(p => {
              const short = p.includes('Wire') ? 'WG' : (p.includes('IKE') ? 'IKE' : 'OVPN');
              return `<span class="px-1.5 py-0.5 rounded bg-surface-container-high text-primary-alt">${short}</span>`;
            }).join('')}
          </div>
        </div>

      </div>
    `;
  }).join('');
}

function toggleServerSelect(id) {
  if (state.selectedServerIds.has(id)) {
    state.selectedServerIds.delete(id);
  } else {
    state.selectedServerIds.add(id);
  }
  updateCounts();
  renderServerCards();
}

function selectAllServers(select) {
  if (select) {
    state.filteredServers.forEach(s => state.selectedServerIds.add(s.id));
  } else {
    state.selectedServerIds.clear();
  }
  updateCounts();
  renderServerCards();
}

function updateCounts() {
  const totalElem = document.getElementById('matrix-total-count');
  if (totalElem) totalElem.textContent = state.servers.length;

  const selElem = document.getElementById('matrix-selected-count');
  if (selElem) selElem.textContent = state.selectedServerIds.size;
}

// Inspector Drawer
function openInspector(id) {
  const s = state.servers.find(srv => srv.id === id);
  if (!s) return;
  state.inspectedServer = s;

  const drawer = document.getElementById('server-inspector-drawer');
  const content = document.getElementById('inspector-content');
  if (!drawer || !content) return;

  const flag = getCountryFlag(s.country_code);

  content.innerHTML = `
    <div class="space-y-1">
      <div class="text-xs font-mono text-outline">${escapeHtml(s.region || s.city)}</div>
      <div class="text-lg font-bold text-on-surface flex items-center gap-2">
        <span>${flag}</span>
        <span>${escapeHtml(s.name)}</span>
      </div>
    </div>

    <div class="bg-surface-container-lowest/80 border border-white/5 rounded-xl p-3 space-y-2 text-xs font-mono">
      <div class="flex justify-between">
        <span class="text-outline">IP Address:</span>
        <span class="font-semibold text-primary select-all">${escapeHtml(s.ip || 'Resolving...')}</span>
      </div>
      <div class="flex justify-between">
        <span class="text-outline">Hostname:</span>
        <span class="font-semibold text-on-surface truncate max-w-[200px] select-all">${escapeHtml(s.hostname)}</span>
      </div>
      <div class="flex justify-between">
        <span class="text-outline">Country:</span>
        <span class="text-on-surface">${escapeHtml(s.country)} (${escapeHtml(s.country_code)})</span>
      </div>
      <div class="flex justify-between">
        <span class="text-outline">Server Load:</span>
        <span class="font-semibold text-secondary">${s.load}%</span>
      </div>
      ${s.wg_public_key ? `
      <div class="flex flex-col gap-1 pt-1 border-t border-white/5">
        <span class="text-outline">WireGuard Public Key:</span>
        <span class="text-[10px] text-outline-variant font-mono break-all select-all">${escapeHtml(s.wg_public_key)}</span>
      </div>` : ''}
    </div>

    <div class="space-y-1.5 text-xs font-mono">
      <span class="text-outline">SUPPORTED PROTOCOLS</span>
      <div class="flex flex-wrap gap-1.5">
        ${s.protocols.map(p => `
          <span class="px-2.5 py-1 rounded-lg bg-surface-container-high border border-white/10 text-primary-alt font-medium">${p}</span>
        `).join('')}
      </div>
    </div>
  `;

  drawer.classList.remove('hidden');
}

function closeInspector() {
  const drawer = document.getElementById('server-inspector-drawer');
  if (drawer) drawer.classList.add('hidden');
  state.inspectedServer = null;
}

async function probeInspectedNode() {
  if (!state.inspectedServer) return;
  const srv = state.inspectedServer;
  closeInspector();
  switchView('results');
  await executeProbing([srv]);
}

// Probing Execution
async function triggerScanSelection() {
  if (state.selectedServerIds.size > 0) {
    await checkSelectedServers();
  } else {
    // Scan top 15 visible servers
    const targets = state.filteredServers.slice(0, 15);
    if (targets.length === 0) {
      showToast("No server nodes available to probe.", "info");
      return;
    }
    switchView('results');
    await executeProbing(targets);
  }
}

async function checkSelectedServers() {
  const targets = state.servers.filter(s => state.selectedServerIds.has(s.id));
  if (targets.length === 0) {
    showToast("Please select at least one server node.", "info");
    return;
  }
  switchView('results');
  await executeProbing(targets);
}

async function executeProbing(targets) {
  if (state.isProbing) {
    showToast("A probe sequence is already active.", "info");
    return;
  }

  state.isProbing = true;
  updateEngineState(true);
  logTerminal(`Starting live probe cycle against ${targets.length} targets...`);

  try {
    if (isWails()) {
      const results = await window.go.main.App.ProbeServers(targets, state.activeProtocols);
      if (results && Array.isArray(results)) {
        results.forEach(upsertResult);
      }
    } else {
      const resp = await fetch('/api/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          servers: targets,
          protocols: state.activeProtocols
        })
      });
      const data = await resp.json();
      if (data && data.results && Array.isArray(data.results)) {
        data.results.forEach(upsertResult);
      }
    }
  } catch (err) {
    console.error('Probe failed:', err);
    showToast("Probe failed: " + err, "error");
    logTerminal(`❌ Probe error: ${err}`);
  } finally {
    state.isProbing = false;
    updateEngineState(false);
  }
}

function stopProbing() {
  try {
    if (isWails()) {
      window.go.main.App.StopProbe();
    } else {
      fetch('/api/stop', { method: 'POST' });
    }
  } catch (e) {
    console.error('Stop error:', e);
  } finally {
    state.isProbing = false;
    updateEngineState(false);
    logTerminal("Probing halted by operator.");
  }
}

function updateEngineState(probing) {
  const chip = document.getElementById('engine-chip');
  const led = document.getElementById('engine-led');
  const text = document.getElementById('engine-status-text');
  const btnScan = document.getElementById('btn-quick-scan');
  const btnStop = document.getElementById('btn-stop-probe');

  if (probing) {
    if (led) {
      led.className = 'w-2 h-2 rounded-full bg-primary animate-ping';
    }
    if (text) text.textContent = 'PROBING NODES...';
    if (btnScan) btnScan.classList.add('hidden');
    if (btnStop) {
      btnStop.classList.remove('hidden');
      btnStop.classList.add('flex');
    }
  } else {
    if (led) {
      led.className = 'w-2 h-2 rounded-full bg-secondary animate-pulse';
    }
    if (text) text.textContent = 'ENGINE READY';
    if (btnScan) btnScan.classList.remove('hidden');
    if (btnStop) {
      btnStop.classList.add('hidden');
      btnStop.classList.remove('flex');
    }
  }
}

// Protocol Selection Toggles
function toggleProtocol(proto) {
  const idx = state.activeProtocols.indexOf(proto);
  if (idx >= 0) {
    if (state.activeProtocols.length > 1) {
      state.activeProtocols.splice(idx, 1);
    } else {
      showToast("At least one protocol must remain active.", "info");
      return;
    }
  } else {
    state.activeProtocols.push(proto);
  }

  // Update button styles
  const btnWG = document.getElementById('proto-wg');
  const btnIKE = document.getElementById('proto-ike');
  const btnOVPN = document.getElementById('proto-ovpn');

  if (btnWG) {
    const on = state.activeProtocols.includes('wireguard');
    btnWG.className = `proto-btn px-2 py-0.5 rounded transition-all ${on ? 'bg-secondary/15 text-secondary border border-secondary/30' : 'bg-surface-container-high text-outline border border-transparent'}`;
  }
  if (btnIKE) {
    const on = state.activeProtocols.includes('ikev2');
    btnIKE.className = `proto-btn px-2 py-0.5 rounded transition-all ${on ? 'bg-primary/15 text-primary border border-primary/30' : 'bg-surface-container-high text-outline border border-transparent'}`;
  }
  if (btnOVPN) {
    const on = state.activeProtocols.includes('openvpn');
    btnOVPN.className = `proto-btn px-2 py-0.5 rounded transition-all ${on ? 'bg-tertiary-container/20 text-tertiary border border-tertiary/30' : 'bg-surface-container-high text-outline border border-transparent'}`;
  }
}

// Results & Table Management
function upsertResult(res) {
  const idx = state.results.findIndex(r => r.id === res.id || r.server.hostname === res.server.hostname);
  if (idx >= 0) {
    state.results[idx] = res;
  } else {
    state.results.unshift(res);
  }

  updateMetrics();
  renderResultsTable();

  const countBadge = document.getElementById('results-count-badge');
  if (countBadge) {
    countBadge.textContent = state.results.length;
    countBadge.classList.remove('hidden');
  }
}

function updateMetrics() {
  const total = state.results.length;
  let real = 0, p1 = 0, silent = 0;

  state.results.forEach(r => {
    if (r.verdict === 'REAL' || r.verdict === 'FRESH') real++;
    else if (r.verdict === 'P1') p1++;
    else silent++;
  });

  const mTotal = document.getElementById('metric-total-audited');
  const mReal = document.getElementById('metric-verified-real');
  const mP1 = document.getElementById('metric-phase1-only');
  const mSilent = document.getElementById('metric-silent-count');

  if (mTotal) mTotal.textContent = total;
  if (mReal) mReal.textContent = real;
  if (mP1) mP1.textContent = p1;
  if (mSilent) mSilent.textContent = silent;
}

function setResultFilter(filter) {
  state.resultFilter = filter;
  renderResultsTable();

  document.querySelectorAll('.res-filter-btn').forEach(btn => {
    btn.className = 'res-filter-btn px-2.5 py-1 rounded-lg text-xs font-mono text-outline hover:text-white';
  });
  if (event && event.target) {
    event.target.className = 'res-filter-btn px-2.5 py-1 rounded-lg text-xs font-mono bg-primary/20 text-primary border border-primary/30';
  }
}

function renderResultsTable() {
  const tbody = document.getElementById('results-table-body');
  if (!tbody) return;

  let list = state.results;
  if (state.resultFilter === 'real') {
    list = list.filter(r => r.verdict === 'REAL' || r.verdict === 'FRESH');
  } else if (state.resultFilter === 'p1') {
    list = list.filter(r => r.verdict === 'P1');
  } else if (state.resultFilter === 'silent') {
    list = list.filter(r => r.verdict === 'SILENT');
  }

  if (list.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="py-12 text-center text-outline font-mono text-xs">
          ${state.results.length === 0 ? 'No probe results yet. Run a scan to inspect servers.' : 'No entries match this filter.'}
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = list.map(r => {
    const flag = getCountryFlag(r.server.country_code);

    let verdictBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-secondary/15 text-secondary border border-secondary/30 font-bold">REAL</span>';
    if (r.verdict === 'P1') {
      verdictBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-tertiary-container/20 text-tertiary border border-tertiary/30 font-bold">P1-ONLY</span>';
    } else if (r.verdict === 'SILENT') {
      verdictBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-error-container/20 text-error border border-error/30 font-bold">SILENT</span>';
    }

    const ikeText = r.ike === 'real' ? `<span class="text-secondary">OK (${r.ike_ms}ms)</span>` : (r.ike === 'p1' ? `<span class="text-tertiary">P1 (${r.ike_ms}ms)</span>` : '<span class="text-outline/40">silent</span>');
    const wgText = r.wg === 'real' ? `<span class="text-secondary">OK (${r.wg_ms}ms)</span>` : '<span class="text-outline/40">silent</span>';
    const ovpnText = r.ovpn === 'real' ? `<span class="text-secondary">OK (${r.ovpn_ms}ms)</span>` : '<span class="text-outline/40">silent</span>';

    return `
      <tr class="hover:bg-white/[0.02] transition-colors">
        <td class="py-3 px-4">
          <div class="font-bold text-on-surface flex items-center gap-1.5">
            <span>${flag}</span>
            <span>${escapeHtml(r.server.name)}</span>
          </div>
          <div class="text-[10px] text-outline">${escapeHtml(r.server.country)}</div>
        </td>
        <td class="py-3 px-4">
          <div class="font-mono text-primary font-semibold select-all">${escapeHtml(r.server.ip)}</div>
          <div class="font-mono text-[10px] text-outline truncate max-w-[220px] select-all">${escapeHtml(r.server.hostname)}</div>
        </td>
        <td class="py-3 px-4 font-mono">${ikeText}</td>
        <td class="py-3 px-4 font-mono">${wgText}</td>
        <td class="py-3 px-4 font-mono">${ovpnText}</td>
        <td class="py-3 px-4 text-right font-mono">${verdictBadge}</td>
      </tr>
    `;
  }).join('');
}

// Exports
async function exportData(format) {
  if (state.results.length === 0) {
    showToast("No probe results to export yet.", "info");
    return;
  }

  try {
    if (isWails()) {
      const savedPath = await window.go.main.App.SaveExportFile(format, state.results);
      if (savedPath) {
        showToast(`Export saved successfully to: ${savedPath}`, "success");
      }
    } else {
      // Browser download
      const resp = await fetch(`/api/export?format=${format}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(state.results)
      });
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vpnban-results.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      showToast(`Exported vpnban-results.${format}`, "success");
    }
  } catch (err) {
    console.error('Export error:', err);
    showToast("Export failed: " + err, "error");
  }
}

// Custom Node Ingress (My List)
function setupDropzone() {
  const dz = document.getElementById('ingress-dropzone');
  if (!dz) return;

  dz.addEventListener('dragover', (e) => {
    e.preventDefault();
    dz.classList.add('border-primary');
  });

  dz.addEventListener('dragleave', () => {
    dz.classList.remove('border-primary');
  });

  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    dz.classList.remove('border-primary');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files);
    }
  });
}

function triggerFileUpload() {
  if (isWails()) {
    window.go.main.App.SelectFile().then(fileData => {
      if (fileData && fileData.content) {
        parseAndStageCustomContent(fileData.content);
      }
    }).catch(err => {
      console.error(err);
    });
  } else {
    const fileInput = document.getElementById('file-input');
    if (fileInput) fileInput.click();
  }
}

function handleFileSelected(files) {
  if (!files || files.length === 0) return;
  const file = files[0];
  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    parseAndStageCustomContent(content);
  };
  reader.readAsText(file);
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      parseAndStageCustomContent(text);
    } else {
      showToast("Clipboard is empty.", "info");
    }
  } catch (err) {
    const pasted = prompt("Paste your servers list or JSON catalog here:");
    if (pasted) parseAndStageCustomContent(pasted);
  }
}

async function parseAndStageCustomContent(content) {
  const allowPoison = document.getElementById('check-allow-poisoned')?.checked || false;
  showToast("Resolving domains and checking endpoints...", "info");

  try {
    let nodes = [];
    if (isWails()) {
      nodes = await window.go.main.App.ParseCustomInput(content, allowPoison);
    } else {
      const resp = await fetch('/api/custom/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, allowPoison })
      });
      nodes = await resp.json();
    }

    state.customNodes = nodes || [];
    renderCustomStaging();

    const countElem = document.getElementById('custom-staged-count');
    if (countElem) countElem.textContent = state.customNodes.length;

    showToast(`Staged ${state.customNodes.length} custom server nodes`, "success");
  } catch (err) {
    console.error('Custom parse error:', err);
    showToast("Failed to parse input: " + err, "error");
  }
}

function renderCustomStaging() {
  const tbody = document.getElementById('custom-staging-body');
  if (!tbody) return;

  if (state.customNodes.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="py-12 text-center text-outline font-mono text-xs">
          Staging area is empty. Upload or paste a hostlist to stage endpoints for probing.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.customNodes.map((node, i) => {
    let statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-secondary/15 text-secondary border border-secondary/30 font-bold">RESOLVED</span>';
    if (node.status === 'POISONED_IP') {
      statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-error-container/20 text-error border border-error/30 font-bold">POISONED (10.x / 192.168)</span>';
    } else if (node.status === 'FAILED') {
      statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-surface-container-high text-outline font-bold">FAILED</span>';
    }

    return `
      <tr class="hover:bg-white/[0.02] transition-colors">
        <td class="py-3 px-4 font-mono">${statusBadge}</td>
        <td class="py-3 px-4 font-mono">
          <div class="font-bold text-on-surface select-all">${escapeHtml(node.hostname)}</div>
          <div class="text-[10px] text-primary select-all">${escapeHtml(node.resolved_ip || 'No IP')}</div>
        </td>
        <td class="py-3 px-4 font-mono">${escapeHtml(node.country)}</td>
        <td class="py-3 px-4 font-mono text-outline">${escapeHtml(node.architecture)}</td>
        <td class="py-3 px-4 font-mono text-outline">UDP :${node.port}</td>
        <td class="py-3 px-4 text-right">
          <button onclick="removeCustomNode(${i})" class="p-1 rounded text-outline hover:text-error hover:bg-white/5 transition-colors" title="Delete">
            <span class="material-symbols-outlined text-[16px]">delete</span>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function removeCustomNode(index) {
  state.customNodes.splice(index, 1);
  renderCustomStaging();
  const countElem = document.getElementById('custom-staged-count');
  if (countElem) countElem.textContent = state.customNodes.length;
}

function clearCustomStaging() {
  state.customNodes = [];
  renderCustomStaging();
  const countElem = document.getElementById('custom-staged-count');
  if (countElem) countElem.textContent = '0';
}

async function startProbingCustomList() {
  if (state.customNodes.length === 0) {
    showToast("Please import or stage custom nodes first.", "info");
    return;
  }

  // Convert custom nodes to UnifiedServer format
  const targets = state.customNodes.map((n, i) => ({
    id: `custom-${i + 1}`,
    name: n.hostname,
    hostname: n.hostname,
    ip: n.resolved_ip,
    country: n.country,
    country_code: n.country_code || 'US',
    city: 'Custom',
    region: 'Custom Cluster',
    load: 10,
    status: 'online',
    protocols: ['WireGuard', 'IKEv2', 'OpenVPN'],
    provider: 'custom'
  }));

  switchView('results');
  await executeProbing(targets);
}

// Global Map Nodes Rendering
function renderMapNodes() {
  const layer = document.getElementById('map-nodes-layer');
  if (!layer) return;

  // Key global anchor locations for the vector map
  const anchors = [
    { id: 'london', name: 'London Cluster', country: 'United Kingdom', x: 590, y: 190, color: '#64D2FF', ping: '18ms' },
    { id: 'frankfurt', name: 'Frankfurt Cluster', country: 'Germany', x: 620, y: 205, color: '#47E266', ping: '22ms' },
    { id: 'stockholm', name: 'Stockholm Cluster', country: 'Sweden', x: 635, y: 155, color: '#47E266', ping: '16ms' },
    { id: 'newyork', name: 'New York Cluster', country: 'United States', x: 330, y: 220, color: '#64D2FF', ping: '35ms' },
    { id: 'chicago', name: 'Chicago Cluster', country: 'United States', x: 280, y: 210, color: '#64D2FF', ping: '42ms' },
    { id: 'tokyo', name: 'Tokyo Cluster', country: 'Japan', x: 970, y: 270, color: '#64D2FF', ping: '85ms' },
    { id: 'singapore', name: 'Singapore Cluster', country: 'Singapore', x: 880, y: 390, color: '#47E266', ping: '65ms' },
    { id: 'sydney', name: 'Sydney Cluster', country: 'Australia', x: 1040, y: 550, color: '#64D2FF', ping: '120ms' },
  ];

  let displayAnchors = anchors;
  if (state.mapRegion === 'europe') {
    displayAnchors = anchors.filter(a => ['london', 'frankfurt', 'stockholm'].includes(a.id));
  } else if (state.mapRegion === 'na') {
    displayAnchors = anchors.filter(a => ['newyork', 'chicago'].includes(a.id));
  } else if (state.mapRegion === 'apac') {
    displayAnchors = anchors.filter(a => ['tokyo', 'singapore', 'sydney'].includes(a.id));
  }

  layer.innerHTML = displayAnchors.map(a => `
    <g class="cursor-pointer group" onclick="switchView('matrix'); setCountryFilter('${a.country.split(' ')[0]}');">
      <!-- Outer pulse circle -->
      <circle cx="${a.x}" cy="${a.y}" r="16" fill="${a.color}" opacity="0.18">
        <animate attributeName="r" values="12;24;12" dur="3s" repeatCount="indefinite"/>
        <animate attributeName="opacity" values="0.3;0.05;0.3" dur="3s" repeatCount="indefinite"/>
      </circle>
      <!-- Core circle -->
      <circle cx="${a.x}" cy="${a.y}" r="4.5" fill="${a.color}" stroke="#0B0C0F" stroke-width="1.5"></circle>
      <!-- Pin label -->
      <text x="${a.x + 8}" y="${a.y + 4}" fill="#e3e2e6" font-size="10" font-family="JetBrains Mono" font-weight="500">${a.name} (${a.ping})</text>
    </g>
  `).join('');
}

function filterMapRegion(region) {
  state.mapRegion = region;
  renderMapNodes();

  document.querySelectorAll('.region-pill').forEach(btn => {
    btn.className = 'region-pill px-2.5 py-1 rounded-lg text-xs font-mono text-outline hover:text-white';
  });
  if (event && event.target) {
    event.target.className = 'region-pill px-2.5 py-1 rounded-lg text-xs font-mono bg-primary/20 text-primary border border-primary/30';
  }
}

function updateMapNodeStatus(id, verdict, ping) {
  // Update UI node indicator if needed
}

// Helpers
function getCountryFlag(code) {
  if (!code) return '🌐';
  const c = code.toUpperCase().trim();
  const flags = {
    'SE': '🇸🇪', 'DE': '🇩🇪', 'US': '🇺🇸', 'UK': '🇬🇧', 'GB': '🇬🇧',
    'NL': '🇳🇱', 'JP': '🇯🇵', 'FR': '🇫🇷', 'CA': '🇨🇦', 'CH': '🇨🇭',
    'NO': '🇳🇴', 'FI': '🇫🇮', 'PL': '🇵🇱', 'ES': '🇪🇸', 'IT': '🇮🇹',
    'AU': '🇦🇺', 'SG': '🇸🇬', 'BR': '🇧🇷', 'IN': '🇮🇳', 'HK': '🇭🇰'
  };
  return flags[c] || '🌐';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  let borderClass = 'border-primary/40 text-primary';
  if (type === 'error') borderClass = 'border-error/40 text-error';
  if (type === 'success') borderClass = 'border-secondary/40 text-secondary';

  toast.className = `px-4 py-2.5 rounded-xl bg-[#121316]/95 border ${borderClass} shadow-2xl text-xs font-mono backdrop-blur-xl transition-all transform translate-y-2 opacity-0 flex items-center gap-2 pointer-events-auto`;
  toast.innerHTML = `
    <span class="material-symbols-outlined text-[16px]">${type === 'error' ? 'error' : (type === 'success' ? 'check_circle' : 'info')}</span>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  setTimeout(() => {
    toast.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

