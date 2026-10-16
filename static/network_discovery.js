/**
 * DDoS-Guard — Local Network Discovery & Asset Inventory Engine
 * Frontend Controller for Subnet Reconnaissance, ARP/ICMP Telemetry, and Device Catalog
 */

(function () {
  'use strict';

  // State Management
  const state = {
    networkInfo: null,
    scanStatus: 'idle', // 'idle' | 'scanning' | 'completed' | 'stopped' | 'error'
    scanId: null,
    pollInterval: null,
    devices: [],
    filterCategory: 'all',
    searchQuery: '',
    sortColumn: 'ip',
    sortAsc: true,
    selectedDevice: null
  };

  // DOM Elements
  const elements = {
    // Top Nav / Health
    ndHealthDot: document.getElementById('ndHealthDot'),
    ndHealthLabel: document.getElementById('ndHealthLabel'),
    ndHeaderCtaBtn: document.getElementById('ndHeaderCtaBtn'),
    menuToggle: document.getElementById('menuToggle'),
    mainNav: document.getElementById('mainNav'),

    // KPI Summary
    kpiTotalDevices: document.getElementById('kpiTotalDevices'),
    kpiOnlineDevices: document.getElementById('kpiOnlineDevices'),
    kpiGatewayDevice: document.getElementById('kpiGatewayDevice'),
    kpiScanDuration: document.getElementById('kpiScanDuration'),

    // Network Ribbon
    ndStateBadge: document.getElementById('ndStateBadge'),
    ndAdapterName: document.getElementById('ndAdapterName'),
    ndLocalIp: document.getElementById('ndLocalIp'),
    ndLocalMac: document.getElementById('ndLocalMac'),
    ndSubnetMask: document.getElementById('ndSubnetMask'),
    ndDefaultGateway: document.getElementById('ndDefaultGateway'),

    // Controls
    ndSubnetInput: document.getElementById('ndSubnetInput'),
    ndUseLocalSubnetBtn: document.getElementById('ndUseLocalSubnetBtn'),
    ndTimeoutSelect: document.getElementById('ndTimeoutSelect'),
    ndConcurrencySelect: document.getElementById('ndConcurrencySelect'),
    ndStartBtn: document.getElementById('ndStartBtn'),
    ndStopBtn: document.getElementById('ndStopBtn'),
    ndRescanBtn: document.getElementById('ndRescanBtn'),

    // Progress & Alert
    ndProgressBox: document.getElementById('ndProgressBox'),
    ndProgressBar: document.getElementById('ndProgressBar'),
    ndProgressStatus: document.getElementById('ndProgressStatus'),
    ndProgressPct: document.getElementById('ndProgressPct'),
    ndAlertBanner: document.getElementById('ndAlertBanner'),
    ndAlertMessage: document.getElementById('ndAlertMessage'),

    // Filter Tabs & Search
    filterTabs: document.querySelectorAll('.nd-filter-tab'),
    countAll: document.getElementById('countAll'),
    countOnline: document.getElementById('countOnline'),
    countRouters: document.getElementById('countRouters'),
    countComputers: document.getElementById('countComputers'),
    countMobile: document.getElementById('countMobile'),
    countIot: document.getElementById('countIot'),
    ndSearchInput: document.getElementById('ndSearchInput'),

    // Table
    ndDeviceTable: document.getElementById('ndDeviceTable'),
    ndTableBody: document.getElementById('ndTableBody'),
    tableHeaders: document.querySelectorAll('#ndDeviceTable thead th[data-sort]'),

    // Modal Drawer
    ndDeviceModalBackdrop: document.getElementById('ndDeviceModalBackdrop'),
    ndDeviceModal: document.getElementById('ndDeviceModal'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    modalDeviceAvatar: document.getElementById('modalDeviceAvatar'),
    modalDeviceTitle: document.getElementById('modalDeviceTitle'),
    modalDeviceSubtitle: document.getElementById('modalDeviceSubtitle'),
    modalHostname: document.getElementById('modalHostname'),
    modalIp: document.getElementById('modalIp'),
    modalMac: document.getElementById('modalMac'),
    modalVendor: document.getElementById('modalVendor'),
    modalCategory: document.getElementById('modalCategory'),
    modalBasis: document.getElementById('modalBasis'),
    modalLastSeen: document.getElementById('modalLastSeen'),
    modalMethods: document.getElementById('modalMethods'),
    modalPortScanLink: document.getElementById('modalPortScanLink')
  };

  // Helper: Sanitize Text
  function escapeHtml(text) {
    if (!text && text !== 0) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Device Category Icon Mapping
  function getDeviceIcon(category, vendor, isGateway, isLocalHost) {
    if (isGateway) return 'fa-shield-halved';
    const cat = (category || '').toLowerCase();
    const ven = (vendor || '').toLowerCase();

    if (cat.includes('router') || cat.includes('gateway') || cat.includes('access point')) {
      return 'fa-wifi';
    }
    if (cat.includes('computer') || cat.includes('workstation') || isLocalHost) {
      return 'fa-laptop';
    }
    if (cat.includes('mobile') || ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi')) {
      return 'fa-mobile-screen-button';
    }
    if (cat.includes('printer')) {
      return 'fa-print';
    }
    if (cat.includes('iot') || cat.includes('embedded') || ven.includes('espressif') || ven.includes('raspberry')) {
      return 'fa-microchip';
    }
    return 'fa-desktop';
  }

  // IP Natural Octet Compare for Sorting
  function compareIps(ipA, ipB) {
    const partsA = (ipA || '').split('.').map(Number);
    const partsB = (ipB || '').split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      const a = partsA[i] || 0;
      const b = partsB[i] || 0;
      if (a !== b) return a - b;
    }
    return 0;
  }

  // Show/Hide Alert Banner
  function showAlert(msg) {
    if (elements.ndAlertBanner && elements.ndAlertMessage) {
      elements.ndAlertMessage.textContent = msg;
      elements.ndAlertBanner.style.display = 'flex';
    }
  }

  function hideAlert() {
    if (elements.ndAlertBanner) {
      elements.ndAlertBanner.style.display = 'none';
    }
  }

  // 1. Fetch Network Configuration on Load
  async function loadNetworkInfo() {
    try {
      const res = await fetch('/api/network-discovery/network-info');
      const data = await res.json();
      if (data.status === 'success' && data.network) {
        state.networkInfo = data.network;
        renderNetworkInfo(data.network);
      } else {
        showAlert(data.message || 'Unable to detect active local network interface.');
      }
    } catch (err) {
      showAlert('Failed to connect to Network Discovery API. Ensure Flask server is online.');
    }
  }

  function renderNetworkInfo(net) {
    if (elements.ndAdapterName) elements.ndAdapterName.textContent = net.adapter_name || 'Ethernet / Wi-Fi';
    if (elements.ndLocalIp) elements.ndLocalIp.textContent = net.local_ip || '--';
    if (elements.ndLocalMac) elements.ndLocalMac.textContent = net.local_mac || 'Unavailable';
    if (elements.ndSubnetMask) elements.ndSubnetMask.textContent = net.subnet_mask || '255.255.255.0';
    if (elements.ndDefaultGateway) elements.ndDefaultGateway.textContent = net.default_gateway || 'None';
    if (elements.kpiGatewayDevice) elements.kpiGatewayDevice.textContent = net.default_gateway || '--';

    if (elements.ndHealthLabel && elements.ndHealthDot) {
      if (net.is_connected) {
        elements.ndHealthLabel.textContent = `Adapter: ${net.adapter_name} (${net.local_ip})`;
        elements.ndHealthDot.className = 'health-dot running';
      } else {
        elements.ndHealthLabel.textContent = 'Adapter: Disconnected / Offline';
        elements.ndHealthDot.className = 'health-dot idle';
      }
    }

    if (elements.ndSubnetInput && !elements.ndSubnetInput.value) {
      elements.ndSubnetInput.value = net.subnet_cidr || '192.168.1.0/24';
    }
  }

  // 2. Scan Controls: Start, Stop, Rescan
  async function startDiscoveryScan() {
    hideAlert();
    const subnet = (elements.ndSubnetInput ? elements.ndSubnetInput.value : '').trim();
    const timeout = parseFloat(elements.ndTimeoutSelect ? elements.ndTimeoutSelect.value : 0.6);
    const concurrency = parseInt(elements.ndConcurrencySelect ? elements.ndConcurrencySelect.value : 50, 10);

    if (!subnet) {
      showAlert('Please specify a valid IPv4 subnet in CIDR notation (e.g. 192.168.1.0/24).');
      return;
    }

    setScanUiState('starting');

    try {
      const res = await fetch('/api/network-discovery/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet, timeout, concurrency })
      });
      const data = await res.json();

      if (res.ok && (data.status === 'scanning' || data.status === 'already_scanning')) {
        state.scanStatus = 'scanning';
        state.scanId = data.scan_id;
        setScanUiState('scanning');
        startStatusPolling();
      } else {
        setScanUiState('error');
        showAlert(data.message || 'Failed to initiate network discovery scan.');
      }
    } catch (err) {
      setScanUiState('error');
      showAlert('Error communicating with discovery service: ' + err.message);
    }
  }

  async function stopDiscoveryScan() {
    try {
      const res = await fetch('/api/network-discovery/stop', { method: 'POST' });
      const data = await res.json();
      state.scanStatus = 'stopped';
      setScanUiState('stopped');
      stopStatusPolling();
      // Fetch final state
      fetchScanStatus();
    } catch (err) {
      showAlert('Failed to cancel scan: ' + err.message);
    }
  }

  function rescanDiscovery() {
    if (state.scanStatus === 'scanning') {
      stopDiscoveryScan().then(() => {
        setTimeout(startDiscoveryScan, 300);
      });
    } else {
      startDiscoveryScan();
    }
  }

  function setScanUiState(st) {
    if (elements.ndStateBadge) {
      elements.ndStateBadge.className = 'nd-badge-state ' + st;
      elements.ndStateBadge.textContent =
        st === 'scanning' ? 'Scanning Subnet...' :
        st === 'completed' ? 'Scan Completed' :
        st === 'stopped' ? 'Scan Stopped' :
        st === 'error' ? 'Scan Error' : 'Ready';
    }

    if (st === 'scanning' || st === 'starting') {
      if (elements.ndStartBtn) elements.ndStartBtn.style.display = 'none';
      if (elements.ndStopBtn) elements.ndStopBtn.style.display = 'inline-flex';
      if (elements.ndProgressBox) elements.ndProgressBox.style.display = 'block';
    } else {
      if (elements.ndStartBtn) elements.ndStartBtn.style.display = 'inline-flex';
      if (elements.ndStopBtn) elements.ndStopBtn.style.display = 'none';
      if (st === 'completed' || st === 'stopped') {
        if (elements.ndProgressBox) elements.ndProgressBox.style.display = 'block';
      }
    }
  }

  // 3. Status Polling Loop
  function startStatusPolling() {
    stopStatusPolling();
    state.pollInterval = setInterval(fetchScanStatus, 500);
    fetchScanStatus();
  }

  function stopStatusPolling() {
    if (state.pollInterval) {
      clearInterval(state.pollInterval);
      state.pollInterval = null;
    }
  }

  async function fetchScanStatus() {
    try {
      const res = await fetch('/api/network-discovery/status');
      if (!res.ok) return;
      const data = await res.json();

      state.scanStatus = data.status || 'idle';
      state.devices = data.devices || [];

      // Update KPIs
      if (elements.kpiTotalDevices) elements.kpiTotalDevices.textContent = data.devices_count || state.devices.length;
      if (elements.kpiOnlineDevices) elements.kpiOnlineDevices.textContent = data.online_count || state.devices.length;
      if (elements.kpiScanDuration) elements.kpiScanDuration.textContent = (data.duration_s || 0).toFixed(1) + 's';

      // Update Progress
      const pct = Math.round(data.progress_pct || 0);
      if (elements.ndProgressBar) elements.ndProgressBar.style.width = pct + '%';
      if (elements.ndProgressPct) elements.ndProgressPct.textContent = pct + '%';
      if (elements.ndProgressStatus) {
        elements.ndProgressStatus.textContent =
          data.status === 'scanning'
            ? `Probing hosts (${data.scanned_hosts || 0}/${data.total_hosts || 0} checked) — ${data.devices_count || 0} responsive hosts discovered`
            : data.message || 'Discovery complete.';
      }

      // Update Category Counts
      updateCategoryCounts(state.devices);

      // Render Table
      renderDeviceTable();

      // Check Completion
      if (data.status === 'completed' || data.status === 'stopped' || data.status === 'error') {
        stopStatusPolling();
        setScanUiState(data.status);
      }
    } catch (err) {
      // transient network glitch
    }
  }

  // 4. Category Counting & Filtering
  function updateCategoryCounts(devices) {
    let online = 0, routers = 0, computers = 0, mobile = 0, iot = 0;
    devices.forEach(dev => {
      if (dev.status === 'Online') online++;
      const cat = (dev.device_type || '').toLowerCase();
      const ven = (dev.vendor || '').toLowerCase();
      if (dev.is_gateway || cat.includes('router') || cat.includes('gateway') || cat.includes('access point')) {
        routers++;
      } else if (cat.includes('computer') || cat.includes('workstation') || dev.is_local_host) {
        computers++;
      } else if (cat.includes('mobile') || ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi')) {
        mobile++;
      } else if (cat.includes('iot') || cat.includes('printer') || cat.includes('embedded')) {
        iot++;
      }
    });

    if (elements.countAll) elements.countAll.textContent = devices.length;
    if (elements.countOnline) elements.countOnline.textContent = online;
    if (elements.countRouters) elements.countRouters.textContent = routers;
    if (elements.countComputers) elements.countComputers.textContent = computers;
    if (elements.countMobile) elements.countMobile.textContent = mobile;
    if (elements.countIot) elements.countIot.textContent = iot;
  }

  function filterAndSortDevices() {
    let list = [...state.devices];

    // Filter by Category
    if (state.filterCategory !== 'all') {
      list = list.filter(dev => {
        const cat = (dev.device_type || '').toLowerCase();
        const ven = (dev.vendor || '').toLowerCase();
        if (state.filterCategory === 'online') return dev.status === 'Online';
        if (state.filterCategory === 'router') {
          return dev.is_gateway || cat.includes('router') || cat.includes('gateway') || cat.includes('access point');
        }
        if (state.filterCategory === 'computer') {
          return cat.includes('computer') || cat.includes('workstation') || dev.is_local_host;
        }
        if (state.filterCategory === 'mobile') {
          return cat.includes('mobile') || ven.includes('apple') || ven.includes('samsung') || ven.includes('xiaomi');
        }
        if (state.filterCategory === 'iot') {
          return cat.includes('iot') || cat.includes('printer') || cat.includes('embedded');
        }
        return true;
      });
    }

    // Filter by Search Query
    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      list = list.filter(dev => {
        return (
          (dev.ip || '').toLowerCase().includes(q) ||
          (dev.hostname || '').toLowerCase().includes(q) ||
          (dev.mac || '').toLowerCase().includes(q) ||
          (dev.vendor || '').toLowerCase().includes(q) ||
          (dev.device_type || '').toLowerCase().includes(q) ||
          (dev.methods || []).join(' ').toLowerCase().includes(q)
        );
      });
    }

    // Sort Devices
    list.sort((a, b) => {
      let valA = a[state.sortColumn] || '';
      let valB = b[state.sortColumn] || '';

      if (state.sortColumn === 'ip') {
        const cmp = compareIps(a.ip, b.ip);
        return state.sortAsc ? cmp : -cmp;
      }

      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();

      if (valA < valB) return state.sortAsc ? -1 : 1;
      if (valA > valB) return state.sortAsc ? 1 : -1;
      return 0;
    });

    return list;
  }

  // 5. Table Rendering
  function renderDeviceTable() {
    if (!elements.ndTableBody) return;

    const list = filterAndSortDevices();

    if (list.length === 0) {
      const isScanActive = state.scanStatus === 'scanning';
      elements.ndTableBody.innerHTML = `
        <tr class="nd-empty-row">
          <td colspan="8">
            <div class="nd-empty-state">
              <div class="nd-empty-icon"><i class="fas ${isScanActive ? 'fa-spinner fa-spin' : 'fa-radar'}"></i></div>
              <h3 class="nd-empty-title">${isScanActive ? 'Probing Subnet...' : 'No Devices Found'}</h3>
              <p class="nd-empty-desc">${
                isScanActive
                  ? 'Active ARP and ICMP sweeps are underway. Discovered hosts will appear here dynamically.'
                  : state.devices.length === 0
                  ? "Click 'Start Discovery' above to sweep your local subnet and populate the device asset inventory."
                  : 'No devices matched the selected filter criteria.'
              }</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    const rowsHtml = list.map(dev => {
      const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);
      const isOnline = dev.status === 'Online';
      const macDisplay = (!dev.mac || dev.mac === 'Unavailable' || dev.mac === 'Unknown')
        ? `<span class="nd-text-muted">Unavailable</span>`
        : `<span class="mono">${escapeHtml(dev.mac)}</span>`;

      const vendorDisplay = (!dev.vendor || dev.vendor === 'Unknown' || dev.vendor === 'Unknown Vendor')
        ? `<span class="nd-text-muted">Unknown</span>`
        : `<span>${escapeHtml(dev.vendor)}</span>`;

      const hostnameDisplay = (!dev.hostname || dev.hostname === 'Unknown')
        ? `<span class="nd-text-muted">Unknown</span>`
        : `<span class="nd-hostname-text">${escapeHtml(dev.hostname)}</span>`;

      // Method Badges
      const methodsHtml = (dev.methods || ['Probed']).map(m =>
        `<span class="nd-method-chip" title="Discovered via ${escapeHtml(m)}">${escapeHtml(m)}</span>`
      ).join('');

      // Badges for Gateway or Local Host
      let roleBadge = '';
      if (dev.is_gateway) {
        roleBadge = `<span class="nd-badge-role gw" title="Default Subnet Gateway Router"><i class="fas fa-shield-alt"></i> Gateway</span>`;
      } else if (dev.is_local_host) {
        roleBadge = `<span class="nd-badge-role self" title="Your Current Local Machine"><i class="fas fa-laptop"></i> Host</span>`;
      }

      // Verified vs Inferred badge
      const isVerified = (dev.device_type_basis || '').includes('Verified');
      const verifiedTag = isVerified
        ? `<span class="nd-tag-verified" title="${escapeHtml(dev.device_type_basis)}">Verified</span>`
        : `<span class="nd-tag-inferred" title="${escapeHtml(dev.device_type_basis)}">Inferred</span>`;

      return `
        <tr class="nd-device-row" data-ip="${escapeHtml(dev.ip)}">
          <td class="col-hostname">
            <div class="nd-device-cell">
              <div class="nd-avatar-circle" title="${escapeHtml(dev.device_type)}">
                <i class="fas ${icon}"></i>
              </div>
              <div class="nd-name-meta">
                ${hostnameDisplay}
                ${roleBadge}
              </div>
            </div>
          </td>
          <td class="col-ip">
            <span class="mono fw-600 ${dev.is_gateway ? 'text-gw' : ''}">${escapeHtml(dev.ip)}</span>
          </td>
          <td class="col-mac">${macDisplay}</td>
          <td class="col-vendor">${vendorDisplay}</td>
          <td class="col-type">
            <div class="nd-type-wrap">
              <span>${escapeHtml(dev.device_type)}</span>
              ${verifiedTag}
            </div>
          </td>
          <td class="col-status">
            <span class="nd-status-pill ${isOnline ? 'online' : 'offline'}">
              <span class="status-pulse-dot"></span>
              ${escapeHtml(dev.status)}
            </span>
          </td>
          <td class="col-methods">
            <div class="nd-methods-wrap">${methodsHtml}</div>
          </td>
          <td class="col-actions">
            <button type="button" class="nd-table-btn nd-view-details-btn" data-ip="${escapeHtml(dev.ip)}" title="View complete hardware profile">
              <i class="fas fa-eye"></i> Details
            </button>
          </td>
        </tr>
      `;
    }).join('');

    elements.ndTableBody.innerHTML = rowsHtml;

    // Attach row click listeners for drawer modal
    elements.ndTableBody.querySelectorAll('.nd-device-row').forEach(row => {
      row.addEventListener('click', (e) => {
        // Prevent opening if clicking a link or button directly
        if (e.target.closest('button') || e.target.closest('a')) return;
        const ip = row.getAttribute('data-ip');
        openDeviceModal(ip);
      });
    });

    elements.ndTableBody.querySelectorAll('.nd-view-details-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const ip = btn.getAttribute('data-ip');
        openDeviceModal(ip);
      });
    });
  }

  // 6. Device Details Drawer Modal
  function openDeviceModal(ip) {
    const dev = state.devices.find(d => d.ip === ip);
    if (!dev) return;

    state.selectedDevice = dev;
    const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);

    if (elements.modalDeviceAvatar) {
      elements.modalDeviceAvatar.innerHTML = `<i class="fas ${icon}"></i>`;
    }
    if (elements.modalDeviceTitle) {
      elements.modalDeviceTitle.textContent = (dev.hostname && dev.hostname !== 'Unknown') ? dev.hostname : dev.ip;
    }
    if (elements.modalDeviceSubtitle) {
      let sub = `IPv4: ${dev.ip}`;
      if (dev.is_gateway) sub += ' • Default Subnet Gateway';
      if (dev.is_local_host) sub += ' • Local Workstation';
      elements.modalDeviceSubtitle.textContent = sub;
    }
    if (elements.modalHostname) elements.modalHostname.textContent = dev.hostname || 'Unknown';
    if (elements.modalIp) elements.modalIp.textContent = dev.ip || 'Unavailable';
    if (elements.modalMac) elements.modalMac.textContent = dev.mac || 'Unavailable';
    if (elements.modalVendor) elements.modalVendor.textContent = dev.vendor || 'Unknown Vendor';
    if (elements.modalCategory) elements.modalCategory.textContent = dev.device_type || 'Unknown Device';
    if (elements.modalBasis) elements.modalBasis.textContent = dev.device_type_basis || 'Standard heuristic probing';
    if (elements.modalLastSeen) elements.modalLastSeen.textContent = dev.last_seen || 'Just now';

    if (elements.modalMethods) {
      elements.modalMethods.innerHTML = (dev.methods || ['Probed']).map(m =>
        `<span class="nd-method-chip">${escapeHtml(m)}</span>`
      ).join(' ');
    }

    if (elements.modalPortScanLink) {
      // Connects to Port Scanner feature on homepage with pre-filled target IP
      elements.modalPortScanLink.href = `/#port-scanner?target=${encodeURIComponent(dev.ip)}`;
    }

    if (elements.ndDeviceModalBackdrop) elements.ndDeviceModalBackdrop.classList.add('open');
    if (elements.ndDeviceModal) elements.ndDeviceModal.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeDeviceModal() {
    if (elements.ndDeviceModalBackdrop) elements.ndDeviceModalBackdrop.classList.remove('open');
    if (elements.ndDeviceModal) elements.ndDeviceModal.classList.remove('open');
    document.body.style.overflow = '';
    state.selectedDevice = null;
  }

  // 7. Clipboard Copy Helper
  function copyToClipboard(elementId, btn) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.textContent.trim();
    if (!text || text === '--' || text === 'Unavailable') return;

    navigator.clipboard.writeText(text).then(() => {
      const origHtml = btn.innerHTML;
      btn.innerHTML = `<i class="fas fa-check" style="color:var(--status-benign)"></i>`;
      setTimeout(() => {
        btn.innerHTML = origHtml;
      }, 1500);
    }).catch(() => {
      // Fallback
    });
  }

  // 8. Event Listeners Setup
  function initEventListeners() {
    // Buttons
    if (elements.ndStartBtn) {
      elements.ndStartBtn.addEventListener('click', startDiscoveryScan);
    }
    if (elements.ndHeaderCtaBtn) {
      elements.ndHeaderCtaBtn.addEventListener('click', () => {
        elements.ndSubnetInput?.scrollIntoView({ behavior: 'smooth' });
        startDiscoveryScan();
      });
    }
    if (elements.ndStopBtn) {
      elements.ndStopBtn.addEventListener('click', stopDiscoveryScan);
    }
    if (elements.ndRescanBtn) {
      elements.ndRescanBtn.addEventListener('click', rescanDiscovery);
    }
    if (elements.ndUseLocalSubnetBtn) {
      elements.ndUseLocalSubnetBtn.addEventListener('click', () => {
        if (state.networkInfo && state.networkInfo.subnet_cidr) {
          elements.ndSubnetInput.value = state.networkInfo.subnet_cidr;
        }
      });
    }

    // Filter Tabs
    elements.filterTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        elements.filterTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.filterCategory = tab.getAttribute('data-filter') || 'all';
        renderDeviceTable();
      });
    });

    // Search Input (Debounced)
    if (elements.ndSearchInput) {
      let debounceTimer = null;
      elements.ndSearchInput.addEventListener('input', (e) => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          state.searchQuery = e.target.value.trim();
          renderDeviceTable();
        }, 120);
      });
    }

    // Table Header Sorting
    elements.tableHeaders.forEach(th => {
      th.addEventListener('click', () => {
        const col = th.getAttribute('data-sort');
        if (state.sortColumn === col) {
          state.sortAsc = !state.sortAsc;
        } else {
          state.sortColumn = col;
          state.sortAsc = true;
        }

        // Update Header Icons
        elements.tableHeaders.forEach(h => {
          const icon = h.querySelector('i');
          if (icon) icon.className = 'fas fa-sort';
        });
        const currentIcon = th.querySelector('i');
        if (currentIcon) {
          currentIcon.className = state.sortAsc ? 'fas fa-sort-up' : 'fas fa-sort-down';
        }

        renderDeviceTable();
      });
    });

    // Modal Drawer Close & Backdrop
    if (elements.modalCloseBtn) {
      elements.modalCloseBtn.addEventListener('click', closeDeviceModal);
    }
    if (elements.ndDeviceModalBackdrop) {
      elements.ndDeviceModalBackdrop.addEventListener('click', (e) => {
        if (e.target === elements.ndDeviceModalBackdrop) {
          closeDeviceModal();
        }
      });
    }
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDeviceModal();
    });

    // Copy Buttons in Modal
    document.querySelectorAll('.nd-copy-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-copy');
        if (targetId) copyToClipboard(targetId, btn);
      });
    });

    // Responsive Mobile Menu Toggle
    if (elements.menuToggle && elements.mainNav) {
      elements.menuToggle.addEventListener('click', () => {
        const expanded = elements.menuToggle.getAttribute('aria-expanded') === 'true';
        elements.menuToggle.setAttribute('aria-expanded', !expanded);
        elements.mainNav.classList.toggle('nav-open');
      });
    }
  }

  // 9. Initialize Page
  document.addEventListener('DOMContentLoaded', () => {
    initEventListeners();
    loadNetworkInfo();
  });
})();
