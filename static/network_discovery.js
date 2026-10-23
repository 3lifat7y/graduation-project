/**
 * DDoS-Guard — Local Network Discovery & Asset Inventory Engine
 * Frontend Controller for Subnet Reconnaissance, ARP/ICMP Telemetry, and Device Catalog
 */

(function () {
  'use strict';

  // State Management
  // State Management
  const state = {
    networkInfo: null,
    networkInfoPromise: null,
    scanStatus: 'idle', // 'idle' | 'scanning' | 'completed' | 'stopped' | 'error'
    scanId: null,
    pollInterval: null,
    devices: [],
    filterCategory: 'all',
    searchQuery: '',
    sortColumn: 'ip',
    sortAsc: true,
    viewMode: localStorage.getItem('nd_view_mode') || 'cards', // 'cards' | 'table'
    selectedDevice: null,
    knownIps: new Set()
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
    kpiUnverifiedDevices: document.getElementById('kpiUnverifiedDevices'),
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

    // History Ribbon
    ndHistoryRibbon: document.getElementById('ndHistoryRibbon'),
    ndHistoryTitle: document.getElementById('ndHistoryTitle'),
    ndHistoryDetails: document.getElementById('ndHistoryDetails'),
    ndHistoryCloseBtn: document.getElementById('ndHistoryCloseBtn'),

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
    countUnverified: document.getElementById('countUnverified'),
    countRouters: document.getElementById('countRouters'),
    countComputers: document.getElementById('countComputers'),
    countMobile: document.getElementById('countMobile'),
    countIot: document.getElementById('countIot'),
    ndSearchInput: document.getElementById('ndSearchInput'),
    ndSearchClearBtn: document.getElementById('ndSearchClearBtn'),
    ndExportJsonBtn: document.getElementById('ndExportJsonBtn'),
    ndExportCsvBtn: document.getElementById('ndExportCsvBtn'),

    // View Mode Switcher
    ndViewCardsBtn: document.getElementById('ndViewCardsBtn'),
    ndViewTableBtn: document.getElementById('ndViewTableBtn'),
    ndCardsContainer: document.getElementById('ndCardsContainer'),
    ndCardsGrid: document.getElementById('ndCardsGrid'),
    ndTableWrapper: document.getElementById('ndTableWrapper'),

    // Table
    ndDeviceTable: document.getElementById('ndDeviceTable'),
    ndTableBody: document.getElementById('ndTableBody'),
    tableHeaders: document.querySelectorAll('#ndDeviceTable thead th[data-sort]'),

    // Modal Drawer
    ndDeviceModalBackdrop: document.getElementById('ndDeviceModalBackdrop'),
    ndDeviceModal: document.getElementById('ndDeviceModal'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    modalFooterCloseBtn: document.getElementById('modalFooterCloseBtn'),
    modalDeviceAvatar: document.getElementById('modalDeviceAvatar'),
    modalDeviceTitle: document.getElementById('modalDeviceTitle'),
    modalDeviceSubtitle: document.getElementById('modalDeviceSubtitle'),
    modalHostname: document.getElementById('modalHostname'),
    modalIp: document.getElementById('modalIp'),
    modalMac: document.getElementById('modalMac'),
    modalVendor: document.getElementById('modalVendor'),
    modalCategory: document.getElementById('modalCategory'),
    modalRole: document.getElementById('modalRole'),
    modalStatusPill: document.getElementById('modalStatusPill'),
    modalStatusText: document.getElementById('modalStatusText'),
    modalBasis: document.getElementById('modalBasis'),
    modalLastSeen: document.getElementById('modalLastSeen'),
    modalMethods: document.getElementById('modalMethods'),
    modalPortsPanel: document.getElementById('modalPortsPanel'),
    modalPortsStatusBadge: document.getElementById('modalPortsStatusBadge'),
    modalPortsCountText: document.getElementById('modalPortsCountText'),
    modalPortsHelperText: document.getElementById('modalPortsHelperText'),
    modalPortsList: document.getElementById('modalPortsList'),
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

  // Helper: Validate IPv4 address or hostname
  function isValidTargetIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const clean = ip.trim();
    if (!clean || clean === 'Unavailable' || clean === 'Unknown' || clean === 'N/A' || clean === 'Not detected') return false;
    const octets = clean.split('.');
    if (octets.length === 4) {
      const allValid = octets.every(o => {
        if (!/^\d{1,3}$/.test(o)) return false;
        const n = Number(o);
        return n >= 0 && n <= 255;
      });
      if (allValid) return true;
    }
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(clean)) {
      return true;
    }
    return false;
  }

  // Helper: Prepare one-time port scan auto-trigger and validate target
  function triggerPortScanForDevice(ip, e) {
    if (e) e.stopPropagation();
    if (!isValidTargetIp(ip)) {
      if (e) e.preventDefault();
      showAlert(`Cannot scan ports: '${ip || "Unknown"}' is not a valid IPv4 address.`);
      return false;
    }
    try {
      sessionStorage.setItem('port_scan_auto_trigger', JSON.stringify({
        ip: ip.trim(),
        timestamp: Date.now()
      }));
    } catch (err) {
      // ignore storage quota issues
    }
    return true;
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
  function loadNetworkInfo() {
    state.networkInfoPromise = (async () => {
      try {
        const res = await fetch('/api/network-discovery/network-info');
        const data = await res.json();
        if (data.status === 'success' && data.network) {
          state.networkInfo = data.network;
          renderNetworkInfo(data.network);
          return data.network;
        } else {
          showAlert(data.message || 'Unable to detect active local network interface.');
          return null;
        }
      } catch (err) {
        showAlert('Failed to connect to Network Discovery API. Ensure Flask server is online.');
        return null;
      }
    })();
    return state.networkInfoPromise;
  }

  function renderNetworkInfo(net) {
    if (elements.ndAdapterName) {
      const typeStr = (net.adapter_type && net.adapter_type !== 'None' && net.adapter_type !== 'Other') ? ` (${net.adapter_type})` : '';
      elements.ndAdapterName.textContent = (net.adapter_name && net.adapter_name !== 'None') ? `${net.adapter_name}${typeStr}` : 'Disconnected / None';
    }
    if (elements.ndLocalIp) elements.ndLocalIp.textContent = (net.is_connected && net.local_ip) ? net.local_ip : '--';
    if (elements.ndLocalMac) elements.ndLocalMac.textContent = net.local_mac || 'Unavailable';
    if (elements.ndSubnetMask) elements.ndSubnetMask.textContent = net.subnet_mask || '--';
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
      const ndHealthDotMobile = document.getElementById('ndHealthDotMobile');
      if (ndHealthDotMobile) {
        ndHealthDotMobile.className = elements.ndHealthDot.className;
      }
      const topNavHealthDot = document.getElementById('topNavHealthDot');
      const topNavHealthLabel = document.getElementById('topNavHealthLabel');
      if (topNavHealthDot) {
        topNavHealthDot.className = elements.ndHealthDot.className;
      }
      if (topNavHealthLabel) {
        topNavHealthLabel.textContent = elements.ndHealthLabel.textContent;
      }
    }

    if (elements.ndSubnetInput && !elements.ndSubnetInput.value) {
      if (net.is_connected && net.subnet_cidr) {
        elements.ndSubnetInput.value = net.subnet_cidr;
      } else {
        elements.ndSubnetInput.value = '';
        elements.ndSubnetInput.placeholder = 'e.g. 192.168.1.0/24';
      }
    }
  }

  // 2. Scan Controls: Start, Stop, Rescan
  async function startDiscoveryScan(isRescan = false) {
    if (state.scanStatus === 'scanning' || state.scanStatus === 'starting') {
      return;
    }
    hideAlert();
    let subnet = (elements.ndSubnetInput ? elements.ndSubnetInput.value : '').trim();

    // If input is empty on initial click, resolve network info gracefully without failing
    if (!subnet) {
      if (elements.ndStartBtn) {
        elements.ndStartBtn.disabled = true;
        const origBtnHtml = elements.ndStartBtn.innerHTML;
        elements.ndStartBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span class="btn-text">Detecting Subnet...</span>';
        try {
          const net = await (state.networkInfoPromise || loadNetworkInfo());
          if (net && net.subnet_cidr) {
            subnet = net.subnet_cidr;
            if (elements.ndSubnetInput) elements.ndSubnetInput.value = subnet;
          }
        } catch (e) {}
        elements.ndStartBtn.innerHTML = origBtnHtml;
        elements.ndStartBtn.disabled = false;
      }
    }

    if (!subnet && state.networkInfo && state.networkInfo.subnet_cidr) {
      subnet = state.networkInfo.subnet_cidr;
      if (elements.ndSubnetInput) elements.ndSubnetInput.value = subnet;
    }
    const timeout = parseFloat(elements.ndTimeoutSelect ? elements.ndTimeoutSelect.value : 0.6);
    const concurrency = parseInt(elements.ndConcurrencySelect ? elements.ndConcurrencySelect.value : 50, 10);

    if (!subnet) {
      showAlert('No active local subnet detected. Please enter a target IPv4 subnet (e.g. 192.168.1.0/24), host IP, or range.');
      if (elements.ndSubnetInput) elements.ndSubnetInput.focus();
      return;
    }

    state.knownIps.clear();
    setScanUiState('starting');
    if (elements.ndStartBtn) elements.ndStartBtn.disabled = true;
    if (elements.ndRescanBtn) elements.ndRescanBtn.disabled = true;

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
        if (elements.ndStartBtn) elements.ndStartBtn.disabled = false;
        if (elements.ndRescanBtn) elements.ndRescanBtn.disabled = false;
        showAlert(data.message || 'Failed to initiate network discovery scan.');
      }
    } catch (err) {
      setScanUiState('error');
      if (elements.ndStartBtn) elements.ndStartBtn.disabled = false;
      if (elements.ndRescanBtn) elements.ndRescanBtn.disabled = false;
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
        setTimeout(() => startDiscoveryScan(true), 350);
      });
    } else {
      startDiscoveryScan(true);
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
      if (elements.ndProgressBox) {
        elements.ndProgressBox.style.display = 'block';
        elements.ndProgressBox.classList.add('scanning');
      }
      if (elements.ndProgressBar) elements.ndProgressBar.classList.add('scanning');
    } else {
      if (elements.ndStartBtn) {
        elements.ndStartBtn.style.display = 'inline-flex';
        elements.ndStartBtn.disabled = false;
      }
      if (elements.ndRescanBtn) {
        elements.ndRescanBtn.disabled = false;
      }
      if (elements.ndStopBtn) elements.ndStopBtn.style.display = 'none';
      if (elements.ndProgressBox) {
        elements.ndProgressBox.classList.remove('scanning');
        if (st === 'completed' || st === 'stopped') {
          elements.ndProgressBox.style.display = 'block';
        }
      }
      if (elements.ndProgressBar) elements.ndProgressBar.classList.remove('scanning');
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
      const onlineCount = data.online_count !== undefined
        ? data.online_count
        : state.devices.filter(d => d.verified || d.status === 'Online').length;
      const unverifiedCount = data.unverified_count !== undefined
        ? data.unverified_count
        : state.devices.filter(d => !d.verified && d.status !== 'Online').length;

      if (elements.kpiTotalDevices) elements.kpiTotalDevices.textContent = data.devices_count || state.devices.length;
      if (elements.kpiOnlineDevices) elements.kpiOnlineDevices.textContent = onlineCount;
      if (elements.kpiUnverifiedDevices) elements.kpiUnverifiedDevices.textContent = unverifiedCount;
      if (elements.kpiScanDuration) elements.kpiScanDuration.textContent = (data.duration_s || 0).toFixed(1) + 's';

      // Connect to background scan if page loaded during active scan
      if (data.status === 'scanning' && !state.pollInterval) {
        setScanUiState('scanning');
        startStatusPolling();
      }

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

      // Render Previous Scan Comparison
      if (elements.ndHistoryRibbon) {
        if (data.history_comparison && (data.status === 'completed' || data.status === 'scanning')) {
          const hc = data.history_comparison;
          if (elements.ndHistoryDetails) {
            let detailParts = [];
            detailParts.push(`Subnet rescan: ${(data.devices_count || 0)} total device(s) found in ${(data.duration_s || 0).toFixed(1)}s.`);
            if (hc.new_hosts_count > 0) {
              detailParts.push(`<strong>${hc.new_hosts_count} new host(s)</strong> active.`);
            }
            if (hc.offline_hosts_count > 0) {
              detailParts.push(`<span>${hc.offline_hosts_count} host(s)</span> unverified / offline.`);
            }
            if (hc.new_hosts_count === 0 && hc.offline_hosts_count === 0) {
              detailParts.push('Host states consistent with previous scan.');
            }
            elements.ndHistoryDetails.innerHTML = detailParts.join(' ');
          }
          elements.ndHistoryRibbon.style.display = 'flex';
        }
      }

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
    let online = 0, unverified = 0, routers = 0, computers = 0, mobile = 0, iot = 0;
    devices.forEach(dev => {
      const isOnline = Boolean(dev.verified || dev.status === 'Online');
      if (isOnline) {
        online++;
      } else {
        unverified++;
      }
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
    if (elements.countUnverified) elements.countUnverified.textContent = unverified;
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
        if (state.filterCategory === 'online') return Boolean(dev.verified || dev.status === 'Online');
        if (state.filterCategory === 'unverified') return !dev.verified || dev.status === 'Unverified';
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

  // Helper: Extract Port Info
  function getDevicePortsInfo(dev) {
    let count = null;
    if (dev.open_ports_count !== undefined && dev.open_ports_count !== null) {
      count = Number(dev.open_ports_count);
    } else if (Array.isArray(dev.open_ports)) {
      count = dev.open_ports.length;
    }
    return {
      count: count,
      ports: Array.isArray(dev.open_ports) ? dev.open_ports : []
    };
  }

  // 5. Inventory Rendering: Cards & Compact Table (Keyed In-Place Reconciliation)
  function renderDeviceInventory() {
    const list = filterAndSortDevices();
    renderDeviceCards(list);
    renderCompactTable(list);
  }

  // Backward compatibility alias for polling loop
  const renderDeviceTable = renderDeviceInventory;

  // 5a. Responsive Cards Grid (Default View with In-Place Keyed Reconciliation)
  function renderDeviceCards(list) {
    if (!elements.ndCardsGrid) return;

    if (list.length === 0) {
      const isScanActive = state.scanStatus === 'scanning';
      elements.ndCardsGrid.innerHTML = `
        <div class="nd-empty-state">
          <div class="nd-empty-icon"><i class="fas ${isScanActive ? 'fa-spinner fa-spin' : 'fa-satellite-dish'}"></i></div>
          <h3 class="nd-empty-title">${isScanActive ? 'Probing Subnet...' : 'No Devices Found'}</h3>
          <p class="nd-empty-desc">${
            isScanActive
              ? 'Active ARP and ICMP sweeps are underway. Discovered hosts will appear here dynamically.'
              : state.devices.length === 0
              ? "Click 'Start Discovery' above to sweep your local subnet and populate the device asset inventory."
              : 'No devices matched the selected filter or search criteria.'
          }</p>
        </div>
      `;
      return;
    }

    // Remove empty state if present
    const emptyState = elements.ndCardsGrid.querySelector('.nd-empty-state');
    if (emptyState) emptyState.remove();

    const currentIps = new Set(list.map(d => d.ip));

    // Remove cards no longer in the filtered/sorted device list
    elements.ndCardsGrid.querySelectorAll('.nd-device-card').forEach(card => {
      const ip = card.getAttribute('data-ip');
      if (!currentIps.has(ip)) {
        card.remove();
      }
    });

    list.forEach((dev, idx) => {
      const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);
      const isOnline = dev.status === 'Online';
      const isNew = state.scanStatus === 'scanning' && !state.knownIps.has(dev.ip);
      if (isNew) state.knownIps.add(dev.ip);

      const hostnameDisplay = (!dev.hostname || dev.hostname === 'Unknown')
        ? `<span class="nd-text-muted">Unknown</span>`
        : `<span class="nd-card-hostname-text">${escapeHtml(dev.hostname)}</span>`;

      const macDisplay = (!dev.mac || dev.mac === 'Unavailable' || dev.mac === 'Unknown')
        ? `<span class="nd-text-muted">Not detected</span>`
        : `<span class="mono">${escapeHtml(dev.mac)}</span>`;

      const vendorClean = (!dev.vendor || dev.vendor === 'Unknown' || dev.vendor === 'Unknown Vendor')
        ? 'Unknown Vendor'
        : dev.vendor;

      const categoryClean = dev.device_type || 'Network Device';

      // Role Badge
      let roleBadge = '';
      if (dev.is_gateway) {
        roleBadge = `<span class="nd-badge-role gw" title="Default Subnet Gateway Router"><i class="fas fa-shield-alt"></i> Gateway</span>`;
      } else if (dev.is_local_host) {
        roleBadge = `<span class="nd-badge-role self" title="Your Current Local Machine"><i class="fas fa-laptop"></i> Host</span>`;
      }

      // Open Ports info
      const portsInfo = getDevicePortsInfo(dev);
      let portsDisplay = '';
      if (portsInfo.count !== null) {
        const hasOpen = portsInfo.count > 0;
        portsDisplay = `
          <span class="nd-ports-badge ${hasOpen ? 'has-ports' : 'zero-ports'}">
            <i class="fas ${hasOpen ? 'fa-door-open' : 'fa-shield'}"></i>
            ${portsInfo.count} ${portsInfo.count === 1 ? 'Open Port' : 'Open Ports'}
          </span>
        `;
      } else {
        portsDisplay = `
          <span class="nd-ports-badge not-scanned" title="Port scan not conducted for this host">
            <i class="fas fa-minus"></i> Not detected
          </span>
        `;
      }

      const statusPillHtml = (dev.verified || dev.status === 'Online')
        ? `<span class="nd-status-pill online" title="Confirmed reachable via ARP/ICMP/TCP probe"><span class="status-pulse-dot"></span> Confirmed Active</span>`
        : dev.status === 'Unverified'
        ? `<span class="nd-status-pill unverified" title="Present in ARP neighbor cache but unverified by direct probes"><i class="fas fa-clock"></i> Unverified</span>`
        : `<span class="nd-status-pill offline">${escapeHtml(dev.status || 'Offline')}</span>`;

      const cardSig = `${dev.status}|${dev.verified}|${dev.hostname}|${dev.mac}|${categoryClean}|${vendorClean}|${portsInfo.count}|${dev.is_gateway}|${dev.is_local_host}`;

      let card = elements.ndCardsGrid.querySelector(`.nd-device-card[data-ip="${escapeHtml(dev.ip)}"]`);

      if (!card) {
        card = document.createElement('div');
        card.className = `nd-device-card ${isNew ? 'new-discovery-glow' : ''}`;
        card.setAttribute('data-ip', dev.ip);
        card.setAttribute('data-sig', cardSig);
        card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'button');
        card.setAttribute('aria-label', `Device ${dev.hostname || dev.ip}, ${categoryClean}. Press Enter to view full details.`);
        card.style.animationDelay = `${Math.min(idx * 35, 500)}ms`;

        card.innerHTML = `
          <div class="nd-card-header">
            <div class="nd-card-avatar" title="${escapeHtml(categoryClean)}">
              <i class="fas ${icon}"></i>
            </div>
            <div class="nd-card-title-col">
              <div class="nd-card-name-row">
                <h4 class="nd-card-hostname" title="${escapeHtml(dev.hostname || dev.ip)}">${hostnameDisplay}</h4>
                ${roleBadge}
              </div>
              <span class="nd-card-sub" title="${escapeHtml(categoryClean)} • ${escapeHtml(vendorClean)}">
                ${escapeHtml(categoryClean)} • ${escapeHtml(vendorClean)}
              </span>
            </div>
            ${statusPillHtml}
            <div class="nd-card-inspect-hint" title="Inspect device profile" aria-hidden="true">
              <i class="fas fa-chevron-right"></i>
            </div>
          </div>

          <div class="nd-card-body">
            <div class="nd-card-prop">
              <span class="nd-prop-label"><i class="fas fa-location-dot"></i> IP Address</span>
              <div class="nd-prop-val-wrap">
                <span class="nd-prop-val mono ${dev.is_gateway ? 'text-gw' : ''}">${escapeHtml(dev.ip)}</span>
                <button type="button" class="nd-mini-copy-btn" data-copy-text="${escapeHtml(dev.ip)}" title="Copy IP Address" aria-label="Copy IP Address">
                  <i class="fas fa-copy"></i>
                </button>
              </div>
            </div>

            <div class="nd-card-prop">
              <span class="nd-prop-label"><i class="fas fa-fingerprint"></i> MAC Address</span>
              <span class="nd-prop-val mono">${macDisplay}</span>
            </div>

            <div class="nd-card-prop">
              <span class="nd-prop-label"><i class="fas fa-shield-halved"></i> Open Ports</span>
              <span class="nd-prop-val">${portsDisplay}</span>
            </div>
          </div>

          <div class="nd-card-footer">
            <a href="/?view=port-scanner&target=${encodeURIComponent(dev.ip)}&trigger=discovery" class="nd-card-action-btn nd-btn-scan-ports" data-target-ip="${escapeHtml(dev.ip)}" title="Scan ports for target ${escapeHtml(dev.ip)}">
              <i class="fas fa-bullseye"></i> Scan Ports
            </a>
          </div>
        `;
        elements.ndCardsGrid.appendChild(card);
      } else {
        // Card already exists in DOM - only update if data actually changed
        if (card.getAttribute('data-sig') !== cardSig) {
          card.setAttribute('data-sig', cardSig);

          const avatar = card.querySelector('.nd-card-avatar');
          if (avatar) {
            avatar.title = categoryClean;
            avatar.innerHTML = `<i class="fas ${icon}"></i>`;
          }
          const nameRow = card.querySelector('.nd-card-name-row');
          if (nameRow) {
            nameRow.innerHTML = `<h4 class="nd-card-hostname" title="${escapeHtml(dev.hostname || dev.ip)}">${hostnameDisplay}</h4>${roleBadge}`;
          }
          const sub = card.querySelector('.nd-card-sub');
          if (sub) {
            sub.title = `${categoryClean} • ${vendorClean}`;
            sub.textContent = `${categoryClean} • ${vendorClean}`;
          }
          const header = card.querySelector('.nd-card-header');
          const oldPill = header ? header.querySelector('.nd-status-pill') : null;
          if (oldPill) {
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = statusPillHtml;
            const newPill = tempDiv.firstElementChild;
            if (newPill) header.replaceChild(newPill, oldPill);
          }
          const macEl = card.querySelector('.nd-card-prop:nth-child(2) .nd-prop-val');
          if (macEl) macEl.innerHTML = macDisplay;
          const portsEl = card.querySelector('.nd-card-prop:nth-child(3) .nd-prop-val');
          if (portsEl) portsEl.innerHTML = portsDisplay;
          const scanLink = card.querySelector('.nd-btn-scan-ports');
          if (scanLink) {
            scanLink.href = `/?view=port-scanner&target=${encodeURIComponent(dev.ip)}&trigger=discovery`;
            scanLink.setAttribute('data-target-ip', dev.ip);
          }
        }
        // Preserve DOM sort order without re-triggering animations
        elements.ndCardsGrid.appendChild(card);
      }
    });
  }

  // 5b. Compact Table View (Secondary Option with In-Place Keyed Reconciliation)
  function renderCompactTable(list) {
    if (!elements.ndTableBody) return;

    if (list.length === 0) {
      const isScanActive = state.scanStatus === 'scanning';
      elements.ndTableBody.innerHTML = `
        <tr class="nd-empty-row">
          <td colspan="6">
            <div class="nd-empty-state">
              <div class="nd-empty-icon"><i class="fas ${isScanActive ? 'fa-spinner fa-spin' : 'fa-satellite-dish'}"></i></div>
              <h3 class="nd-empty-title">${isScanActive ? 'Probing Subnet...' : 'No Devices Found'}</h3>
              <p class="nd-empty-desc">${
                isScanActive
                  ? 'Active ARP and ICMP sweeps are underway. Discovered hosts will appear here dynamically.'
                  : state.devices.length === 0
                  ? "Click 'Start Discovery' above to sweep your local subnet and populate the device asset inventory."
                  : 'No devices matched the selected filter or search criteria.'
              }</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    // Remove empty row if present
    const emptyRow = elements.ndTableBody.querySelector('.nd-empty-row');
    if (emptyRow) emptyRow.remove();

    const currentIps = new Set(list.map(d => d.ip));

    // Remove rows no longer in list
    elements.ndTableBody.querySelectorAll('.nd-device-row').forEach(row => {
      const ip = row.getAttribute('data-ip');
      if (!currentIps.has(ip)) {
        row.remove();
      }
    });

    list.forEach((dev, idx) => {
      const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);
      const isOnline = dev.status === 'Online';

      const hostnameDisplay = (!dev.hostname || dev.hostname === 'Unknown')
        ? `<span class="nd-text-muted">Unknown</span>`
        : `<span class="nd-hostname-text" title="${escapeHtml(dev.hostname)}">${escapeHtml(dev.hostname)}</span>`;

      const macDisplay = (!dev.mac || dev.mac === 'Unavailable' || dev.mac === 'Unknown')
        ? `<span class="nd-text-muted">Not detected</span>`
        : `<span class="mono">${escapeHtml(dev.mac)}</span>`;

      // Role Badge
      let roleBadge = '';
      if (dev.is_gateway) {
        roleBadge = `<span class="nd-badge-role gw" title="Default Subnet Gateway Router"><i class="fas fa-shield-alt"></i> Gateway</span>`;
      } else if (dev.is_local_host) {
        roleBadge = `<span class="nd-badge-role self" title="Your Current Local Machine"><i class="fas fa-laptop"></i> Host</span>`;
      }

      // Open Ports
      const portsInfo = getDevicePortsInfo(dev);
      let portsDisplay = '';
      if (portsInfo.count !== null) {
        const hasOpen = portsInfo.count > 0;
        portsDisplay = `
          <span class="nd-ports-badge ${hasOpen ? 'has-ports' : 'zero-ports'}">
            <i class="fas ${hasOpen ? 'fa-door-open' : 'fa-shield'}"></i>
            ${portsInfo.count} Open
          </span>
        `;
      } else {
        portsDisplay = `
          <span class="nd-ports-badge not-scanned" title="Port scan not conducted for this host">
            <i class="fas fa-minus"></i> Not detected
          </span>
        `;
      }

      const statusPillHtml = (dev.verified || dev.status === 'Online')
        ? `<span class="nd-status-pill online" title="Confirmed reachable"><span class="status-pulse-dot"></span> Confirmed Active</span>`
        : dev.status === 'Unverified'
        ? `<span class="nd-status-pill unverified" title="Present in ARP neighbor cache but unverified by direct probes"><i class="fas fa-clock"></i> Unverified</span>`
        : `<span class="nd-status-pill offline">${escapeHtml(dev.status || 'Offline')}</span>`;

      const rowSig = `${dev.status}|${dev.verified}|${dev.hostname}|${dev.mac}|${dev.device_type}|${portsInfo.count}|${dev.is_gateway}|${dev.is_local_host}`;

      let row = elements.ndTableBody.querySelector(`.nd-device-row[data-ip="${escapeHtml(dev.ip)}"]`);

      if (!row) {
        row = document.createElement('tr');
        row.className = 'nd-device-row';
        row.setAttribute('data-ip', dev.ip);
        row.setAttribute('data-sig', rowSig);
        row.setAttribute('tabindex', '0');
        row.setAttribute('role', 'button');
        row.setAttribute('aria-label', `Device ${dev.hostname || dev.ip}, ${dev.device_type}. Press Enter to view full details.`);
        row.style.animationDelay = `${Math.min(idx * 28, 450)}ms`;

        row.innerHTML = `
          <td class="col-hostname">
            <div class="nd-device-cell">
              <div class="nd-avatar-circle" title="${escapeHtml(dev.device_type || 'Device')}">
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
          <td class="col-status">
            ${statusPillHtml}
          </td>
          <td class="col-ports">${portsDisplay}</td>
          <td class="col-actions">
            <a href="/?view=port-scanner&target=${encodeURIComponent(dev.ip)}&trigger=discovery" class="nd-table-btn nd-btn-scan-ports" data-target-ip="${escapeHtml(dev.ip)}" title="Scan ports on ${escapeHtml(dev.ip)}">
              <i class="fas fa-bullseye"></i> Ports
            </a>
          </td>
        `;
        elements.ndTableBody.appendChild(row);
      } else {
        if (row.getAttribute('data-sig') !== rowSig) {
          row.setAttribute('data-sig', rowSig);
          const nameMeta = row.querySelector('.nd-name-meta');
          if (nameMeta) nameMeta.innerHTML = `${hostnameDisplay}${roleBadge}`;
          const macCol = row.querySelector('.col-mac');
          if (macCol) macCol.innerHTML = macDisplay;
          const statusCol = row.querySelector('.col-status');
          if (statusCol) statusCol.innerHTML = statusPillHtml;
          const portsCol = row.querySelector('.col-ports');
          if (portsCol) portsCol.innerHTML = portsDisplay;
          const scanLink = row.querySelector('.nd-btn-scan-ports');
          if (scanLink) {
            scanLink.href = `/?view=port-scanner&target=${encodeURIComponent(dev.ip)}&trigger=discovery`;
            scanLink.setAttribute('data-target-ip', dev.ip);
          }
        }
        elements.ndTableBody.appendChild(row);
      }
    });
  }

  // Backward compatibility stub (delegated event listeners attached once in initEventListeners)
  function attachDeviceActionListeners() {}

  // 6. Device Details Modal (Structured in 4 Sections)
  function openDeviceModal(ip) {
    const dev = state.devices.find(d => d.ip === ip);
    if (!dev) return;

    state.selectedDevice = dev;
    const icon = getDeviceIcon(dev.device_type, dev.vendor, dev.is_gateway, dev.is_local_host);
    const isOnline = dev.status === 'Online';

    // Header Avatar & Title
    if (elements.modalDeviceAvatar) {
      elements.modalDeviceAvatar.innerHTML = `<i class="fas ${icon}"></i>`;
    }
    if (elements.modalDeviceTitle) {
      elements.modalDeviceTitle.textContent = (dev.hostname && dev.hostname !== 'Unknown') ? dev.hostname : dev.ip;
    }
    if (elements.modalDeviceSubtitle) {
      let sub = `IPv4: ${dev.ip}`;
      if (dev.is_gateway) sub += ' • Default Subnet Gateway';
      else if (dev.is_local_host) sub += ' • Local Workstation';
      elements.modalDeviceSubtitle.textContent = sub;
    }

    // --- Section 1: General Information ---
    if (elements.modalHostname) {
      elements.modalHostname.textContent = (dev.hostname && dev.hostname !== 'Unknown') ? dev.hostname : 'Unknown Hostname';
    }
    if (elements.modalCategory) {
      elements.modalCategory.textContent = dev.device_type || 'Unknown Device';
    }
    if (elements.modalRole) {
      elements.modalRole.textContent = dev.is_gateway
        ? 'Default Subnet Gateway Router'
        : dev.is_local_host
        ? 'Local Workstation (This Device)'
        : 'Network Endpoint Host';
    }
    if (elements.modalStatusPill && elements.modalStatusText) {
      elements.modalStatusPill.className = 'nd-status-pill ' + (isOnline ? 'online' : 'offline');
      elements.modalStatusText.textContent = dev.status || 'Offline';
    }

    // --- Section 2: Network Information ---
    if (elements.modalIp) {
      elements.modalIp.textContent = dev.ip || 'Unavailable';
    }
    if (elements.modalMac) {
      const macVal = (!dev.mac || dev.mac === 'Unavailable' || dev.mac === 'Unknown') ? 'Not detected' : dev.mac;
      elements.modalMac.textContent = macVal;
    }
    if (elements.modalVendor) {
      const vendorVal = (!dev.vendor || dev.vendor === 'Unknown' || dev.vendor === 'Unknown Vendor') ? 'Unknown Vendor' : dev.vendor;
      elements.modalVendor.textContent = vendorVal;
    }
    if (elements.modalMethods) {
      elements.modalMethods.innerHTML = (dev.methods || ['Probed']).map(m =>
        `<span class="nd-method-chip">${escapeHtml(m)}</span>`
      ).join(' ');
    }

    // --- Section 3: Open Ports ---
    const portsInfo = getDevicePortsInfo(dev);
    if (elements.modalPortsCountText && elements.modalPortsStatusBadge) {
      if (portsInfo.count !== null) {
        const hasOpen = portsInfo.count > 0;
        elements.modalPortsStatusBadge.className = 'nd-ports-status-badge ' + (hasOpen ? 'has-ports' : 'zero-ports');
        elements.modalPortsCountText.textContent = `${portsInfo.count} ${portsInfo.count === 1 ? 'Open Port' : 'Open Ports'} Detected`;
        
        if (portsInfo.ports.length > 0 && elements.modalPortsList) {
          elements.modalPortsList.style.display = 'flex';
          elements.modalPortsList.innerHTML = portsInfo.ports.map(p => `
            <span class="nd-port-tag">
              <span class="port-num">${escapeHtml(p.port || p)}</span>
              ${p.service ? `<span class="port-srv">${escapeHtml(p.service)}</span>` : ''}
              ${p.state ? `<span class="port-st ${escapeHtml(p.state)}">${escapeHtml(p.state)}</span>` : ''}
            </span>
          `).join('');
          if (elements.modalPortsHelperText) elements.modalPortsHelperText.textContent = 'Active listening services verified on this host.';
        } else {
          if (elements.modalPortsList) elements.modalPortsList.style.display = 'none';
          if (elements.modalPortsHelperText) {
            elements.modalPortsHelperText.textContent = hasOpen
              ? 'Ports recorded by discovery scan.'
              : 'No open services responded on scanned ports.';
          }
        }
      } else {
        elements.modalPortsStatusBadge.className = 'nd-ports-status-badge not-scanned';
        elements.modalPortsCountText.textContent = 'Not scanned / Not detected';
        if (elements.modalPortsList) elements.modalPortsList.style.display = 'none';
        if (elements.modalPortsHelperText) {
          elements.modalPortsHelperText.textContent = 'Run a targeted port scan on this host to enumerate active services.';
        }
      }
    }

    // --- Section 4: Scan Details ---
    if (elements.modalLastSeen) {
      elements.modalLastSeen.textContent = dev.last_seen || 'Just now';
    }
    if (elements.modalBasis) {
      elements.modalBasis.textContent = dev.device_type_basis || 'Standard ARP/ICMP probing';
    }

    // Quick Action: Port Scanner Link
    if (elements.modalPortScanLink) {
      elements.modalPortScanLink.href = `/?view=port-scanner&target=${encodeURIComponent(dev.ip)}&trigger=discovery`;
      elements.modalPortScanLink.setAttribute('data-target-ip', dev.ip);
    }

    // Open Modal
    if (elements.ndDeviceModalBackdrop) elements.ndDeviceModalBackdrop.classList.add('open');
    if (elements.ndDeviceModal) elements.ndDeviceModal.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeDeviceModal() {
    if (elements.ndDeviceModal) elements.ndDeviceModal.classList.remove('open');
    setTimeout(() => {
      if (elements.ndDeviceModalBackdrop) elements.ndDeviceModalBackdrop.classList.remove('open');
      document.body.style.overflow = '';
      state.selectedDevice = null;
    }, 180);
  }

  // 7. Clipboard Copy Helpers
  function copyDirectText(text, btn) {
    if (!text || text === '--' || text === 'Unavailable' || text === 'Not detected') return;
    navigator.clipboard.writeText(text).then(() => {
      const origHtml = btn.innerHTML;
      btn.innerHTML = `<i class="fas fa-check" style="color:var(--status-benign)"></i>`;
      setTimeout(() => {
        btn.innerHTML = origHtml;
      }, 1500);
    }).catch(() => {});
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
    if (elements.ndHistoryCloseBtn) {
      elements.ndHistoryCloseBtn.addEventListener('click', () => {
        if (elements.ndHistoryRibbon) elements.ndHistoryRibbon.style.display = 'none';
      });
    }
    if (elements.ndUseLocalSubnetBtn) {
      elements.ndUseLocalSubnetBtn.addEventListener('click', async () => {
        if (!state.networkInfo && state.networkInfoPromise) {
          await state.networkInfoPromise;
        }
        if (state.networkInfo && state.networkInfo.subnet_cidr) {
          elements.ndSubnetInput.value = state.networkInfo.subnet_cidr;
          hideAlert();
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

    // View Mode Switcher
    function setViewMode(mode) {
      state.viewMode = mode;
      localStorage.setItem('nd_view_mode', mode);
      if (mode === 'table') {
        if (elements.ndCardsContainer) elements.ndCardsContainer.style.display = 'none';
        if (elements.ndTableWrapper) elements.ndTableWrapper.style.display = 'block';
        if (elements.ndViewCardsBtn) {
          elements.ndViewCardsBtn.classList.remove('active');
          elements.ndViewCardsBtn.setAttribute('aria-pressed', 'false');
        }
        if (elements.ndViewTableBtn) {
          elements.ndViewTableBtn.classList.add('active');
          elements.ndViewTableBtn.setAttribute('aria-pressed', 'true');
        }
      } else {
        if (elements.ndCardsContainer) elements.ndCardsContainer.style.display = 'block';
        if (elements.ndTableWrapper) elements.ndTableWrapper.style.display = 'none';
        if (elements.ndViewCardsBtn) {
          elements.ndViewCardsBtn.classList.add('active');
          elements.ndViewCardsBtn.setAttribute('aria-pressed', 'true');
        }
        if (elements.ndViewTableBtn) {
          elements.ndViewTableBtn.classList.remove('active');
          elements.ndViewTableBtn.setAttribute('aria-pressed', 'false');
        }
      }
    }

    if (elements.ndViewCardsBtn) {
      elements.ndViewCardsBtn.addEventListener('click', () => setViewMode('cards'));
    }
    if (elements.ndViewTableBtn) {
      elements.ndViewTableBtn.addEventListener('click', () => setViewMode('table'));
    }
    // Set initial view state
    setViewMode(state.viewMode);

    // Export Handlers
    function exportResultsJson() {
      if (!state.devices || state.devices.length === 0) {
        showAlert('No discovery results available to export. Run a subnet scan first.');
        return;
      }
      const exportData = {
        scan_id: state.scanId || `export_${Date.now()}`,
        exported_at: new Date().toISOString(),
        subnet: state.networkInfo ? state.networkInfo.subnet_cidr : null,
        total_devices: state.devices.length,
        confirmed_active: state.devices.filter(d => d.verified || d.status === 'Online').length,
        unverified: state.devices.filter(d => !d.verified && d.status !== 'Online').length,
        devices: state.devices.map(d => ({
          ip: d.ip,
          hostname: d.hostname && d.hostname !== 'Unknown' ? d.hostname : null,
          mac: d.mac && d.mac !== 'Unavailable' && d.mac !== 'Unknown' ? d.mac : null,
          vendor: d.vendor && d.vendor !== 'Unknown Vendor' ? d.vendor : null,
          device_type: d.device_type,
          device_type_basis: d.device_type_basis,
          status: d.status,
          verified: Boolean(d.verified),
          is_gateway: Boolean(d.is_gateway),
          is_local_host: Boolean(d.is_local_host),
          methods: d.methods || [],
          last_seen: d.last_seen
        }))
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `network_discovery_${state.scanId || Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function exportResultsCsv() {
      if (!state.devices || state.devices.length === 0) {
        showAlert('No discovery results available to export. Run a subnet scan first.');
        return;
      }
      const headers = ['IP Address', 'Hostname', 'MAC Address', 'Vendor', 'Device Type', 'Status', 'Verified Active', 'Is Gateway', 'Is Local Host', 'Discovery Methods', 'Last Seen'];
      const rows = state.devices.map(d => [
        d.ip || '',
        d.hostname && d.hostname !== 'Unknown' ? d.hostname : '',
        d.mac && d.mac !== 'Unavailable' && d.mac !== 'Unknown' ? d.mac : '',
        d.vendor && d.vendor !== 'Unknown Vendor' ? d.vendor : '',
        d.device_type || '',
        d.status || '',
        d.verified ? 'Yes' : 'No',
        d.is_gateway ? 'Yes' : 'No',
        d.is_local_host ? 'Yes' : 'No',
        (d.methods || []).join('; '),
        d.last_seen || ''
      ]);

      const csvContent = [headers, ...rows].map(row =>
        row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
      ).join('\r\n');

      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `network_discovery_${state.scanId || Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    if (elements.ndExportJsonBtn) elements.ndExportJsonBtn.addEventListener('click', exportResultsJson);
    if (elements.ndExportCsvBtn) elements.ndExportCsvBtn.addEventListener('click', exportResultsCsv);

    // Search Clear Handler
    if (elements.ndSearchInput && elements.ndSearchClearBtn) {
      elements.ndSearchInput.addEventListener('input', (e) => {
        elements.ndSearchClearBtn.style.display = e.target.value.trim() ? 'flex' : 'none';
      });
      elements.ndSearchClearBtn.addEventListener('click', () => {
        elements.ndSearchInput.value = '';
        state.searchQuery = '';
        elements.ndSearchClearBtn.style.display = 'none';
        renderDeviceTable();
        elements.ndSearchInput.focus();
      });
    }

    // Delegated click and keydown handlers for Cards Grid
    if (elements.ndCardsGrid) {
      elements.ndCardsGrid.addEventListener('click', (e) => {
        const copyBtn = e.target.closest('.nd-mini-copy-btn');
        if (copyBtn) {
          e.stopPropagation();
          const text = copyBtn.getAttribute('data-copy-text');
          if (text) copyDirectText(text, copyBtn);
          return;
        }
        const scanPortsLink = e.target.closest('.nd-btn-scan-ports');
        if (scanPortsLink) {
          const card = e.target.closest('.nd-device-card');
          const targetIp = scanPortsLink.getAttribute('data-target-ip') || (card ? card.getAttribute('data-ip') : '');
          if (!triggerPortScanForDevice(targetIp, e)) {
            return;
          }
          return;
        }
        if (e.target.closest('a') || e.target.closest('button')) return;
        const card = e.target.closest('.nd-device-card');
        if (card) {
          const ip = card.getAttribute('data-ip');
          if (ip) openDeviceModal(ip);
        }
      });

      // Keyboard navigation for Cards Grid (Enter / Space opens details)
      elements.ndCardsGrid.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          const card = e.target.closest('.nd-device-card');
          if (card && !e.target.closest('a') && !e.target.closest('button')) {
            e.preventDefault();
            const ip = card.getAttribute('data-ip');
            if (ip) openDeviceModal(ip);
          }
        }
      });
    }

    // Delegated click and keydown handlers for Table Body
    if (elements.ndTableBody) {
      elements.ndTableBody.addEventListener('click', (e) => {
        const scanPortsLink = e.target.closest('.nd-btn-scan-ports');
        if (scanPortsLink) {
          const row = e.target.closest('.nd-device-row');
          const targetIp = scanPortsLink.getAttribute('data-target-ip') || (row ? row.getAttribute('data-ip') : '');
          if (!triggerPortScanForDevice(targetIp, e)) {
            return;
          }
          return;
        }
        if (e.target.closest('a') || e.target.closest('button')) return;
        const row = e.target.closest('.nd-device-row');
        if (row) {
          const ip = row.getAttribute('data-ip');
          if (ip) openDeviceModal(ip);
        }
      });

      // Keyboard navigation for Table Body (Enter / Space opens details)
      elements.ndTableBody.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          const row = e.target.closest('.nd-device-row');
          if (row && !e.target.closest('a') && !e.target.closest('button')) {
            e.preventDefault();
            const ip = row.getAttribute('data-ip');
            if (ip) openDeviceModal(ip);
          }
        }
      });
    }

    // Modal Port Scan Button Listener
    if (elements.modalPortScanLink) {
      elements.modalPortScanLink.addEventListener('click', (e) => {
        const targetIp = elements.modalPortScanLink.getAttribute('data-target-ip') ||
          (state.selectedDevice ? state.selectedDevice.ip : '');
        if (!triggerPortScanForDevice(targetIp, e)) {
          return;
        }
      });
    }

    // Modal Drawer Close & Backdrop
    if (elements.modalCloseBtn) {
      elements.modalCloseBtn.addEventListener('click', closeDeviceModal);
    }
    if (elements.modalFooterCloseBtn) {
      elements.modalFooterCloseBtn.addEventListener('click', closeDeviceModal);
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

    // Collapsible Sidebar & Mobile Navigation
    if (localStorage.getItem('nss_sidebar_collapsed') === 'true') {
      document.body.classList.add('sidebar-collapsed');
    }

    const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
    const navbarSidebarToggleBtn = document.getElementById('navbarSidebarToggleBtn');
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const sidebarBackdrop = document.getElementById('sidebarBackdrop');
    const sidebarMobileCloseBtn = document.getElementById('sidebarMobileCloseBtn');

    function closeMobileSidebar() {
      document.body.classList.remove('mobile-sidebar-open');
      if (mobileMenuBtn) mobileMenuBtn.setAttribute('aria-expanded', 'false');
      if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute('aria-expanded', 'false');
    }

    function handleSidebarToggle() {
      if (window.innerWidth < 992) {
        const isOpen = document.body.classList.toggle('mobile-sidebar-open');
        if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        if (mobileMenuBtn) mobileMenuBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      } else {
        const isCollapsed = document.body.classList.toggle('sidebar-collapsed');
        localStorage.setItem('nss_sidebar_collapsed', isCollapsed ? 'true' : 'false');
        if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
      }
    }

    if (sidebarToggleBtn) {
      sidebarToggleBtn.addEventListener('click', () => {
        const isCollapsed = document.body.classList.toggle('sidebar-collapsed');
        localStorage.setItem('nss_sidebar_collapsed', isCollapsed ? 'true' : 'false');
      });
    }

    if (navbarSidebarToggleBtn) {
      navbarSidebarToggleBtn.addEventListener('click', handleSidebarToggle);
    }

    if (mobileMenuBtn) {
      mobileMenuBtn.addEventListener('click', () => {
        const isOpen = document.body.classList.toggle('mobile-sidebar-open');
        mobileMenuBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      });
    }

    if (sidebarBackdrop) {
      sidebarBackdrop.addEventListener('click', closeMobileSidebar);
    }

    if (sidebarMobileCloseBtn) {
      sidebarMobileCloseBtn.addEventListener('click', closeMobileSidebar);
    }

    // Dismiss on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && document.body.classList.contains('mobile-sidebar-open')) {
        closeMobileSidebar();
      }
    });

    // Dismiss on resize
    window.addEventListener('resize', () => {
      if (window.innerWidth >= 992 && document.body.classList.contains('mobile-sidebar-open')) {
        closeMobileSidebar();
      }
    });

    function autoCloseSidebarAfterNav() {
      if (window.innerWidth < 992) {
        closeMobileSidebar();
      } else {
        if (!document.body.classList.contains('sidebar-collapsed')) {
          document.body.classList.add('sidebar-collapsed');
          localStorage.setItem('nss_sidebar_collapsed', 'true');
          if (navbarSidebarToggleBtn) {
            navbarSidebarToggleBtn.setAttribute('aria-expanded', 'false');
          }
        }
      }
    }

    document.querySelectorAll('.sidebar-nav-item').forEach(link => {
      link.addEventListener('click', (e) => {
        const navTarget = link.getAttribute('data-nav');
        if (navTarget === 'network-discovery') {
          e.preventDefault();
          window.scrollTo({ top: 0, behavior: 'smooth' });
          autoCloseSidebarAfterNav();
        } else {
          autoCloseSidebarAfterNav();
        }
      });
    });

    const sidebarBrandLink = document.getElementById('sidebarBrandLink');
    if (sidebarBrandLink) {
      sidebarBrandLink.addEventListener('click', () => {
        autoCloseSidebarAfterNav();
      });
    }

    const globalTopNavbar = document.getElementById('globalTopNavbar');
    if (globalTopNavbar) {
      window.addEventListener('scroll', () => {
        if (window.scrollY > 8) {
          globalTopNavbar.classList.add('is-scrolled');
        } else {
          globalTopNavbar.classList.remove('is-scrolled');
        }
      }, { passive: true });
    }
  }

  // 9. Theme Management (Light / Dark Mode with Persistence)
  function initTheme() {
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    const themeToggleIcon = document.getElementById('themeToggleIcon');
    const themeToggleText = document.getElementById('themeToggleText');
    const metaTheme = document.querySelector('meta[name="theme-color"]');

    function applyTheme(theme, animate = false) {
      if (animate) {
        document.body.classList.add('theme-transitioning');
      }
      document.documentElement.setAttribute('data-theme', theme);
      const isDark = theme === 'dark';

      if (themeToggleIcon) {
        themeToggleIcon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
      }
      if (themeToggleText) {
        themeToggleText.textContent = isDark ? 'Light Mode' : 'Dark Mode';
      }
      if (themeToggleBtn) {
        const titleStr = isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode';
        themeToggleBtn.setAttribute('title', titleStr);
        themeToggleBtn.setAttribute('aria-label', titleStr);
      }
      if (metaTheme) {
        metaTheme.setAttribute('content', isDark ? '#101411' : '#F7F5EF');
      }

      if (animate) {
        window.setTimeout(() => {
          document.body.classList.remove('theme-transitioning');
        }, 260);
      }
    }

    const savedTheme = localStorage.getItem('nss_theme');
    const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initialTheme = savedTheme || (systemDark ? 'dark' : 'light');
    applyTheme(initialTheme, false);

    if (themeToggleBtn) {
      themeToggleBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        const next = current === 'dark' ? 'light' : 'dark';
        localStorage.setItem('nss_theme', next);
        applyTheme(next, true);
      });
    }

    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem('nss_theme')) {
          applyTheme(e.matches ? 'dark' : 'light', true);
        }
      });
    }
  }

  // 10. Initialize Page
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initEventListeners();
    loadNetworkInfo();
    fetchScanStatus();
  });
})();
