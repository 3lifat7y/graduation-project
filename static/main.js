/**
 * DDoS-Guard — Frontend Control Engine
 * Real-time packet sniffer synchronization, multi-class threat telemetry,
 * interactive threat vector explorer & responsive UI interactions.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ============================================================================
  // 1. API Configuration & Constants
  // ============================================================================
  const API_BASE_URL = "/api";
  let scanPollInterval = null;
  let scanTimeoutTimer = null;
  let isScanning = false;
  let scanStartTime = 0;
  let activeScanId = null;

  // ============================================================================
  // 2. DOM Elements Cache
  // ============================================================================
  // Controls & Badges
  const checkBtn = document.getElementById("checkBtn");
  const rescanBtn = document.getElementById("rescanBtn");
  const rescanIcon = document.getElementById("rescanIcon");
  const rescanText = document.getElementById("rescanText");
  const rescanStatusBanner = document.getElementById("rescanStatusBanner");
  const rescanStatusIcon = document.getElementById("rescanStatusIcon");
  const rescanStatusTitle = document.getElementById("rescanStatusTitle");
  const rescanStatusDesc = document.getElementById("rescanStatusDesc");
  const rescanRecoveryActions = document.getElementById("rescanRecoveryActions");
  const rescanRestartBtn = document.getElementById("rescanRestartBtn");
  const rescanSelectAdapterBtn = document.getElementById("rescanSelectAdapterBtn");
  const rescanDismissBtn = document.getElementById("rescanDismissBtn");
  let isRescanning = false;

  const stopBtn = document.getElementById("stopBtn");
  const stateBadge = document.getElementById("stateBadge");
  const statusEl = document.getElementById("connectionStatus");
  const rateEl = document.getElementById("connectionRate");
  const labelEl = document.getElementById("connectionStatusText");
  const resultIcon = document.getElementById("resultIcon");
  const resultIconWrap = document.getElementById("resultIconWrap");
  const resultsConsole = document.getElementById("resultsConsole");
  const radarBox = document.getElementById("radarBox");
  const confidenceBarFill = document.getElementById("confidenceBarFill");
  const resultChipState = document.getElementById("resultChipState");

  // Telemetry Grid Items
  const telemetryGrid = document.getElementById("telemetryGrid");
  const telemetryPkts = document.getElementById("telemetryPkts");
  const telemetryDuration = document.getElementById("telemetryDuration");
  const telemetryThroughput = document.getElementById("telemetryThroughput");
  const telemetryProtocol = document.getElementById("telemetryProtocol");

  // Diagnostic Alerts
  const diagnosticAlert = document.getElementById("diagnosticAlert");
  const diagnosticMsg = document.getElementById("diagnosticMsg");

  // Real-Time Radar Packet Telemetry Blips
  const radarPacketBlips = document.getElementById("radarPacketBlips");
  const scannerConsole = document.getElementById("scannerConsole");
  let lastCapturedPacketCount = 0;

  function triggerRadarPacketBlip() {
    if (!radarPacketBlips || document.hidden) return;
    if (radarPacketBlips.children.length > 5) return;
    const blip = document.createElement("div");
    blip.className = "radar-packet-blip";
    const angle = Math.random() * Math.PI * 2;
    const distance = 15 + Math.random() * 55;
    const x = 50 + distance * Math.cos(angle);
    const y = 50 + distance * Math.sin(angle);
    blip.style.left = `${x}%`;
    blip.style.top = `${y}%`;
    radarPacketBlips.appendChild(blip);
    setTimeout(() => {
      if (blip.parentElement) blip.remove();
    }, 1500);
  }

  function updateTelemetryCounter(el, newText) {
    if (!el) return;
    if (el.textContent !== String(newText)) {
      el.textContent = newText;
      el.classList.remove("counter-pop");
      void el.offsetWidth;
      el.classList.add("counter-pop");
    }
  }

  // Adapter & Service Badges
  const adapterChip = document.getElementById("adapterChip");
  const adapterName = document.getElementById("adapterName");
  const adapterIp = document.getElementById("adapterIp");
  const driverStatusBadge = document.getElementById("driverStatusBadge");
  const adapterIcon = document.getElementById("adapterIcon");
  const headerHealthDot = document.getElementById("headerHealthDot");
  const headerHealthLabel = document.getElementById("headerHealthLabel");

  // Adapter Selection Hub Elements
  const adapterSelectionHub = document.getElementById("adapterSelectionHub");
  const monitoringAdapterSelect = document.getElementById("monitoringAdapterSelect");
  const autoSelectAdapterBtn = document.getElementById("autoSelectAdapterBtn");
  const refreshAdaptersBtn = document.getElementById("refreshAdaptersBtn");
  const refreshAdaptersIcon = document.getElementById("refreshAdaptersIcon");
  const refreshAdaptersText = document.getElementById("refreshAdaptersText");
  const adapterModeBadge = document.getElementById("adapterModeBadge");
  const adapterCountPill = document.getElementById("adapterCountPill");
  const adapterDetailsGrid = document.getElementById("adapterDetailsGrid");
  const adapterTypeMeta = document.getElementById("adapterTypeMeta");
  const adapterGatewayMeta = document.getElementById("adapterGatewayMeta");
  const adapterStatusPill = document.getElementById("adapterStatusPill");
  const adapterLinkSpeedMeta = document.getElementById("adapterLinkSpeedMeta");
  const adapterDriverMeta = document.getElementById("adapterDriverMeta");
  const adapterEmptyCard = document.getElementById("adapterEmptyCard");
  const adapterRationaleText = document.getElementById("adapterRationaleText");
  const candidatesTray = document.getElementById("candidatesTray");
  const candidatesChips = document.getElementById("candidatesChips");
  const adapterDisappearedAlert = document.getElementById("adapterDisappearedAlert");
  const adapterDisappearedTitle = document.getElementById("adapterDisappearedTitle");
  const adapterDisappearedMessage = document.getElementById("adapterDisappearedMessage");
  const monitoringAdapterError = document.getElementById("monitoringAdapterError");
  const adapterErrorTitle = document.getElementById("adapterErrorTitle");
  const adapterErrorMessage = document.getElementById("adapterErrorMessage");
  const adapterStatusDot = document.getElementById("adapterStatusDot");
  const adapterStatusText = document.getElementById("adapterStatusText");

  // State Management for Network Interface Hub
  let discoveredAdapters = [];
  let selectedAdapterMode = "auto"; // "auto" or "manual"
  let selectedAdapterKey = "auto";
  let autoSelectedAdapter = null;
  let currentNetworkAdapter = null;
  let lastSelectedManualAdapter = null;
  let selectedAdapterDisappeared = false;
  let selectionRationale = "";
  let evaluatedCandidates = [];

  // Refresh Concurrency, Sequence Guard & Abort Controller
  let isAdapterRefreshing = false;
  let adapterRefreshSequence = 0;
  let activeRefreshAbortController = null;

  // Live Monitoring Auto-Switch & Manual Stop Intent Tracking
  let userManuallyStopped = false;
  let adapterSwitchSeq = 0;

  // Navigation & UI Elements
  const menuToggle = document.getElementById("menuToggle");
  const mainNav = document.getElementById("mainNav");
  const backToTopBtn = document.getElementById("backToTop");
  const headerQuickCheckBtn = document.getElementById("headerQuickCheckBtn");

  // Threat Vectors Slider & Filter Elements
  const slider = document.querySelector(".slider");
  const cardContainer = document.querySelector(".card-container");
  const sliderPrevBtn = document.getElementById("sliderPrevBtn");
  const sliderNextBtn = document.getElementById("sliderNextBtn");
  const filterTabs = document.querySelectorAll(".filter-tab");
  const sliderCurrentIndex = document.getElementById("sliderCurrentIndex");
  const sliderTotalCount = document.getElementById("sliderTotalCount");
  const allCards = Array.from(document.querySelectorAll(".attack-card-item"));

  // ============================================================================
  // 3. Header & Service Status Synchronization
  // ============================================================================
  function updateServiceBadge(svc, drv) {
    if (!svc && !drv) return;
    svc = svc || {};
    drv = drv || {};

    const statusStr = (svc.status || "").toUpperCase();
    const isRunning = svc.running === true || statusStr === "RUNNING";
    const isPending = statusStr === "START_PENDING";
    const isStopped = statusStr === "STOPPED" || statusStr === "STOP_PENDING";

    let labelText = "Service: Checking...";
    let badgeClass = "driver-badge";
    let healthClass = "stopped";
    let healthText = "Service Stopped";

    if (isRunning) {
      if (svc.ipc_online !== false) {
        labelText = "Service: Running";
        badgeClass = "driver-badge driver-ready";
        healthClass = "running";
        healthText = "Service Online";
      } else {
        labelText = "Service: Connecting...";
        badgeClass = "driver-badge driver-pending";
        healthClass = "pending";
        healthText = "IPC Connecting";
      }
    } else if (isPending) {
      labelText = "Service: Starting...";
      badgeClass = "driver-badge driver-pending";
      healthClass = "pending";
      healthText = "Service Starting";
    } else if (svc.installed) {
      labelText = `Service: ${svc.status || "Stopped"}`;
      badgeClass = "driver-badge driver-stopped";
      healthClass = "stopped";
      healthText = "Service Inactive";
    } else if (drv.can_capture_live) {
      labelText = "Npcap: Ready";
      badgeClass = "driver-badge driver-ready";
      healthClass = "running";
      healthText = "Npcap Ready";
    } else {
      labelText = "Service: Not Installed";
      badgeClass = "driver-badge driver-stopped";
      healthClass = "stopped";
      healthText = "Service Offline";
    }

    if (driverStatusBadge) {
      driverStatusBadge.textContent = labelText;
      driverStatusBadge.className = badgeClass;
    }

    if (headerHealthDot && headerHealthLabel) {
      headerHealthDot.className = `health-dot ${healthClass}`;
      headerHealthLabel.textContent = healthText;
    }

    const headerHealthDotMobile = document.getElementById("headerHealthDotMobile");
    if (headerHealthDotMobile) {
      headerHealthDotMobile.className = `health-dot ${healthClass}`;
    }

    const topNavHealthDot = document.getElementById("topNavHealthDot");
    const topNavHealthLabel = document.getElementById("topNavHealthLabel");
    if (topNavHealthDot) {
      topNavHealthDot.className = `health-dot ${healthClass}`;
    }
    if (topNavHealthLabel) {
      topNavHealthLabel.textContent = `Engine Core: ${healthText}`;
    }
  }

  function getAdapterKey(ad) {
    if (!ad) return "";
    return ad.guid || ad.network_name || (ad.index !== undefined && ad.index !== null ? `idx_${ad.index}` : ad.name);
  }

  function renderAdapterDropdown(preserveSelection = true) {
    if (!monitoringAdapterSelect) return;

    const previousKey = selectedAdapterKey;
    monitoringAdapterSelect.innerHTML = "";

    // Empty state handling
    if (!discoveredAdapters || discoveredAdapters.length === 0) {
      if (adapterEmptyCard) adapterEmptyCard.style.display = "flex";
      if (adapterDetailsGrid) adapterDetailsGrid.style.display = "none";
      if (adapterCountPill) adapterCountPill.textContent = "0 Discovered";

      const emptyOpt = document.createElement("option");
      emptyOpt.value = "";
      emptyOpt.disabled = true;
      emptyOpt.selected = true;
      emptyOpt.textContent = "No Network Adapters Detected";
      monitoringAdapterSelect.appendChild(emptyOpt);
      return;
    }

    if (adapterEmptyCard) adapterEmptyCard.style.display = "none";
    if (adapterDetailsGrid) adapterDetailsGrid.style.display = "grid";
    if (adapterCountPill) adapterCountPill.textContent = `${discoveredAdapters.length} Discovered`;

    // 1. Auto Select option
    const autoOpt = document.createElement("option");
    autoOpt.value = "auto";
    const autoRec = autoSelectedAdapter
      ? `${autoSelectedAdapter.name} (${autoSelectedAdapter.primary_ip || 'No IPv4'})`
      : "OS Default";
    autoOpt.textContent = `⚡ Auto Select (Recommended: ${autoRec})`;
    monitoringAdapterSelect.appendChild(autoOpt);

    // 2. Discovered adapters
    discoveredAdapters.forEach((ad) => {
      const opt = document.createElement("option");
      const key = getAdapterKey(ad);
      opt.value = key;

      const typeTag = `[${ad.type || 'Adapter'}]`;
      const ipStr = ad.primary_ip ? ` — ${ad.primary_ip}` : (ad.status !== 'Up' ? ` — ${ad.status}` : ' — No IP');
      const descStr = ad.description ? ` (${ad.description})` : '';
      const captureStr = ad.can_capture ? ' [Capture Ready]' : '';

      opt.textContent = `${typeTag} ${ad.name}${ipStr}${descStr}${captureStr}`;

      if (ad.status === "Disconnected" || ad.status === "Disabled") {
        opt.textContent += " (Offline)";
      }
      monitoringAdapterSelect.appendChild(opt);
    });

    // 3. Selection preservation logic
    if (preserveSelection && selectedAdapterMode === "manual" && previousKey !== "auto") {
      const matched = discoveredAdapters.find(ad => getAdapterKey(ad) === previousKey);
      if (matched) {
        monitoringAdapterSelect.value = previousKey;
        selectedAdapterKey = previousKey;
        currentNetworkAdapter = matched;
        lastSelectedManualAdapter = matched;
        selectedAdapterDisappeared = false;
        if (adapterDisappearedAlert) adapterDisappearedAlert.style.display = "none";
        return;
      } else {
        // Previously selected manual adapter disappeared from operating system!
        selectedAdapterDisappeared = true;
        const missingName = lastSelectedManualAdapter ? lastSelectedManualAdapter.name : previousKey;
        if (isScanning) {
          stopScan(true);
          setUIState("error", {
            message: `Selected adapter '${missingName}' was disconnected or removed. Packet capture stopped.`
          });
        }
        if (adapterDisappearedAlert) {
          adapterDisappearedAlert.style.display = "flex";
          if (adapterDisappearedMessage) {
            adapterDisappearedMessage.textContent = `Previously selected adapter '${missingName}' was disconnected or removed. Live capture cannot proceed with a missing adapter. Please select an operational adapter from the dropdown or click 'Auto Select'.`;
          }
        }
        const disOpt = document.createElement("option");
        disOpt.value = previousKey;
        disOpt.disabled = true;
        disOpt.selected = true;
        disOpt.textContent = `⚠️ [Unavailable] ${missingName} (Disconnected / Removed)`;
        monitoringAdapterSelect.appendChild(disOpt);
        monitoringAdapterSelect.value = previousKey;
        return;
      }
    }

    // Default to auto mode
    monitoringAdapterSelect.value = "auto";
    selectedAdapterKey = "auto";
    selectedAdapterMode = "auto";
    currentNetworkAdapter = autoSelectedAdapter;
    selectedAdapterDisappeared = false;
    if (adapterDisappearedAlert) adapterDisappearedAlert.style.display = "none";
  }

  function updateSelectedAdapterDisplay() {
    const isAuto = (selectedAdapterMode === "auto");

    // Mode badge
    if (adapterModeBadge) {
      if (selectedAdapterDisappeared) {
        adapterModeBadge.textContent = "Selection Missing";
        adapterModeBadge.className = "adapter-mode-badge manual-mode";
      } else if (isAuto) {
        adapterModeBadge.textContent = "Auto Select Active";
        adapterModeBadge.className = "adapter-mode-badge auto-mode";
      } else {
        adapterModeBadge.textContent = "Manual Selection";
        adapterModeBadge.className = "adapter-mode-badge manual-mode";
      }
    }

    // Handle missing / disappeared adapter state
    if (selectedAdapterDisappeared) {
      const missingName = lastSelectedManualAdapter ? lastSelectedManualAdapter.name : selectedAdapterKey;
      if (adapterName) adapterName.textContent = `${missingName} [Unavailable]`;
      if (adapterTypeMeta) adapterTypeMeta.textContent = "Hardware Disconnected / Removed";
      if (adapterIp) adapterIp.textContent = "IPv4: Offline";
      if (adapterGatewayMeta) adapterGatewayMeta.textContent = "Default Gateway: Unavailable";
      if (adapterStatusText) adapterStatusText.textContent = "Disconnected / Removed";
      if (adapterStatusDot) adapterStatusDot.className = "chip-dot dot-red";
      if (adapterLinkSpeedMeta) adapterLinkSpeedMeta.textContent = "Physical Link: Severed";
      if (driverStatusBadge) {
        driverStatusBadge.textContent = "Capture: Blocked";
        driverStatusBadge.className = "driver-badge driver-stopped";
      }
      if (adapterDriverMeta) adapterDriverMeta.textContent = "Hardware unavailable for Npcap binding";
      if (adapterRationaleText) {
        adapterRationaleText.textContent = `Manual adapter selection '${missingName}' is missing. The system enforces strict zero-fallback: live capture will NOT silently switch to another adapter. Please choose an active adapter or click Auto Select.`;
      }
      if (candidatesTray) candidatesTray.style.display = "none";
      return;
    }

    const activeAd = isAuto ? autoSelectedAdapter : currentNetworkAdapter;

    if (activeAd) {
      // Card 1: Device Name, Type & Icon
      if (adapterName) {
        adapterName.textContent = activeAd.name || "Unknown Adapter";
      }
      if (adapterTypeMeta) {
        const typeLabel = activeAd.type || "Physical";
        const desc = activeAd.description ? ` • ${activeAd.description}` : "";
        adapterTypeMeta.textContent = `${typeLabel} Hardware${desc}`;
      }
      if (adapterIcon) {
        if (activeAd.type === "Ethernet") {
          adapterIcon.className = "fas fa-ethernet";
        } else if (activeAd.type === "Wi-Fi") {
          adapterIcon.className = "fas fa-wifi";
        } else if (activeAd.type === "VirtualBox" || activeAd.is_virtual) {
          adapterIcon.className = "fas fa-server";
        } else {
          adapterIcon.className = "fas fa-network-wired";
        }
      }

      // Card 2: IPv4 Address & Gateway
      if (adapterIp) {
        adapterIp.textContent = `IPv4: ${activeAd.primary_ip || (activeAd.status === 'Up' ? 'DHCP Pending' : 'None')}`;
      }
      if (adapterGatewayMeta) {
        adapterGatewayMeta.textContent = activeAd.gateway
          ? `Default Gateway: ${activeAd.gateway}`
          : "Default Gateway: None / Direct Subnet";
      }

      // Card 3: Connection State & Link Speed
      if (adapterStatusText) {
        adapterStatusText.textContent = `Status: ${activeAd.status || 'Unknown'}`;
      }
      if (adapterStatusDot) {
        if (activeAd.status === "Up") {
          adapterStatusDot.className = "chip-dot dot-green";
        } else if (activeAd.status === "Disconnected" || activeAd.status === "Disabled") {
          adapterStatusDot.className = "chip-dot dot-red";
        } else {
          adapterStatusDot.className = "chip-dot dot-gray";
        }
      }
      if (adapterLinkSpeedMeta) {
        if (activeAd.link_speed) {
          adapterLinkSpeedMeta.textContent = `Link Speed: ${activeAd.link_speed}`;
        } else if (activeAd.mac) {
          adapterLinkSpeedMeta.textContent = `MAC: ${activeAd.mac}`;
        } else {
          adapterLinkSpeedMeta.textContent = "Physical Link Active";
        }
      }

      // Card 4: Capture Driver Readiness
      if (driverStatusBadge) {
        if (activeAd.can_capture) {
          driverStatusBadge.textContent = "Npcap: Capture Ready";
          driverStatusBadge.className = "driver-badge driver-ready";
        } else {
          driverStatusBadge.textContent = "Driver: Unavailable";
          driverStatusBadge.className = "driver-badge driver-stopped";
        }
      }
      if (adapterDriverMeta) {
        adapterDriverMeta.textContent = activeAd.can_capture
          ? "Scapy Kernel Driver Bound"
          : "Npcap Binding Not Detected";
      }

      // Rationale and Candidates
      if (adapterRationaleText) {
        if (isAuto) {
          adapterRationaleText.textContent = selectionRationale ||
            `Auto-selected '${activeAd.name}' based on active routing and packet capture capability.`;
        } else {
          adapterRationaleText.textContent =
            `Manually selected '${activeAd.name}' for packet capture. Hardware: ${activeAd.description || activeAd.type}. Operational status: ${activeAd.status}. IPv4: ${activeAd.primary_ip || 'None'}. Scapy driver binding: ${activeAd.can_capture ? 'Ready' : 'Pending'}. Strict zero-fallback policy active.`;
        }
      }

      // Evaluated candidates tray
      if (candidatesTray && candidatesChips) {
        if (isAuto && evaluatedCandidates && evaluatedCandidates.length > 0) {
          candidatesTray.style.display = "flex";
          candidatesChips.innerHTML = "";
          evaluatedCandidates.forEach(c => {
            const chip = document.createElement("span");
            chip.className = "candidate-chip" + (c.is_selected ? " selected" : "");
            chip.textContent = `${c.name} (${c.type}: ${c.primary_ip || c.status})`;
            candidatesChips.appendChild(chip);
          });
        } else {
          candidatesTray.style.display = "none";
        }
      }

      // Check offline warning
      if (monitoringAdapterError && adapterErrorMessage) {
        if (activeAd.status === "Disconnected" || activeAd.status === "Disabled") {
          monitoringAdapterError.style.display = "flex";
          adapterErrorMessage.textContent = `Selected interface '${activeAd.name}' is currently ${activeAd.status}. Live capture cannot start on an offline adapter. Please connect the cable, enable the interface, or choose another adapter.`;
        } else {
          monitoringAdapterError.style.display = "none";
        }
      }
    } else {
      if (adapterName) adapterName.textContent = "No Adapter Detected";
      if (adapterTypeMeta) adapterTypeMeta.textContent = "Hardware Interface";
      if (adapterIp) adapterIp.textContent = "IPv4: None";
      if (adapterGatewayMeta) adapterGatewayMeta.textContent = "Default Gateway: None";
      if (adapterStatusText) adapterStatusText.textContent = "Status: Offline";
      if (adapterStatusDot) adapterStatusDot.className = "chip-dot dot-red";
      if (adapterLinkSpeedMeta) adapterLinkSpeedMeta.textContent = "Physical Link: Down";
      if (driverStatusBadge) {
        driverStatusBadge.textContent = "Driver: Inactive";
        driverStatusBadge.className = "driver-badge driver-stopped";
      }
      if (adapterDriverMeta) adapterDriverMeta.textContent = "No Adapter Bound";
      if (monitoringAdapterError && adapterErrorMessage) {
        monitoringAdapterError.style.display = "flex";
        adapterErrorMessage.textContent = "No active physical network adapter was detected on the host. Please connect to Wi-Fi or plug in an Ethernet cable.";
      }
    }
  }

  async function discoverInterfaces(preserveSelection = true, isUserInitiated = false) {
    // 1. Concurrency guard: reject duplicate overlapping requests
    if (isAdapterRefreshing) {
      console.log("[AdapterHub] Refresh operation already in progress. Ignoring duplicate click.");
      return;
    }

    isAdapterRefreshing = true;
    const reqSeq = ++adapterRefreshSequence;

    // 2. Visual loading state on button and hub
    if (refreshAdaptersBtn) {
      refreshAdaptersBtn.disabled = true;
    }
    if (refreshAdaptersText) {
      refreshAdaptersText.textContent = "Refreshing...";
    }
    if (refreshAdaptersIcon) {
      refreshAdaptersIcon.classList.add("fa-spin");
    }
    if (adapterSelectionHub) {
      adapterSelectionHub.classList.add("hub-refreshing");
    }

    // 3. Setup timeout abort controller (8 seconds)
    if (activeRefreshAbortController) {
      try { activeRefreshAbortController.abort(); } catch (e) {}
    }
    activeRefreshAbortController = new AbortController();
    const timeoutId = setTimeout(() => {
      if (activeRefreshAbortController) {
        try { activeRefreshAbortController.abort(); } catch (e) {}
      }
    }, 8000);

    try {
      const res = await fetch(`${API_BASE_URL}/adapter-info`, {
        signal: activeRefreshAbortController.signal
      });
      clearTimeout(timeoutId);

      // Guard against stale response race conditions
      if (reqSeq !== adapterRefreshSequence) {
        console.log(`[AdapterHub] Discarding stale response (seq ${reqSeq} < current ${adapterRefreshSequence})`);
        return;
      }

      if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`);
      const data = await res.json();

      if (reqSeq !== adapterRefreshSequence) return;

      if (data.status === "success" || data.status === "warning") {
        discoveredAdapters = Array.isArray(data.available_adapters) ? data.available_adapters : [];
        autoSelectedAdapter = data.adapter || data.auto_selected || null;
        selectionRationale = data.selection_rationale || "";
        evaluatedCandidates = Array.isArray(data.candidates) ? data.candidates : [];

        const drv = data.driver_status || {};
        const svc = data.service_state || drv.service_state || {};
        updateServiceBadge(svc, drv);

        renderAdapterDropdown(preserveSelection);
        updateSelectedAdapterDisplay();

        if (monitoringAdapterError && !selectedAdapterDisappeared) {
          monitoringAdapterError.style.display = "none";
        }
      }
    } catch (err) {
      clearTimeout(timeoutId);
      if (reqSeq !== adapterRefreshSequence) return;

      console.warn("[AdapterHub] Interface discovery failed:", err);
      const isTimeout = (err.name === "AbortError");
      const errorMsg = isTimeout
        ? "Network interface discovery timed out after 8 seconds. Please check host connectivity and retry."
        : `Interface discovery error: ${err.message || err}.`;

      if (adapterRationaleText) {
        adapterRationaleText.textContent = `${errorMsg} Retaining previous adapter configurations.`;
      }
      if (isUserInitiated && monitoringAdapterError && adapterErrorMessage) {
        monitoringAdapterError.style.display = "flex";
        adapterErrorMessage.textContent = errorMsg;
      }
    } finally {
      // 4. Always restore button state (never leave permanently disabled)
      if (reqSeq === adapterRefreshSequence) {
        isAdapterRefreshing = false;
        activeRefreshAbortController = null;
        if (refreshAdaptersIcon) {
          refreshAdaptersIcon.classList.remove("fa-spin");
        }
        if (refreshAdaptersText) {
          refreshAdaptersText.textContent = "Refresh Interfaces";
        }
        if (refreshAdaptersBtn) {
          refreshAdaptersBtn.disabled = false;
        }
        if (adapterSelectionHub) {
          adapterSelectionHub.classList.remove("hub-refreshing");
        }
      }
    }
  }

  async function loadAdapterInfo() {
    await discoverInterfaces(true);
  }

  async function syncServiceStatus() {
    if (isScanning) return;
    try {
      // Light status polling without triggering heavy OS adapter enumeration
      const res = await fetch(`${API_BASE_URL}/service-status`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.status === "success" && data.service) {
        updateServiceBadge(data.service);
      }
    } catch (err) {
      // Ignore background heartbeat error
    }
  }

  // ============================================================================
  // 3b. Live Monitoring Automatic Interface Switching Engine
  // ============================================================================
  async function handleAdapterSelectionChange(val) {
    const currentSeq = ++adapterSwitchSeq;
    selectedAdapterKey = val;
    selectedAdapterDisappeared = false;
    if (adapterDisappearedAlert) adapterDisappearedAlert.style.display = "none";
    if (monitoringAdapterError) monitoringAdapterError.style.display = "none";

    if (val === "auto") {
      selectedAdapterMode = "auto";
      currentNetworkAdapter = autoSelectedAdapter;
    } else {
      selectedAdapterMode = "manual";
      const found = discoveredAdapters.find(ad => getAdapterKey(ad) === val);
      if (found) {
        currentNetworkAdapter = found;
        lastSelectedManualAdapter = found;
      }
    }
    updateSelectedAdapterDisplay();

    // Guard against missing/disappeared adapter
    if (selectedAdapterDisappeared) {
      return;
    }

    // Zero silent fallback: if selected adapter is Disconnected or Disabled, abort capture & report actual error
    const activeAd = (selectedAdapterMode === "auto") ? autoSelectedAdapter : currentNetworkAdapter;
    if (activeAd && (activeAd.status === "Disconnected" || activeAd.status === "Disabled")) {
      if (isScanning) {
        await stopScan(true);
      }
      const offMsg = `Selected adapter '${activeAd.name}' is ${activeAd.status}. Live packet capture cannot start on a disconnected or disabled interface. Please connect the cable, enable the adapter, or choose another interface.`;
      if (monitoringAdapterError && adapterErrorMessage) {
        monitoringAdapterError.style.display = "flex";
        adapterErrorMessage.textContent = offMsg;
      }
      setUIState("error", { message: offMsg });
      return;
    }

    // Requirement 9: If user manually stopped monitoring earlier, do not restart unexpectedly; wait for Start click.
    if (!isScanning && userManuallyStopped) {
      console.log("[AdapterHub] Adapter selection updated while monitoring manually stopped. Retaining stopped state.");
      return;
    }

    console.log(`[AdapterHub] Auto-triggering capture on '${activeAd ? activeAd.name : val}' (seq: ${currentSeq}, wasScanning: ${isScanning})...`);

    // Requirement 2: Safely stop and clean up previous capture worker before starting the new one
    if (isScanning) {
      await stopScan(true);
      if (currentSeq !== adapterSwitchSeq) {
        console.log(`[AdapterHub] Discarding outdated switch sequence ${currentSeq} (current: ${adapterSwitchSeq})`);
        return;
      }
    }

    // Requirement 5: Reset packet counters and telemetry displays to clean zero state
    if (telemetryPkts) telemetryPkts.textContent = "0";
    if (telemetryDuration) telemetryDuration.textContent = "0.0 s";
    if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
    if (telemetryProtocol) telemetryProtocol.textContent = "Npcap";
    lastCapturedPacketCount = 0;

    if (currentSeq !== adapterSwitchSeq) return;

    await startScan({ forceRestart: true, switchSeq: currentSeq });
  }

  // Bind Adapter Hub Controls
  if (monitoringAdapterSelect) {
    monitoringAdapterSelect.addEventListener("change", async (e) => {
      await handleAdapterSelectionChange(e.target.value);
    });
  }

  if (autoSelectAdapterBtn) {
    autoSelectAdapterBtn.addEventListener("click", async () => {
      const wasAuto = (selectedAdapterMode === "auto" && selectedAdapterKey === "auto");
      if (monitoringAdapterSelect) {
        monitoringAdapterSelect.value = "auto";
      }
      if (!wasAuto) {
        await handleAdapterSelectionChange("auto");
      } else {
        updateSelectedAdapterDisplay();
      }
    });
  }

  if (refreshAdaptersBtn) {
    refreshAdaptersBtn.addEventListener("click", (e) => {
      e.preventDefault();
      discoverInterfaces(true, true);
    });
  }

  // Initial interface discovery and heartbeat interval
  discoverInterfaces(false);
  setInterval(syncServiceStatus, 5000);

  // ============================================================================
  // 4. Reactive UI State Machine (6 Clean Scan States)
  // ============================================================================
  function setUIState(state, payload = {}) {
    if (payload && (payload.service_state || payload.driver_status)) {
      updateServiceBadge(payload.service_state, payload.driver_status);
    }
    if (payload && payload.interface) {
      const iface = payload.interface;
      if (adapterName) adapterName.textContent = `${iface.name} (${iface.type})`;
      if (adapterIp && iface.primary_ip) adapterIp.textContent = `IPv4: ${iface.primary_ip}`;
      if (adapterIcon) {
        adapterIcon.className = (iface.type === "Ethernet") ? "fas fa-ethernet" : "fas fa-wifi";
      }
    }

    if (stateBadge) {
      stateBadge.className = `status-indicator-badge state-${state}`;
    }

    // Reset console status classes
    if (resultsConsole) {
      resultsConsole.classList.remove("state-benign", "state-attack");
    }

    switch (state) {
      case "ready":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-ready";
          stateBadge.textContent = "Ready";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Standby";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = "none";
          rescanBtn.disabled = false;
        }
        if (rescanStatusBanner) {
          rescanStatusBanner.style.display = "none";
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }
        if (statusEl) {
          statusEl.textContent = payload.message || "System ready. Click 'Start Monitoring' to capture live network traffic.";
          statusEl.style.color = "";
        }
        break;

      case "starting":
      case "scanning":
        isScanning = true;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-scanning";
          stateBadge.textContent = "Starting...";
        }
        if (radarBox) radarBox.classList.add("active");
        if (scannerConsole) scannerConsole.classList.add("scanning-active");
        if (resultChipState) resultChipState.textContent = "Starting Engine";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> <span class="btn-text">Starting...</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = "inline-flex";
          rescanBtn.disabled = true;
        }
        if (stopBtn) {
          stopBtn.style.display = "inline-flex";
          stopBtn.disabled = false;
        }

        if (statusEl) {
          statusEl.textContent = payload.message || "Initializing packet capture session across active adapter...";
          statusEl.style.color = "";
        }
        if (diagnosticAlert) diagnosticAlert.style.display = "none";
        break;

      case "monitoring":
      case "prediction_available":
        isScanning = true;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-monitoring";
          stateBadge.textContent = "Monitoring";
        }
        if (radarBox) radarBox.classList.add("active");
        if (scannerConsole) scannerConsole.classList.add("scanning-active");
        if (resultChipState) resultChipState.textContent = "Live Telemetry";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-wave-square fa-spin"></i> <span class="btn-text">Monitoring Live</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = "inline-flex";
          rescanBtn.disabled = isRescanning;
        }
        if (stopBtn) {
          stopBtn.style.display = "inline-flex";
          stopBtn.disabled = false;
        }

        const isAttack = Boolean(payload.is_attack);
        const label = payload.label || (isAttack ? "DDoS Attack" : "Benign");
        const confNum = typeof payload.confidence === "number" ? payload.confidence : 0;
        const confStr = confNum > 0 ? `${confNum.toFixed(1)}%` : "--%";

        if (resultsConsole) {
          resultsConsole.classList.remove("state-benign", "state-attack");
          resultsConsole.classList.add(isAttack ? "state-attack" : "state-benign");
        }

        if (labelEl) {
          labelEl.textContent = label;
          labelEl.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        if (rateEl) {
          rateEl.textContent = `Confidence: ${confStr}`;
          rateEl.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        if (confidenceBarFill) {
          confidenceBarFill.style.width = `${Math.min(Math.max(confNum, 5), 100)}%`;
          confidenceBarFill.style.background = isAttack
            ? "linear-gradient(90deg, #f59e0b, #ef4444)"
            : "linear-gradient(90deg, #00e5ff, #10b981)";
        }

        if (statusEl) {
          statusEl.textContent = isAttack
            ? "⚠️ Security Alert: Malicious DDoS Traffic Signature Detected!"
            : "✅ Security Status: Normal / Benign Traffic Flow Verified";
          statusEl.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        if (resultIcon) {
          resultIcon.className = isAttack
            ? "fas fa-shield-virus result-icon"
            : "fas fa-shield-halved result-icon";
          resultIcon.style.color = isAttack ? "var(--status-attack)" : "var(--status-benign)";
        }

        // Render Telemetry Flow Statistics & Trigger Live Packet Blips
        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          const totalPkts = payload.packets_captured !== undefined ? payload.packets_captured : (payload.flow_summary?.packets_captured || 0);

          // Animate packet arrival blip when new packets are genuinely intercepted
          if (totalPkts > lastCapturedPacketCount) {
            const diff = totalPkts - lastCapturedPacketCount;
            lastCapturedPacketCount = totalPkts;
            const count = Math.min(diff, 4);
            for (let i = 0; i < count; i++) {
              setTimeout(triggerRadarPacketBlip, i * 130);
            }
          }

          if (telemetryPkts) {
            const winPkts = payload.window_packets !== undefined ? payload.window_packets : 0;
            const pktsText = winPkts > 0 ? `${totalPkts} (${winPkts}/win)` : `${totalPkts}`;
            updateTelemetryCounter(telemetryPkts, pktsText);
          }
          if (telemetryDuration) {
            const dur = payload.duration !== undefined ? payload.duration : (((payload.flow_summary?.flow_duration_us || 0) / 1000000));
            telemetryDuration.textContent = `${Number(dur).toFixed(1)} s`;
          }
          if (telemetryThroughput) {
            const kbps = payload.throughput_kbps !== undefined ? payload.throughput_kbps : (((payload.flow_summary?.flow_bytes_per_s || 0) / 1024));
            updateTelemetryCounter(telemetryThroughput, `${Number(kbps).toFixed(1)} KB/s`);
          }
          if (telemetryProtocol) {
            telemetryProtocol.textContent = payload.protocol || "Npcap";
          }
        }
        if (diagnosticAlert) diagnosticAlert.style.display = "none";
        break;

      case "no_traffic":
        const isContinuousNoTraffic = payload.continuous !== false;
        isScanning = isContinuousNoTraffic;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-no_traffic";
          stateBadge.textContent = "No Traffic Detected";
        }
        if (radarBox) {
          if (isContinuousNoTraffic) radarBox.classList.add("active");
          else radarBox.classList.remove("active");
        }
        if (resultChipState) resultChipState.textContent = isContinuousNoTraffic ? "Idle Window" : "Idle Network";

        if (checkBtn) {
          checkBtn.disabled = isContinuousNoTraffic;
          checkBtn.innerHTML = isContinuousNoTraffic
            ? '<i class="fas fa-wave-square"></i> <span class="btn-text">Monitoring (Idle)...</span>'
            : '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = isContinuousNoTraffic ? "inline-flex" : "none";
          rescanBtn.disabled = isContinuousNoTraffic ? isRescanning : false;
        }
        if (stopBtn) {
          stopBtn.style.display = isContinuousNoTraffic ? "inline-flex" : "none";
          stopBtn.disabled = !isContinuousNoTraffic;
        }

        // Clear stale prediction (never classify empty or invalid features as Benign)
        if (resultsConsole) {
          resultsConsole.classList.remove("state-benign", "state-attack");
        }
        if (labelEl) {
          labelEl.textContent = "No Traffic Detected";
          labelEl.style.color = "var(--text-muted)";
        }
        if (rateEl) {
          rateEl.textContent = "Confidence: N/A";
          rateEl.style.color = "var(--text-muted)";
        }
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "No packets intercepted during rolling window. Waiting for network traffic...";
          statusEl.style.color = "var(--text-muted)";
        }

        if (resultIcon) {
          resultIcon.className = "fas fa-network-wired result-icon";
          resultIcon.style.color = "var(--text-muted)";
        }

        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          if (telemetryPkts) telemetryPkts.textContent = `${payload.packets_captured || 0} (0/win)`;
          if (telemetryDuration) telemetryDuration.textContent = `${Number(payload.duration || 0).toFixed(1)} s`;
          if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
          if (telemetryProtocol) telemetryProtocol.textContent = "Idle";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = "Zero physical network packets intercepted in active window. If Wi-Fi is disabled, please connect to a network. If connected, browse a webpage or run 'python send_traffic.py'.";
          }
        }
        break;

      case "insufficient_traffic":
        const isContinuousInsufficient = payload.continuous !== false;
        isScanning = isContinuousInsufficient;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-insufficient_traffic";
          stateBadge.textContent = "Insufficient Data";
        }
        if (radarBox) {
          if (isContinuousInsufficient) radarBox.classList.add("active");
          else radarBox.classList.remove("active");
        }
        if (resultChipState) resultChipState.textContent = "Low Packet Volume";

        if (checkBtn) {
          checkBtn.disabled = isContinuousInsufficient;
          checkBtn.innerHTML = isContinuousInsufficient
            ? '<i class="fas fa-wave-square"></i> <span class="btn-text">Monitoring (Low Traffic)...</span>'
            : '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = isContinuousInsufficient ? "inline-flex" : "none";
          rescanBtn.disabled = isContinuousInsufficient ? isRescanning : false;
        }
        if (stopBtn) {
          stopBtn.style.display = isContinuousInsufficient ? "inline-flex" : "none";
          stopBtn.disabled = !isContinuousInsufficient;
        }

        // Clear stale prediction (never classify insufficient features as Benign)
        if (resultsConsole) {
          resultsConsole.classList.remove("state-benign", "state-attack");
        }
        if (labelEl) {
          labelEl.textContent = "Insufficient Data";
          labelEl.style.color = "var(--status-warning)";
        }
        if (rateEl) {
          rateEl.textContent = "Confidence: N/A";
          rateEl.style.color = "var(--text-muted)";
        }
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "Interpreting traffic: window packet volume is below model classification threshold.";
          statusEl.style.color = "var(--status-warning)";
        }

        if (resultIcon) {
          resultIcon.className = "fas fa-hourglass-half result-icon";
          resultIcon.style.color = "var(--status-warning)";
        }

        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          const winPkts = payload.window_packets !== undefined ? payload.window_packets : (payload.packets_captured || 0);
          if (telemetryPkts) telemetryPkts.textContent = `${payload.packets_captured || 0} (${winPkts}/win)`;
          if (telemetryDuration) telemetryDuration.textContent = `${Number(payload.duration || 0).toFixed(1)} s`;
          if (telemetryThroughput) telemetryThroughput.textContent = `${(payload.throughput_kbps || 0.0).toFixed(1)} KB/s`;
          if (telemetryProtocol) telemetryProtocol.textContent = payload.protocol || "Gathering...";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = `Only ${payload.window_packets || payload.packets_captured || 0} packet(s) were captured in current window (minimum ${payload.min_required || 3} required). Generate more traffic.`;
          }
        }
        break;

      case "stopped":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-stopped";
          stateBadge.textContent = "Stopped";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (scannerConsole) scannerConsole.classList.remove("scanning-active");
        if (radarPacketBlips) radarPacketBlips.innerHTML = "";
        lastCapturedPacketCount = 0;
        if (resultChipState) resultChipState.textContent = "Monitoring Stopped";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = "none";
          rescanBtn.disabled = false;
        }
        if (rescanStatusBanner) {
          rescanStatusBanner.style.display = "none";
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }

        if (statusEl) {
          statusEl.textContent = payload.message || "Continuous monitoring stopped by user.";
          statusEl.style.color = "var(--text-muted)";
        }
        if (telemetryDuration && payload.duration) {
          telemetryDuration.textContent = `${Number(payload.duration).toFixed(1)} s`;
        }
        break;

      case "uac_cancelled":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-uac_cancelled";
          stateBadge.textContent = "Elevation Cancelled";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Cancelled";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = "none";
          rescanBtn.disabled = false;
        }
        if (rescanStatusBanner) {
          rescanStatusBanner.style.display = "none";
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }

        if (labelEl) {
          labelEl.textContent = "Elevation Cancelled";
          labelEl.style.color = "var(--status-warning)";
        }
        if (rateEl) rateEl.textContent = "Confidence: N/A";
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = "Administrator approval was cancelled. Click 'Start Monitoring' to approve the prompt or stream simulation packets.";
          statusEl.style.color = "var(--status-warning)";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = payload.message || "Live kernel packet capture requires starting the background service. Please accept the Windows UAC prompt.";
          }
        }
        break;

      case "error":
        isScanning = false;
        if (stateBadge) {
          stateBadge.className = "status-indicator-badge state-error";
          stateBadge.textContent = "Capture Error";
        }
        if (radarBox) radarBox.classList.remove("active");
        if (scannerConsole) scannerConsole.classList.remove("scanning-active");
        if (radarPacketBlips) radarPacketBlips.innerHTML = "";
        lastCapturedPacketCount = 0;
        if (resultChipState) resultChipState.textContent = "Error";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-rotate-right"></i> <span class="btn-text">Start Monitoring</span>';
        }
        if (rescanBtn) {
          rescanBtn.style.display = "none";
          rescanBtn.disabled = false;
        }
        if (rescanStatusBanner) {
          rescanStatusBanner.style.display = "none";
        }
        if (stopBtn) {
          stopBtn.style.display = "none";
          stopBtn.disabled = true;
        }

        if (labelEl) {
          labelEl.textContent = "Capture Error";
          labelEl.style.color = "var(--status-attack)";
        }
        if (rateEl) rateEl.textContent = "Confidence: N/A";
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "An error occurred during packet capture.";
          statusEl.style.color = "var(--status-attack)";
        }

        if (telemetryPkts) telemetryPkts.textContent = "0";
        if (telemetryDuration) telemetryDuration.textContent = "0.0 s";
        if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
        if (telemetryProtocol) telemetryProtocol.textContent = "N/A";

        if (resultIcon) {
          resultIcon.className = "fas fa-triangle-exclamation result-icon";
          resultIcon.style.color = "var(--status-attack)";
        }

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            let errDetail = payload.error || payload.message || "Driver or permissions error.";
            if (payload.log_tail && Array.isArray(payload.log_tail) && payload.log_tail.length > 0) {
              errDetail += `\n\n[Service Diagnostics]:\n${payload.log_tail.slice(-4).join("\n")}`;
            }
            diagnosticMsg.textContent = errDetail;
          }
        }
        break;
    }
  }

  // ============================================================================
  // 5. Scan Execution & Polling Lifecycle
  // ============================================================================
  async function startScan(opts = {}) {
    const forceRestart = Boolean(opts && opts.forceRestart);
    const switchSeq = (opts && opts.switchSeq !== undefined) ? opts.switchSeq : adapterSwitchSeq;

    if (isScanning && !forceRestart) return;

    activeScanId = null;
    console.log(`[DDoS-Guard] Initiating continuous monitoring session (seq: ${switchSeq}, forceRestart: ${forceRestart})...`);

    // Reset previous outputs immediately
    if (resultsConsole) {
      resultsConsole.classList.remove("state-benign", "state-attack");
    }
    if (resultIcon) {
      resultIcon.className = "fas fa-satellite-dish result-icon fa-spin";
      resultIcon.style.color = "var(--accent-cyan)";
    }
    if (labelEl) {
      labelEl.textContent = "Starting Monitoring...";
      labelEl.style.color = "var(--text-primary)";
    }
    if (rateEl) {
      rateEl.textContent = "Confidence: --%";
      rateEl.style.color = "var(--accent-cyan)";
    }
    if (confidenceBarFill) {
      confidenceBarFill.style.width = "15%";
      confidenceBarFill.style.background = "linear-gradient(90deg, #00e5ff, #3b82f6)";
    }

    // Initialize telemetry grid to fresh zero state
    if (telemetryGrid) telemetryGrid.style.display = "grid";
    if (telemetryPkts) telemetryPkts.textContent = "0";
    if (telemetryDuration) telemetryDuration.textContent = "0.0 s";
    if (telemetryThroughput) telemetryThroughput.textContent = "0.0 KB/s";
    if (telemetryProtocol) telemetryProtocol.textContent = "Npcap";

    if (diagnosticAlert) diagnosticAlert.style.display = "none";
    if (rescanStatusBanner) rescanStatusBanner.style.display = "none";

    setUIState("starting");
    scanStartTime = Date.now();

    try {
      // Guard against starting capture on a disappeared or removed adapter
      if (selectedAdapterDisappeared) {
        if (adapterDisappearedAlert) adapterDisappearedAlert.style.display = "flex";
        const missingMsg = "Cannot start live monitoring: The previously selected network adapter was disconnected or removed. Please select an active interface from the dropdown or click 'Auto Select'.";
        if (monitoringAdapterError && adapterErrorMessage) {
          monitoringAdapterError.style.display = "flex";
          adapterErrorMessage.textContent = missingMsg;
        }
        setUIState("error", { message: missingMsg });
        return;
      }

      // Validate selected adapter before dispatching start request
      const activeAd = (selectedAdapterMode === "auto") ? autoSelectedAdapter : currentNetworkAdapter;
      if (activeAd && (activeAd.status === "Disconnected" || activeAd.status === "Disabled")) {
        const offMsg = `Selected adapter '${activeAd.name}' is ${activeAd.status}. Live packet capture cannot start on a disconnected or disabled interface. Please connect the cable, enable the adapter, or choose another interface.`;
        if (monitoringAdapterError && adapterErrorMessage) {
          monitoringAdapterError.style.display = "flex";
          adapterErrorMessage.textContent = offMsg;
        }
        setUIState("error", { message: offMsg });
        return;
      }

      if (monitoringAdapterError) {
        monitoringAdapterError.style.display = "none";
      }

      // Sequence check before network dispatch to discard stale overlapping requests
      if (switchSeq !== adapterSwitchSeq) {
        console.log(`[DDoS-Guard] Pre-fetch sequence mismatch (seq ${switchSeq} < ${adapterSwitchSeq}). Aborting start.`);
        return;
      }

      const scanPayload = { continuous: true, min_packets: 3 };
      if (forceRestart) {
        scanPayload.force_restart = true;
      }
      if (selectedAdapterMode === "auto") {
        scanPayload.adapter = "auto";
      } else if (currentNetworkAdapter) {
        scanPayload.adapter = currentNetworkAdapter.name;
        scanPayload.interface_name = currentNetworkAdapter.name;
        scanPayload.interface_index = currentNetworkAdapter.index;
        if (currentNetworkAdapter.guid) {
          scanPayload.guid = currentNetworkAdapter.guid;
        }
        if (currentNetworkAdapter.network_name) {
          scanPayload.network_name = currentNetworkAdapter.network_name;
        }
      }

      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scanPayload)
      });

      // Sequence check after network dispatch to discard stale responses from fast switching
      if (switchSeq !== adapterSwitchSeq) {
        console.log(`[DDoS-Guard] Post-fetch sequence mismatch (seq ${switchSeq} < ${adapterSwitchSeq}). Discarding start response.`);
        try { fetch(`${API_BASE_URL}/scan-stop`, { method: "POST" }); } catch (e) {}
        return;
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        console.error("[DDoS-Guard] /api/scan returned HTTP error:", res.status, errData);
        if (monitoringAdapterError && adapterErrorMessage) {
          monitoringAdapterError.style.display = "flex";
          adapterErrorMessage.textContent = errData.message || errData.error || "Capture start failed.";
        }
        setUIState("error", errData);
        return;
      }

      const startData = await res.json().catch(() => ({}));
      activeScanId = startData.scan_id || null;
      console.log("[DDoS-Guard] Monitoring session registered:", activeScanId, startData);

      if (startData.service_state || startData.driver_status) {
        updateServiceBadge(startData.service_state, startData.driver_status);
      }
      if (startData.status === "uac_cancelled") {
        console.warn("[DDoS-Guard] Elevation was cancelled by user.");
        activeScanId = null;
        setUIState("uac_cancelled", startData);
        return;
      }
      if (startData.status === "error" || startData.error_type === "ADAPTER_OFFLINE" || startData.error_type === "InterfaceNotFound" || startData.error_type === "SERVICE_START_FAILED" || startData.error_type === "SERVICE_NOT_INSTALLED") {
        console.error("[DDoS-Guard] Service error on startup:", startData);
        activeScanId = null;
        if (monitoringAdapterError && adapterErrorMessage) {
          monitoringAdapterError.style.display = "flex";
          adapterErrorMessage.textContent = startData.message || startData.error || "Capture start failed on selected adapter.";
        }
        setUIState("error", startData);
        return;
      }

      // Begin polling status every 500ms continuously until Stop is clicked
      if (scanPollInterval) clearInterval(scanPollInterval);
      scanPollInterval = setInterval(pollScanStatus, 500);

    } catch (err) {
      console.error("[DDoS-Guard] Fetch failed:", err);
      activeScanId = null;
      setUIState("error", {
        message: `Cannot connect to API server: ${err.message}. Ensure 'python api.py' is running.`
      });
    }
  }

  async function pollScanStatus() {
    try {
      const res = await fetch(`${API_BASE_URL}/scan-status`);
      if (!res.ok) return;
      const data = await res.json();

      if (data.service_state || data.driver_status) {
        updateServiceBadge(data.service_state, data.driver_status);
      }

      // STRICT CHECK: Reject any poll data from a previous or mismatched scan session
      if (activeScanId && data.scan_id && data.scan_id !== activeScanId) {
        return;
      }

      const status = data.status;
      const isContinuous = data.continuous !== false;

      if (status === "starting" || status === "scanning") {
        setUIState("starting", data);
      } else if (status === "monitoring" || status === "prediction_available") {
        setUIState("monitoring", data);
        if (!isContinuous) {
          if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
          }
        }
      } else if (status === "no_traffic") {
        setUIState("no_traffic", data);
        if (!isContinuous) {
          if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
          }
        }
      } else if (status === "insufficient_traffic") {
        setUIState("insufficient_traffic", data);
        if (!isContinuous) {
          if (scanPollInterval) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
          }
        }
      } else if (status === "stopped") {
        if (scanPollInterval) {
          clearInterval(scanPollInterval);
          scanPollInterval = null;
        }
        setUIState("stopped", data);
      } else if (status === "error") {
        if (scanPollInterval) {
          clearInterval(scanPollInterval);
          scanPollInterval = null;
        }
        setUIState("error", data);
      }
    } catch (err) {
      console.warn("[DDoS-Guard] Polling network error:", err);
    }
  }

  async function stopScan(silent = false) {
    if (rescanBtn) {
      rescanBtn.style.display = "none";
      rescanBtn.disabled = false;
    }
    if (rescanStatusBanner) {
      rescanStatusBanner.style.display = "none";
    }
    if (scanPollInterval) {
      clearInterval(scanPollInterval);
      scanPollInterval = null;
    }
    if (scanTimeoutTimer) {
      clearTimeout(scanTimeoutTimer);
      scanTimeoutTimer = null;
    }
    activeScanId = null;
    isScanning = false;

    try {
      const res = await fetch(`${API_BASE_URL}/scan-stop`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!silent) {
        setUIState("stopped", data.status === "stopped" ? data : { message: "Monitoring session stopped." });
      }
    } catch (err) {
      if (!silent) {
        setUIState("stopped", { message: "Monitoring stopped." });
      }
    }
  }

  // ============================================================================
  // 5b. Non-Intrusive Session Rescan & Health Verification
  // ============================================================================
  async function rescanActiveSession() {
    if (isRescanning) return;
    isRescanning = true;

    if (rescanBtn) {
      rescanBtn.disabled = true;
      if (rescanIcon) rescanIcon.classList.add("fa-spin");
      if (rescanText) rescanText.textContent = "Checking...";
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      const res = await fetch(`${API_BASE_URL}/scan-rescan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      const data = await res.json();
      displayRescanResult(data);
    } catch (err) {
      console.warn("[DDoS-Guard] Rescan check error:", err);
      displayRescanResult({
        status: "error",
        health_state: "worker_failed",
        message: "Rescan request failed or timed out. Check backend connection.",
        recovery_action: "restart_monitoring"
      });
    } finally {
      isRescanning = false;
      if (rescanBtn) {
        if (rescanIcon) rescanIcon.classList.remove("fa-spin");
        if (rescanText) rescanText.textContent = "Rescan";
        rescanBtn.disabled = !isScanning;
      }
    }
  }

  function displayRescanResult(data) {
    if (!rescanStatusBanner) return;

    const state = data.health_state || (data.status === "error" ? "worker_failed" : "healthy_quiet");
    const message = data.message || "Rescan inspection completed.";

    rescanStatusBanner.className = "rescan-status-banner";
    rescanStatusBanner.classList.add(
      `state-${state === "healthy_active" ? "healthy" : state === "healthy_quiet" ? "quiet" : state === "adapter_unavailable" ? "warning" : "error"}`
    );

    if (rescanStatusIcon) {
      if (state === "healthy_active") {
        rescanStatusIcon.className = "fas fa-circle-check";
      } else if (state === "healthy_quiet") {
        rescanStatusIcon.className = "fas fa-circle-info";
      } else if (state === "adapter_unavailable") {
        rescanStatusIcon.className = "fas fa-triangle-exclamation";
      } else {
        rescanStatusIcon.className = "fas fa-circle-xmark";
      }
    }

    if (rescanStatusTitle) {
      if (state === "healthy_active") {
        rescanStatusTitle.textContent = "Capture Healthy & Active";
      } else if (state === "healthy_quiet") {
        rescanStatusTitle.textContent = "Capture Running (Quiet Network)";
      } else if (state === "adapter_unavailable") {
        rescanStatusTitle.textContent = "Selected Interface Unavailable";
      } else if (state === "worker_failed") {
        rescanStatusTitle.textContent = "Capture Worker Failure";
      } else {
        rescanStatusTitle.textContent = "Monitoring Status Inspection";
      }
    }

    if (rescanStatusDesc) {
      rescanStatusDesc.textContent = message;
    }

    // Recovery Actions UI Handling
    if (rescanRecoveryActions) {
      if (state === "adapter_unavailable") {
        rescanRecoveryActions.style.display = "flex";
        if (rescanRestartBtn) rescanRestartBtn.style.display = "inline-flex";
        if (rescanSelectAdapterBtn) rescanSelectAdapterBtn.style.display = "inline-flex";
      } else if (state === "worker_failed") {
        rescanRecoveryActions.style.display = "flex";
        if (rescanRestartBtn) rescanRestartBtn.style.display = "inline-flex";
        if (rescanSelectAdapterBtn) rescanSelectAdapterBtn.style.display = "none";
      } else {
        rescanRecoveryActions.style.display = "none";
      }
    }

    // Live update Card 2 IP text if provided by backend
    if (data.adapter && data.adapter.primary_ip && adapterIp) {
      adapterIp.textContent = data.adapter.primary_ip;
    }

    rescanStatusBanner.style.display = "flex";
  }

  // ============================================================================
  // 6. Threat Vectors Continuous Horizontal Marquee & Category Filtering
  // ============================================================================
  const originalCardsOrder = [...allCards];
  let visibleCards = [...allCards];
  let marqueeOffset = 0;
  let isMarqueePaused = false;
  let isMarqueeOffscreen = false;
  let marqueeRafId = null;
  let lastTimestamp = null;
  const MARQUEE_SPEED_PPS = 48; // Smooth reading speed: 48 pixels per second

  const prefersReducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  let isReducedMotion = prefersReducedMotionQuery.matches;

  function updateSliderCounter() {
    if (!sliderCurrentIndex || !sliderTotalCount) return;
    sliderTotalCount.textContent = visibleCards.length;
    sliderCurrentIndex.textContent = visibleCards.length;
  }

  function marqueeStep(timestamp) {
    if (!lastTimestamp) lastTimestamp = timestamp;
    const dt = Math.min((timestamp - lastTimestamp) / 1000, 0.1);
    lastTimestamp = timestamp;

    if (!isMarqueePaused && !isMarqueeOffscreen && !isReducedMotion && slider && cardContainer) {
      const activeCards = Array.from(cardContainer.children).filter(c => c.style.display !== "none");
      const sliderWidth = slider.clientWidth || 1100;
      let totalWidth = 0;
      activeCards.forEach(card => {
        totalWidth += (card.offsetWidth || 320) + 20; // 20px gap
      });

      if (totalWidth > sliderWidth + 30 && activeCards.length > 1) {
        marqueeOffset += MARQUEE_SPEED_PPS * dt;

        const firstVisible = activeCards[0];
        const cardPitch = (firstVisible.offsetWidth || 320) + 20;

        if (marqueeOffset >= cardPitch) {
          const firstHidden = cardContainer.querySelector('.attack-card-item[style*="display: none"]');
          if (firstHidden) {
            cardContainer.insertBefore(firstVisible, firstHidden);
          } else {
            cardContainer.appendChild(firstVisible);
          }
          marqueeOffset -= cardPitch;
        }

        cardContainer.style.transform = `translate3d(-${marqueeOffset.toFixed(2)}px, 0, 0)`;
      } else {
        cardContainer.style.transform = "translate3d(0, 0, 0)";
      }
    }

    marqueeRafId = requestAnimationFrame(marqueeStep);
  }

  function filterCards(category) {
    visibleCards = [];
    const hiddenCards = [];

    originalCardsOrder.forEach(card => {
      const cardCat = card.getAttribute("data-category");
      if (category === "all" || cardCat === category) {
        card.style.display = "flex";
        visibleCards.push(card);
      } else {
        card.style.display = "none";
        hiddenCards.push(card);
      }
    });

    // Re-populate container with visible cards first, then hidden cards
    visibleCards.forEach(card => cardContainer.appendChild(card));
    hiddenCards.forEach(card => cardContainer.appendChild(card));

    marqueeOffset = 0;
    if (cardContainer) {
      cardContainer.style.transform = "translate3d(0, 0, 0)";
    }

    updateSliderCounter();
    lastTimestamp = null;
  }

  // Filter tab events
  filterTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      filterTabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const category = tab.getAttribute("data-filter");
      filterCards(category);
    });
  });

  // Dedicated Marquee Pause / Resume Control
  const marqueeToggleBtn = document.getElementById("marqueeToggleBtn");
  const marqueeToggleIcon = document.getElementById("marqueeToggleIcon");
  const marqueeToggleText = document.getElementById("marqueeToggleText");
  const marqueePatrolBadge = document.getElementById("marqueePatrolBadge");

  if (marqueeToggleBtn && cardContainer) {
    marqueeToggleBtn.addEventListener("click", () => {
      isMarqueePaused = !isMarqueePaused;
      cardContainer.classList.toggle("marquee-paused", isMarqueePaused);

      if (marqueeToggleIcon) {
        marqueeToggleIcon.className = isMarqueePaused ? "fas fa-play" : "fas fa-pause";
      }
      if (marqueeToggleText) {
        marqueeToggleText.textContent = isMarqueePaused ? "Resume" : "Pause";
      }
      marqueeToggleBtn.setAttribute("aria-label", isMarqueePaused ? "Resume continuous marquee animation" : "Pause continuous marquee animation");

      if (marqueePatrolBadge) {
        marqueePatrolBadge.classList.toggle("paused", isMarqueePaused);
        const badgeText = marqueePatrolBadge.querySelector(".badge-text");
        if (badgeText) {
          badgeText.textContent = isMarqueePaused ? "Patrol Paused" : "Auto-Patrol Active";
        }
      }

      if (!isMarqueePaused) {
        lastTimestamp = performance.now();
      }
    });
  }

  // Slider arrows (smooth step without pausing if invoked)
  if (sliderNextBtn) {
    sliderNextBtn.addEventListener("click", () => {
      marqueeOffset += 120;
    });
  }

  if (sliderPrevBtn) {
    sliderPrevBtn.addEventListener("click", () => {
      marqueeOffset = Math.max(0, marqueeOffset - 120);
    });
  }

  // IntersectionObserver to avoid background CPU load when offscreen
  if ("IntersectionObserver" in window && slider) {
    const marqueeObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        isMarqueeOffscreen = !entry.isIntersecting;
        if (entry.isIntersecting) {
          lastTimestamp = performance.now();
        }
      });
    }, { threshold: 0.05 });
    marqueeObserver.observe(slider);
  }

  // Accessibility: handle reduced motion
  prefersReducedMotionQuery.addEventListener("change", (e) => {
    isReducedMotion = e.matches;
    if (isReducedMotion) {
      if (cardContainer) cardContainer.style.transform = "none";
      if (marqueePatrolBadge) {
        marqueePatrolBadge.classList.add("paused");
        const badgeText = marqueePatrolBadge.querySelector(".badge-text");
        if (badgeText) badgeText.textContent = "Motion Reduced";
      }
      if (marqueeToggleText) marqueeToggleText.textContent = "Resume";
      if (marqueeToggleIcon) marqueeToggleIcon.className = "fas fa-play";
    } else {
      if (!isMarqueePaused) {
        lastTimestamp = performance.now();
      }
    }
  });

  // Start continuous marquee RAF loop
  if (!isReducedMotion) {
    marqueeRafId = requestAnimationFrame(marqueeStep);
  }
  updateSliderCounter();

  // ============================================================================
  // 7. General Navigation, Collapsible Sidebar & Dedicated View Coordinator
  // ============================================================================
  const sidebarToggleBtn = document.getElementById("sidebarToggleBtn");
  const navbarSidebarToggleBtn = document.getElementById("navbarSidebarToggleBtn");
  const mobileMenuBtn = document.getElementById("mobileMenuBtn");
  const sidebarBackdrop = document.getElementById("sidebarBackdrop");
  const sidebarNavItems = document.querySelectorAll(".sidebar-nav-item");
  const topNavLinks = document.querySelectorAll(".top-nav-link");

  const dedicatedToolBar = document.getElementById("dedicatedToolBar");
  const dedicatedToolTitle = document.getElementById("dedicatedToolTitle");
  const dedicatedViewToggleBtn = document.getElementById("dedicatedViewToggleBtn");
  const breadcrumbHomeLink = document.getElementById("breadcrumbHomeLink");
  const launchDedicatedMonitorBtn = document.getElementById("launchDedicatedMonitorBtn");
  const launchDedicatedPortScannerBtn = document.getElementById("launchDedicatedPortScannerBtn");

  const heroSection = document.getElementById("overview");
  const monitorSection = document.getElementById("check-connection");
  const portScannerSection = document.getElementById("port-scanner");
  const ndLandingSection = document.getElementById("network-discovery-section");
  const threatSection = document.getElementById("threat-intelligence");
  const preventionSection = document.getElementById("prevention");
  const teamSection = document.getElementById("team");
  const footerEl = document.querySelector(".site-footer");

  const sidebarMobileCloseBtn = document.getElementById("sidebarMobileCloseBtn");

  // Restore Sidebar Collapsed State from localStorage
  if (localStorage.getItem("nss_sidebar_collapsed") === "true") {
    document.body.classList.add("sidebar-collapsed");
  }

  // Close Mobile Drawer Helper
  function closeMobileSidebar() {
    document.body.classList.remove("mobile-sidebar-open");
    if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");
    if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", "false");
  }

  // Toggle Sidebar Function (Responsive for Desktop Collapse & Mobile Drawer)
  function handleSidebarToggle() {
    if (window.innerWidth < 992) {
      const isOpen = document.body.classList.toggle("mobile-sidebar-open");
      if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
      if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    } else {
      const isCollapsed = document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem("nss_sidebar_collapsed", isCollapsed ? "true" : "false");
      if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", isCollapsed ? "false" : "true");
    }
  }

  if (sidebarToggleBtn) {
    sidebarToggleBtn.addEventListener("click", () => {
      const isCollapsed = document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem("nss_sidebar_collapsed", isCollapsed ? "true" : "false");
    });
  }

  if (navbarSidebarToggleBtn) {
    navbarSidebarToggleBtn.addEventListener("click", handleSidebarToggle);
  }

  // Mobile Drawer Toggle (Fallback)
  if (mobileMenuBtn) {
    mobileMenuBtn.addEventListener("click", () => {
      const isOpen = document.body.classList.toggle("mobile-sidebar-open");
      mobileMenuBtn.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
  }

  // Mobile Backdrop Click
  if (sidebarBackdrop) {
    sidebarBackdrop.addEventListener("click", closeMobileSidebar);
  }

  // Mobile Drawer Close Button
  if (sidebarMobileCloseBtn) {
    sidebarMobileCloseBtn.addEventListener("click", closeMobileSidebar);
  }

  // Dismiss mobile drawer on Escape key
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.body.classList.contains("mobile-sidebar-open")) {
      closeMobileSidebar();
    }
  });

  // Ensure drawer closes when resizing past mobile breakpoint
  window.addEventListener("resize", () => {
    if (window.innerWidth >= 992 && document.body.classList.contains("mobile-sidebar-open")) {
      closeMobileSidebar();
    }
  });

  // Update Active Link in Sidebar
  function setSidebarActive(navName) {
    sidebarNavItems.forEach(item => {
      if (item.getAttribute("data-nav") === navName) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });
  }

  // Update Active Link in Global Top Navbar
  function setTopNavActive(navName) {
    topNavLinks.forEach(link => {
      if (link.getAttribute("data-top-nav") === navName) {
        link.classList.add("active");
      } else {
        link.classList.remove("active");
      }
    });
  }

  // ============================================================================
  // Complete Global Dark / Light Theme System
  // ============================================================================
  function initTheme() {
    const themeToggleBtn = document.getElementById("themeToggleBtn");
    const themeToggleIcon = document.getElementById("themeToggleIcon");
    const themeToggleText = document.getElementById("themeToggleText");
    const metaTheme = document.querySelector('meta[name="theme-color"]');

    function applyTheme(theme, animate = false) {
      if (animate) {
        document.body.classList.add("theme-transitioning");
      }
      document.documentElement.setAttribute("data-theme", theme);
      const isDark = theme === "dark";

      if (themeToggleIcon) {
        themeToggleIcon.className = isDark ? "fas fa-sun" : "fas fa-moon";
      }
      if (themeToggleText) {
        themeToggleText.textContent = isDark ? "Light Mode" : "Dark Mode";
      }
      if (themeToggleBtn) {
        const titleStr = isDark ? "Switch to Light Mode" : "Switch to Dark Mode";
        themeToggleBtn.setAttribute("title", titleStr);
        themeToggleBtn.setAttribute("aria-label", titleStr);
      }
      if (metaTheme) {
        metaTheme.setAttribute("content", isDark ? "#101411" : "#F7F5EF");
      }

      if (animate) {
        window.setTimeout(() => {
          document.body.classList.remove("theme-transitioning");
        }, 260);
      }
    }

    const savedTheme = localStorage.getItem("nss_theme");
    const systemDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const initialTheme = savedTheme || (systemDark ? "dark" : "light");
    applyTheme(initialTheme, false);

    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        localStorage.setItem("nss_theme", next);
        applyTheme(next, true);
      });
    }

    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
        if (!localStorage.getItem("nss_theme")) {
          applyTheme(e.matches ? "dark" : "light", true);
        }
      });
    }
  }

  initTheme();

  // Get Requested View from URL or Hash
  function getQueryView() {
    const params = new URLSearchParams(window.location.search);
    const view = params.get("view");
    if (view === "monitoring" || view === "live-monitoring") return "monitoring";
    if (view === "port-scanner" || view === "scanner") return "port-scanner";

    const hash = window.location.hash;
    if (hash === "#live-monitoring" || hash === "#monitoring") return "monitoring";
    if (hash === "#port-scanner-page") return "port-scanner";

    return "landing";
  }

  // Switch View: Dedicated Workspace vs Full Landing Page
  function switchView(targetView, updateHistory = true) {
    // Close mobile drawer on navigation
    document.body.classList.remove("mobile-sidebar-open");
    if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", "false");
    if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");

    if (targetView === "monitoring") {
      document.body.classList.add("dedicated-mode-monitoring");
      document.body.classList.remove("dedicated-mode-port-scanner", "home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Live Network Monitoring & Intrusion Detection";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "block";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("monitoring");
      setTopNavActive("monitoring");
      window.scrollTo({ top: 0, behavior: "smooth" });
      discoverInterfaces(true);

      if (updateHistory) {
        history.pushState({ view: "monitoring" }, "", "?view=monitoring");
      }
    } else if (targetView === "port-scanner") {
      document.body.classList.add("dedicated-mode-port-scanner");
      document.body.classList.remove("dedicated-mode-monitoring", "home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Port & Network Reconnaissance Scanner";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "block";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("port-scanner");
      setTopNavActive("port-scanner");
      window.scrollTo({ top: 0, behavior: "smooth" });

      if (updateHistory) {
        history.pushState({ view: "port-scanner" }, "", "?view=port-scanner");
      }
    } else {
      // Home Page Mode: Live Monitoring and Port Scanner are NEVER displayed on Home!
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner");
      document.body.classList.add("home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "none";

      if (heroSection) heroSection.style.display = "block";
      if (monitorSection) monitorSection.style.display = "none"; // NEVER on Home
      if (portScannerSection) portScannerSection.style.display = "none"; // NEVER on Home
      if (ndLandingSection) ndLandingSection.style.display = "block";
      if (threatSection) threatSection.style.display = "block";
      if (preventionSection) preventionSection.style.display = "block";
      if (teamSection) teamSection.style.display = "block";
      if (footerEl) footerEl.style.display = "block";

      setSidebarActive("home");
      setTopNavActive("home");

      if (updateHistory && window.location.search) {
        history.pushState({ view: "landing" }, "", window.location.pathname + (window.location.hash || ""));
      }
    }
  }

  // Intercept Navigation Link Clicks in Global Top Navbar
  topNavLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      const navTarget = link.getAttribute("data-top-nav");
      if (navTarget === "monitoring") {
        e.preventDefault();
        switchView("monitoring");
      } else if (navTarget === "port-scanner") {
        e.preventDefault();
        switchView("port-scanner");
      } else if (navTarget === "home") {
        if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner")) {
          e.preventDefault();
          switchView("landing");
          window.scrollTo({ top: 0, behavior: "smooth" });
        } else {
          document.body.classList.remove("mobile-sidebar-open");
          if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");
          setSidebarActive("home");
          setTopNavActive("home");
        }
      }
    });
  });

  // Intercept Navigation Link Clicks
  sidebarNavItems.forEach(item => {
    item.addEventListener("click", (e) => {
      closeMobileSidebar();
      const navTarget = item.getAttribute("data-nav");
      if (navTarget === "monitoring") {
        e.preventDefault();
        switchView("monitoring");
      } else if (navTarget === "port-scanner") {
        e.preventDefault();
        switchView("port-scanner");
      } else if (navTarget === "home") {
        if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner")) {
          e.preventDefault();
          switchView("landing");
          window.scrollTo({ top: 0, behavior: "smooth" });
        } else {
          closeMobileSidebar();
          setSidebarActive("home");
        }
      }
    });
  });

  const sidebarBrandLink = document.getElementById("sidebarBrandLink");
  if (sidebarBrandLink) {
    sidebarBrandLink.addEventListener("click", closeMobileSidebar);
  }

  if (breadcrumbHomeLink) {
    breadcrumbHomeLink.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("landing");
    });
  }

  if (dedicatedViewToggleBtn) {
    dedicatedViewToggleBtn.addEventListener("click", () => {
      switchView("landing");
    });
  }

  const heroStartScanBtn = document.getElementById("heroStartScanBtn");
  const heroPortScanBtn = document.getElementById("heroPortScanBtn");

  if (heroStartScanBtn) {
    heroStartScanBtn.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("monitoring");
    });
  }

  if (heroPortScanBtn) {
    heroPortScanBtn.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("port-scanner");
    });
  }

  if (launchDedicatedMonitorBtn) {
    launchDedicatedMonitorBtn.addEventListener("click", () => {
      switchView("monitoring");
    });
  }

  if (launchDedicatedPortScannerBtn) {
    launchDedicatedPortScannerBtn.addEventListener("click", () => {
      switchView("port-scanner");
    });
  }

  // Listen to popstate (browser back/forward)
  window.addEventListener("popstate", () => {
    switchView(getQueryView(), false);
  });

  // Initialize view from URL
  switchView(getQueryView(), false);

  // Back To Top Button
  if (backToTopBtn) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 350) {
        backToTopBtn.classList.add("visible");
      } else {
        backToTopBtn.classList.remove("visible");
      }
    });

    backToTopBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  // ScrollSpy for Active Navigation Links on Landing Page
  const navSections = document.querySelectorAll("section[id]");

  function highlightNavOnScroll() {
    if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner")) {
      return;
    }
    setSidebarActive("home");
  }

  window.addEventListener("scroll", highlightNavOnScroll, { passive: true });

  // ============================================================================
  // 8. Event Listeners for DDoS Live Scanning
  // ============================================================================
  if (checkBtn) {
    checkBtn.addEventListener("click", () => {
      userManuallyStopped = false;
      startScan();
    });
  }

  if (rescanBtn) {
    rescanBtn.addEventListener("click", () => {
      rescanActiveSession();
    });
  }

  if (rescanDismissBtn) {
    rescanDismissBtn.addEventListener("click", () => {
      if (rescanStatusBanner) rescanStatusBanner.style.display = "none";
    });
  }

  if (rescanRestartBtn) {
    rescanRestartBtn.addEventListener("click", async () => {
      userManuallyStopped = false;
      if (rescanStatusBanner) rescanStatusBanner.style.display = "none";
      await stopScan(true);
      setTimeout(() => {
        startScan({ forceRestart: true });
      }, 400);
    });
  }

  if (rescanSelectAdapterBtn) {
    rescanSelectAdapterBtn.addEventListener("click", async () => {
      userManuallyStopped = false;
      if (rescanStatusBanner) rescanStatusBanner.style.display = "none";
      await stopScan(false);
      const hub = document.getElementById("adapterSelectionHub");
      if (hub) {
        hub.scrollIntoView({ behavior: "smooth", block: "center" });
        hub.classList.add("focus-pulse");
        setTimeout(() => hub.classList.remove("focus-pulse"), 2500);
      }
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener("click", () => {
      userManuallyStopped = true;
      stopScan();
    });
  }

  // ============================================================================
  // 9. Independent Port & Network Scanner Module (Decoupled from DDoS Core)
  // ============================================================================
  const PortScannerUI = (() => {
    let portScanPollTimer = null;
    let isPortScanning = false;
    let currentMode = "localhost";
    let currentPreset = "top20";
    let autoDetectedSubnet = "";
    let lastScanData = null;
    let activeFilter = "open"; // 'open' | 'all'
    let searchQuery = "";

    // DOM Elements
    const tabLocalhost = document.getElementById("psTabLocalhost");
    const tabTargetIp = document.getElementById("psTabTargetIp");
    const tabNetwork = document.getElementById("psTabNetwork");
    const modeTabs = [tabLocalhost, tabTargetIp, tabNetwork];

    const targetInput = document.getElementById("psTargetInput");
    const targetHint = document.getElementById("psTargetHint");
    const autoSubnetBtn = document.getElementById("psAutoSubnetBtn");
    const authWrap = document.getElementById("psAuthWrap");
    const authCheck = document.getElementById("psAuthCheck");

    const presetBtns = Array.from(document.querySelectorAll(".ps-preset-btn"));
    const customPortWrap = document.getElementById("psCustomPortWrap");
    const customPortInput = document.getElementById("psCustomPortInput");

    const timeoutSelect = document.getElementById("psTimeoutSelect");
    const concurrencySelect = document.getElementById("psConcurrencySelect");

    const startBtn = document.getElementById("psStartBtn");
    const rescanBtn = document.getElementById("psRescanBtn");
    const stopBtn = document.getElementById("psStopBtn");
    const exportGroup = document.getElementById("psExportGroup");
    const exportJsonBtn = document.getElementById("psExportJsonBtn");
    const exportCsvBtn = document.getElementById("psExportCsvBtn");

    const stateBadge = document.getElementById("psStateBadge");
    const localIpBadge = document.getElementById("psLocalIpBadge");
    const resultsTimestamp = document.getElementById("psResultsTimestamp");
    const timestampText = document.getElementById("psTimestampText");
    const progressBox = document.getElementById("psProgressBox");
    const progressBar = document.getElementById("psProgressBar");
    const progressStatusText = document.getElementById("psProgressStatusText");
    const progressPct = document.getElementById("psProgressPct");

    const kpiGrid = document.getElementById("psKpiGrid");
    const kpiHosts = document.getElementById("psKpiHosts");
    const kpiScanned = document.getElementById("psKpiScanned");
    const kpiOpen = document.getElementById("psKpiOpen");
    const kpiDuration = document.getElementById("psKpiDuration");

    const errorBanner = document.getElementById("psErrorBanner");
    const errorText = document.getElementById("psErrorText");

    const resultsWrapper = document.getElementById("psResultsWrapper");
    const resultsContent = document.getElementById("psResultsContent");
    const filterPills = Array.from(document.querySelectorAll(".ps-filter-pill"));
    const filterOpenCount = document.getElementById("psFilterOpenCount");
    const filterAllCount = document.getElementById("psFilterAllCount");
    const searchInput = document.getElementById("psSearchInput");

    async function loadNetworkInfo() {
      try {
        const res = await fetch("/api/port-scan/network-info");
        if (!res.ok) return;
        const data = await res.json();
        if (data.status === "success") {
          autoDetectedSubnet = data.suggested_subnet || "";
          if (localIpBadge) {
            const isConn = data.is_connected && data.local_ip && !data.local_ip.startsWith("127.");
            const ipLabel = isConn ? data.local_ip : (data.local_ip || "Offline");
            const typeStr = (data.adapter_type && data.adapter_type !== 'None' && data.adapter_type !== 'Other') ? ` (${data.adapter_type})` : '';
            localIpBadge.innerHTML = `<i class="fas fa-circle-dot"></i> Local IP: ${ipLabel}${typeStr}`;
          }
        }
      } catch (e) {
        console.warn("Could not load network info for port scanner:", e);
      }
    }

    function switchMode(mode) {
      currentMode = mode;
      hideError();

      modeTabs.forEach(tab => {
        if (!tab) return;
        const isActive = tab.getAttribute("data-mode") === mode;
        tab.classList.toggle("active", isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
      });

      if (!targetInput) return;

      if (mode === "localhost") {
        targetInput.value = "127.0.0.1";
        targetInput.readOnly = true;
        targetInput.placeholder = "127.0.0.1";
        if (targetHint) targetHint.textContent = "Loopback interface strictly locked for local inspection.";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "none";
        if (authWrap) authWrap.style.display = "none";
      } else if (mode === "target_ip") {
        targetInput.value = "";
        targetInput.readOnly = false;
        targetInput.placeholder = "e.g. 192.168.1.15 or router.local";
        if (targetHint) targetHint.textContent = "Enter target IPv4 address or resolvable hostname.";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "none";
        if (authWrap) authWrap.style.display = "none";
        targetInput.focus();
      } else if (mode === "network") {
        targetInput.value = autoDetectedSubnet || "";
        targetInput.readOnly = false;
        targetInput.placeholder = "e.g. 192.168.1.0/24";
        if (targetHint) targetHint.textContent = "Enter private CIDR subnet (maximum size /24, up to 256 hosts).";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "inline-flex";
        if (authWrap) authWrap.style.display = "block";
      }
    }

    function switchPreset(preset) {
      currentPreset = preset;
      presetBtns.forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-preset") === preset);
      });
      if (customPortWrap) {
        customPortWrap.style.display = (preset === "custom") ? "block" : "none";
        if (preset === "custom" && customPortInput) customPortInput.focus();
      }
    }

    function showError(msg) {
      if (errorBanner && errorText) {
        errorText.textContent = msg;
        errorBanner.style.display = "flex";
      }
    }

    function hideError() {
      if (errorBanner) errorBanner.style.display = "none";
    }

    function setBadge(state, label) {
      if (!stateBadge) return;
      stateBadge.className = `ps-status-pill ps-state-${state}`;
      stateBadge.textContent = label;
    }

    async function startScan() {
      if (isPortScanning) return;
      hideError();

      const target = (targetInput ? targetInput.value : "").trim();
      if (!target) {
        if (currentMode === "network") {
          showError("No active local subnet detected. Please enter a target IPv4 subnet (e.g. 192.168.1.0/24) manually.");
        } else {
          showError("Target address is required.");
        }
        if (targetInput) targetInput.focus();
        return;
      }

      if (currentMode === "network") {
        if (authCheck && !authCheck.checked) {
          showError("Please confirm authorization to perform discovery on this target network.");
          return;
        }
      }

      let customPorts = null;
      if (currentPreset === "custom") {
        customPorts = (customPortInput ? customPortInput.value : "").trim();
        if (!customPorts) {
          showError("Please enter one or more custom ports (e.g. 80, 443, 8080).");
          if (customPortInput) customPortInput.focus();
          return;
        }
      }

      const timeout = parseFloat(timeoutSelect ? timeoutSelect.value : 0.5) || 0.5;
      const concurrency = parseInt(concurrencySelect ? concurrencySelect.value : 150, 10) || 150;

      // Update UI to scanning state
      isPortScanning = true;
      setBadge("scanning", "Scanning...");
      if (startBtn) {
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Scanning...</span>';
      }
      if (rescanBtn) {
        rescanBtn.disabled = true;
        rescanBtn.style.display = "none";
      }
      if (stopBtn) stopBtn.style.display = "inline-flex";
      if (progressBox) {
        progressBox.style.display = "block";
        progressBox.classList.add("ps-scanning");
      }
      if (progressBar) {
        progressBar.style.width = "0%";
        progressBar.classList.add("scanning");
      }
      if (progressPct) progressPct.textContent = "0%";
      if (progressStatusText) progressStatusText.textContent = `Connecting to ${target}...`;

      if (kpiGrid) kpiGrid.style.display = "grid";
      if (kpiHosts) kpiHosts.textContent = "0";
      if (kpiScanned) kpiScanned.textContent = "0";
      if (kpiOpen) kpiOpen.textContent = "0";
      if (kpiDuration) kpiDuration.textContent = "0.0s";

      if (exportGroup) exportGroup.style.display = "none";

      try {
        const res = await fetch("/api/port-scan/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scan_type: currentMode,
            target: target,
            ports_mode: currentPreset,
            custom_ports: customPorts,
            timeout: timeout,
            concurrency: concurrency
          })
        });

        const data = await res.json();
        if (!res.ok || data.status === "error") {
          throw new Error(data.message || "Failed to start port scan.");
        }

        // Start polling status
        if (portScanPollTimer) clearInterval(portScanPollTimer);
        portScanPollTimer = setInterval(pollScanStatus, 350);

      } catch (err) {
        resetUI();
        setBadge("error", "Error");
        showError(err.message || "Connection error starting port scan.");
      }
    }

    async function stopScan() {
      try {
        await fetch("/api/port-scan/stop", { method: "POST" });
      } catch (e) {
        // ignore
      }
      if (portScanPollTimer) {
        clearInterval(portScanPollTimer);
        portScanPollTimer = null;
      }
      resetUI();
      setBadge("stopped", "Stopped");
      if (progressStatusText) progressStatusText.textContent = "Scan cancelled by user.";
    }

    async function pollScanStatus() {
      try {
        const res = await fetch("/api/port-scan/status");
        if (!res.ok) return;
        const data = await res.json();
        lastScanData = data;

        const status = data.status;
        const pct = Math.min(Math.max(data.progress_pct || 0, 0), 100);

        if (progressBar) progressBar.style.width = `${pct}%`;
        if (progressPct) progressPct.textContent = `${pct.toFixed(0)}%`;
        if (progressStatusText && data.message) progressStatusText.textContent = data.message;

        if (kpiHosts) updateTelemetryCounter(kpiHosts, data.active_hosts_count || 0);
        if (kpiScanned) updateTelemetryCounter(kpiScanned, data.scanned_ports || 0);
        if (kpiOpen) updateTelemetryCounter(kpiOpen, data.open_ports_count || 0);
        if (kpiDuration) kpiDuration.textContent = `${(data.duration_s || 0).toFixed(1)}s`;

        // Render live interim results if any open ports found
        if (data.results && data.results.length > 0) {
          renderResults(data.results);
        }

        if (status === "completed" || status === "stopped" || status === "error") {
          if (portScanPollTimer) {
            clearInterval(portScanPollTimer);
            portScanPollTimer = null;
          }
          resetUI();

          if (status === "completed") {
            setBadge("completed", "Completed");
            if (progressBar) progressBar.style.width = "100%";
            if (progressPct) progressPct.textContent = "100%";
            if (resultsTimestamp && timestampText) {
              const timeStr = data.completed_at_str || new Date().toLocaleTimeString();
              timestampText.textContent = `Last scanned at ${timeStr}`;
              resultsTimestamp.style.display = "inline-flex";
            }
            if (rescanBtn) rescanBtn.style.display = "inline-flex";
          } else if (status === "stopped") {
            setBadge("stopped", "Stopped");
            if (rescanBtn) rescanBtn.style.display = "inline-flex";
          } else if (status === "error") {
            setBadge("error", "Error");
            showError(data.error || data.message || "An error occurred during port scan.");
          }

          if (data.results && data.results.length > 0) {
            renderResults(data.results);
            if (exportGroup) exportGroup.style.display = "inline-flex";
          }
        }
      } catch (e) {
        console.warn("Port scanner poll error:", e);
      }
    }

    function resetUI() {
      isPortScanning = false;
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play"></i> <span>Start Port Scan</span>';
      }
      if (rescanBtn) {
        rescanBtn.disabled = false;
      }
      if (stopBtn) stopBtn.style.display = "none";
      if (progressBox) progressBox.classList.remove("ps-scanning");
      if (progressBar) progressBar.classList.remove("scanning");
    }

    function renderResults(hosts) {
      if (!resultsWrapper || !resultsContent) return;
      resultsWrapper.style.display = "block";

      // Compute total counts
      let totalOpen = 0;
      let totalAll = 0;
      hosts.forEach(h => {
        totalOpen += (h.open_ports || []).length;
        totalAll += (h.all_ports || []).length;
      });

      if (filterOpenCount) filterOpenCount.textContent = totalOpen;
      if (filterAllCount) filterAllCount.textContent = totalAll;

      const q = searchQuery.toLowerCase().trim();

      // Render based on scan mode
      if (currentMode === "network") {
        // Multi-host accordion cards
        let html = "";
        hosts.forEach((h, idx) => {
          const portsList = (activeFilter === "open") ? (h.open_ports || []) : (h.all_ports || []);
          const filteredPorts = portsList.filter(p => {
            if (!q) return true;
            return String(p.port).includes(q) || (p.service || "").toLowerCase().includes(q) || (p.banner || "").toLowerCase().includes(q);
          });

          const isOpenByDefault = idx === 0 || (h.open_ports && h.open_ports.length > 0);
          const openBadgeClass = (h.open_ports_count > 0) ? "ps-state-tag state-open" : "ps-state-tag state-closed";

          html += `
            <div class="ps-host-card ${isOpenByDefault ? "open" : ""}">
              <div class="ps-host-header" onclick="this.parentElement.classList.toggle('open')">
                <div class="ps-host-title">
                  <span class="ps-host-ip"><i class="fas fa-server"></i> ${escapeHtml(h.host)}</span>
                  ${h.hostname && h.hostname !== h.host ? `<span class="ps-host-name">(${escapeHtml(h.hostname)})</span>` : ""}
                </div>
                <div class="ps-host-meta">
                  <span class="${openBadgeClass}">
                    <i class="fas ${h.open_ports_count > 0 ? "fa-circle-check" : "fa-circle-xmark"}"></i>
                    ${h.open_ports_count} Open
                  </span>
                  <i class="fas fa-chevron-down ps-chevron"></i>
                </div>
              </div>
              <div class="ps-host-body">
                ${renderPortsTable(filteredPorts)}
              </div>
            </div>
          `;
        });

        if (!html) {
          html = `<div class="ps-empty-state"><i class="fas fa-search"></i>No hosts or ports match the current filter.</div>`;
        }
        resultsContent.innerHTML = html;

      } else {
        // Single host table (Localhost or Target IP)
        const host = hosts[0] || {};
        const portsList = (activeFilter === "open") ? (host.open_ports || []) : (host.all_ports || []);
        const filteredPorts = portsList.filter(p => {
          if (!q) return true;
          return String(p.port).includes(q) || (p.service || "").toLowerCase().includes(q) || (p.banner || "").toLowerCase().includes(q);
        });

        resultsContent.innerHTML = `
          <div class="ps-table-card">
            ${renderPortsTable(filteredPorts)}
          </div>
        `;
      }
    }

    function renderPortsTable(ports) {
      if (!ports || ports.length === 0) {
        return `<div class="ps-empty-state"><i class="fas fa-shield-halved"></i>No open ports detected in this category.</div>`;
      }

      let rows = "";
      ports.forEach((p, idx) => {
        const stateClass = p.state === "open" ? "state-open" : (p.state === "filtered" ? "state-filtered" : (p.state === "error" ? "state-error" : "state-closed"));
        const stateIcon = p.state === "open" ? "fa-circle-check" : (p.state === "filtered" ? "fa-circle-exclamation" : (p.state === "error" ? "fa-triangle-exclamation" : "fa-circle-xmark"));
        const latencyText = p.latency_ms !== null ? `${p.latency_ms} ms` : "--";
        const bannerHtml = p.banner ? `<code class="ps-banner-code" title="${escapeHtml(p.banner)}">${escapeHtml(p.banner)}</code>` : '<span class="text-muted">--</span>';

        rows += `
          <tr style="animation-delay: ${Math.min(idx * 28, 400)}ms">
            <td class="ps-port-num">${p.port}</td>
            <td><span class="ps-proto-tag">${p.protocol || "TCP"}</span></td>
            <td>
              <span class="ps-state-tag ${stateClass}">
                <i class="fas ${stateIcon}"></i> ${(p.state || "closed").toUpperCase()}
              </span>
            </td>
            <td><strong>${escapeHtml(p.service || "Unknown")}</strong></td>
            <td>${bannerHtml}</td>
            <td style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-muted);">${latencyText}</td>
          </tr>
        `;
      });

      return `
        <div class="ps-table-responsive-wrap">
          <table class="ps-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Banner / Info</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      `;
    }

    function escapeHtml(str) {
      if (!str) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function exportResults(format) {
      if (!lastScanData || !lastScanData.results || lastScanData.results.length === 0) return;

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `port_scan_${lastScanData.scan_type || "results"}_${timestamp}.${format}`;

      if (format === "json") {
        const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: "application/json" });
        downloadBlob(blob, filename);
      } else if (format === "csv") {
        let csv = "Host,Hostname,Port,Protocol,State,Service,Banner,LatencyMs\n";
        lastScanData.results.forEach(h => {
          const ports = h.all_ports && h.all_ports.length > 0 ? h.all_ports : (h.open_ports || []);
          ports.forEach(p => {
            const cleanBanner = (p.banner || "").replace(/"/g, '""');
            csv += `"${h.host}","${h.hostname || ""}","${p.port}","${p.protocol || "TCP"}","${p.state}","${p.service || ""}","${cleanBanner}","${p.latency_ms || ""}"\n`;
          });
        });
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        downloadBlob(blob, filename);
      }
    }

    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function init() {
      loadNetworkInfo();

      // Mode tabs
      modeTabs.forEach(tab => {
        if (!tab) return;
        tab.addEventListener("click", () => {
          if (isPortScanning) return;
          switchMode(tab.getAttribute("data-mode"));
        });
      });

      // Auto Subnet Button
      if (autoSubnetBtn) {
        autoSubnetBtn.addEventListener("click", () => {
          if (targetInput && autoDetectedSubnet) {
            targetInput.value = autoDetectedSubnet;
          } else {
            showError("No active local subnet detected on the system. Please enter a target subnet manually.");
          }
        });
      }

      // Presets
      presetBtns.forEach(btn => {
        btn.addEventListener("click", () => {
          if (isPortScanning) return;
          switchPreset(btn.getAttribute("data-preset"));
        });
      });

      // Start / Rescan / Stop
      if (startBtn) startBtn.addEventListener("click", () => startScan());
      if (rescanBtn) rescanBtn.addEventListener("click", () => startScan());
      if (stopBtn) stopBtn.addEventListener("click", stopScan);

      // Export buttons
      if (exportJsonBtn) exportJsonBtn.addEventListener("click", () => exportResults("json"));
      if (exportCsvBtn) exportCsvBtn.addEventListener("click", () => exportResults("csv"));

      // Filter tabs
      filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
          filterPills.forEach(p => p.classList.remove("active"));
          pill.classList.add("active");
          activeFilter = pill.getAttribute("data-filter") || "open";
          if (lastScanData && lastScanData.results) {
            renderResults(lastScanData.results);
          }
        });
      });

      // Search input
      if (searchInput) {
        searchInput.addEventListener("input", (e) => {
          searchQuery = e.target.value;
          if (lastScanData && lastScanData.results) {
            renderResults(lastScanData.results);
          }
        });
      }

      // Check URL parameters (e.g. from Network Discovery card Scan Ports link)
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const targetParam = urlParams.get("target");
        if (targetParam) {
          switchMode("target_ip");
          if (targetInput) targetInput.value = targetParam;
          const scannerSec = document.getElementById("portScannerSection") || document.querySelector(".port-scanner-card");
          if (scannerSec) {
            setTimeout(() => scannerSec.scrollIntoView({ behavior: "smooth" }), 250);
          }
        }
      } catch (e) {
        // ignore
      }
    }

    return {
      init,
      startScan,
      stopScan
    };
  })();

  // ============================================================================
  // 10. Home Page Cybersecurity Constellation Background & KPI Animation
  // ============================================================================
  function initCyberBackgroundCanvas() {
    const canvas = document.getElementById("cyberNetworkCanvas");
    if (!canvas) return;

    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      canvas.style.display = "none";
      return;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let animId = null;
    let isVisible = true;

    function resize() {
      const parent = canvas.parentElement;
      if (!parent) return;
      const rect = parent.getBoundingClientRect();
      width = rect.width || window.innerWidth;
      height = rect.height || 600;
      canvas.width = width * (window.devicePixelRatio || 1);
      canvas.height = height * (window.devicePixelRatio || 1);
      ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    }
    resize();
    window.addEventListener("resize", resize, { passive: true });

    const nodeCount = Math.max(18, Math.min(38, Math.floor(width / 36)));
    const nodes = [];
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: 1.5 + Math.random() * 1.5,
        alpha: 0.25 + Math.random() * 0.35
      });
    }

    function render() {
      if (!isVisible) {
        animId = null;
        return;
      }
      ctx.clearRect(0, 0, width, height);

      const isDark = document.documentElement.getAttribute("data-theme") === "dark";
      const nodeRgb = isDark ? "72, 139, 110" : "53, 92, 74";

      // Connecting lines
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 115) {
            const lineAlpha = (1 - dist / 115) * 0.16;
            ctx.strokeStyle = `rgba(${nodeRgb}, ${lineAlpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // Nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        if (n.x < 0) { n.x = 0; n.vx *= -1; }
        else if (n.x > width) { n.x = width; n.vx *= -1; }
        if (n.y < 0) { n.y = 0; n.vy *= -1; }
        else if (n.y > height) { n.y = height; n.vy *= -1; }

        ctx.fillStyle = `rgba(${nodeRgb}, ${n.alpha})`;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      animId = requestAnimationFrame(render);
    }

    const heroSec = canvas.closest(".hero-section");
    if (heroSec && "IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          isVisible = entry.isIntersecting && !document.hidden;
          if (isVisible && !animId) {
            animId = requestAnimationFrame(render);
          }
        });
      }, { threshold: 0.05 });
      observer.observe(heroSec);
    } else {
      animId = requestAnimationFrame(render);
    }

    document.addEventListener("visibilitychange", () => {
      isVisible = !document.hidden;
      if (isVisible && !animId) {
        animId = requestAnimationFrame(render);
      }
    });
  }

  function initHeroStatsAnimation() {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    const statElements = document.querySelectorAll(".hero-stat-card .stat-number");
    if (!statElements || statElements.length === 0) return;

    let hasAnimated = false;
    const heroStatsGrid = document.querySelector(".hero-stats-grid");
    if (!heroStatsGrid) return;

    function animateValue(el, start, end, duration, decimals = 0, prefix = "", suffix = "") {
      let startTimestamp = null;
      const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const ease = 1 - (1 - progress) * (1 - progress);
        const current = start + (end - start) * ease;
        el.textContent = `${prefix}${current.toFixed(decimals)}${suffix}`;
        if (progress < 1) {
          window.requestAnimationFrame(step);
        } else {
          el.textContent = `${prefix}${end.toFixed(decimals)}${suffix}`;
        }
      };
      window.requestAnimationFrame(step);
    }

    function runStatsAnimation() {
      if (hasAnimated) return;
      hasAnimated = true;
      statElements.forEach(el => {
        const text = el.textContent.trim();
        if (text === "15") {
          animateValue(el, 0, 15, 1000);
        } else if (text === "77") {
          animateValue(el, 0, 77, 1200);
        } else if (text.includes("99.86")) {
          animateValue(el, 80.0, 99.86, 1400, 2, "", "%");
        } else if (text.includes("1.0")) {
          el.style.opacity = "0";
          setTimeout(() => {
            el.style.transition = "opacity 0.6s ease";
            el.style.opacity = "1";
          }, 300);
        }
      });
    }

    if ("IntersectionObserver" in window) {
      const obs = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            runStatsAnimation();
            obs.disconnect();
          }
        });
      }, { threshold: 0.2 });
      obs.observe(heroStatsGrid);
    } else {
      runStatsAnimation();
    }
  }

  // Initialize Hero Visual Enhancements
  initCyberBackgroundCanvas();
  initHeroStatsAnimation();

  // Initialize Port Scanner UI
  PortScannerUI.init();

  window.addEventListener("beforeunload", () => {
    if (isScanning) stopScan(true);
  });
});