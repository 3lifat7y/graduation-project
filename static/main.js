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
    const str = String(newText);
    if (el.textContent !== str) {
      el.textContent = str;
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
  // Live Traffic Stream & Detected Attacks UI Controller
  // ============================================================================
  const liveTrafficTableBody = document.getElementById("liveTrafficTableBody");
  const trafficTableEmptyRow = document.getElementById("trafficTableEmptyRow");
  const liveTrafficCounterPill = document.getElementById("liveTrafficCounterPill");
  const liveStreamBadge = document.getElementById("liveStreamBadge");
  const liveStreamStatusText = document.getElementById("liveStreamStatusText");
  const trafficSearchInput = document.getElementById("trafficSearchInput");
  const trafficFilterBtns = document.querySelectorAll(".traffic-filter-btn");

  const attacksListContainer = document.getElementById("attacksListContainer");
  const emptyAttacksState = document.getElementById("emptyAttacksState");
  const attackCountBadge = document.getElementById("attackCountBadge");
  const clearAttackHistoryBtn = document.getElementById("clearAttackHistoryBtn");

  const attackDetailsModal = document.getElementById("attackDetailsModal");
  const closeAttackModalBtn = document.getElementById("closeAttackModalBtn");
  const attackModalBackdrop = document.getElementById("attackModalBackdrop");
  const modalAttackBody = document.getElementById("modalAttackBody");
  const modalAttackTitle = document.getElementById("modalAttackTitle");
  const modalAttackSubtitle = document.getElementById("modalAttackSubtitle");

  let livePacketsBuffer = [];
  const detectedAttacksRegistry = new Map();
  let activeTrafficFilter = "all";
  let trafficSearchTerm = "";

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function updateLiveTrafficStream(incomingPackets, isCapturing, totalCaptured) {
    if (liveStreamBadge && liveStreamStatusText) {
      if (isCapturing) {
        liveStreamBadge.classList.add("active");
        liveStreamStatusText.textContent = "Live Intercept";
      } else {
        liveStreamBadge.classList.remove("active");
        liveStreamStatusText.textContent = "Stream Idle";
      }
    }

    if (Array.isArray(incomingPackets) && incomingPackets.length > 0) {
      const seenKeys = new Set(livePacketsBuffer.slice(-50).map(p => `${p.raw_timestamp || p.timestamp}_${p.src_ip}_${p.src_port}_${p.dst_ip}_${p.dst_port}_${p.length}`));
      for (const pkt of incomingPackets) {
        const key = `${pkt.raw_timestamp || pkt.timestamp}_${pkt.src_ip}_${pkt.src_port}_${pkt.dst_ip}_${pkt.dst_port}_${pkt.length}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          livePacketsBuffer.push(pkt);
        }
      }
      if (livePacketsBuffer.length > 150) {
        livePacketsBuffer = livePacketsBuffer.slice(-150);
      }
    }

    if (liveTrafficCounterPill) {
      const displayCount = totalCaptured !== undefined ? totalCaptured : livePacketsBuffer.length;
      liveTrafficCounterPill.textContent = `${displayCount} Packets`;
    }

    renderLiveTrafficTable();
  }

  function renderLiveTrafficTable() {
    if (!liveTrafficTableBody) return;

    let filtered = livePacketsBuffer;
    if (activeTrafficFilter !== "all") {
      filtered = filtered.filter(p => {
        const proto = (p.protocol || "").toUpperCase();
        if (activeTrafficFilter === "tcp") return proto.includes("TCP");
        if (activeTrafficFilter === "udp") return proto.includes("UDP");
        if (activeTrafficFilter === "icmp") return proto.includes("ICMP") || (!proto.includes("TCP") && !proto.includes("UDP"));
        return true;
      });
    }

    if (trafficSearchTerm) {
      const term = trafficSearchTerm.toLowerCase();
      filtered = filtered.filter(p => {
        return (
          (p.src_ip && p.src_ip.toLowerCase().includes(term)) ||
          (p.dst_ip && p.dst_ip.toLowerCase().includes(term)) ||
          String(p.src_port).includes(term) ||
          String(p.dst_port).includes(term) ||
          (p.protocol && p.protocol.toLowerCase().includes(term)) ||
          (p.flow_id && p.flow_id.toLowerCase().includes(term))
        );
      });
    }

    if (filtered.length === 0) {
      liveTrafficTableBody.innerHTML = `
        <tr class="empty-row" id="trafficTableEmptyRow">
          <td colspan="6">
            <div class="empty-traffic-state">
              <i class="fas fa-satellite-dish"></i>
              <p>${isScanning ? "Listening for live packets on active network adapter..." : "Waiting for live traffic... Click <strong>Start Monitoring</strong> to inspect packets."}</p>
            </div>
          </td>
        </tr>`;
      return;
    }

    const displayList = filtered.slice(-35).reverse();
    const rowsHtml = displayList.map(pkt => {
      const proto = escapeHtml(pkt.protocol || "TCP");
      const protoClass = proto.toLowerCase().includes("tcp")
        ? "row-proto-tcp"
        : (proto.toLowerCase().includes("udp") ? "row-proto-udp" : "row-proto-icmp");
      const timeStr = escapeHtml(pkt.timestamp || "--:--:--");
      const srcStr = `${escapeHtml(pkt.src_ip || "0.0.0.0")}:${escapeHtml(pkt.src_port || "0")}`;
      const dstStr = `${escapeHtml(pkt.dst_ip || "0.0.0.0")}:${escapeHtml(pkt.dst_port || "0")}`;
      const lenStr = `${escapeHtml(pkt.length || 60)} B`;
      const flagsStr = escapeHtml(pkt.flags || "--");

      return `
        <tr class="${protoClass}">
          <td>${timeStr}</td>
          <td>${srcStr}</td>
          <td>${dstStr}</td>
          <td class="col-proto">${proto}</td>
          <td>${lenStr}</td>
          <td>${flagsStr}</td>
        </tr>`;
    }).join("");

    liveTrafficTableBody.innerHTML = rowsHtml;
  }

  function updateDetectedAttacksPanel(attacks) {
    if (!attacksListContainer || !Array.isArray(attacks)) return;

    for (const att of attacks) {
      const detId = att.detection_id || `det_${att.scan_id}_${att.flow_id}_${att.label}`;
      if (!detectedAttacksRegistry.has(detId)) {
        detectedAttacksRegistry.set(detId, att);
        createAttackCardElement(att, detId);
      } else {
        const existing = detectedAttacksRegistry.get(detId);
        Object.assign(existing, att);
        updateAttackCardElement(detId, att);
      }
    }

    const count = detectedAttacksRegistry.size;
    if (attackCountBadge) {
      attackCountBadge.textContent = `${count} Detected`;
    }

    if (emptyAttacksState) {
      emptyAttacksState.style.display = count > 0 ? "none" : "flex";
    }
  }

  function createAttackCardElement(att, detId) {
    const card = document.createElement("div");
    card.className = "attack-card";
    card.id = `card_${detId}`;
    card.setAttribute("role", "button");
    card.setAttribute("tabindex", "0");
    card.setAttribute("aria-label", `View details for ${att.label} detection`);

    const labelStr = escapeHtml(att.label || "Threat Detected");
    const confVal = typeof att.confidence === "number" ? att.confidence.toFixed(1) : "--";
    const timeStr = escapeHtml(att.timestamp || "--:--:--");
    const srcStr = `${escapeHtml(att.src_ip || "0.0.0.0")}:${escapeHtml(att.src_port || 0)}`;
    const dstStr = `${escapeHtml(att.dst_ip || "0.0.0.0")}:${escapeHtml(att.dst_port || 0)}`;
    const protoStr = escapeHtml(att.protocol || "TCP");

    card.innerHTML = `
      <div class="attack-card-top">
        <span class="attack-label-badge"><i class="fas fa-biohazard"></i> ${labelStr}</span>
        <span class="attack-time-meta" id="time_${detId}"><i class="fas fa-clock"></i> ${timeStr}</span>
      </div>
      <div class="attack-card-flow">
        <span>${srcStr}</span>
        <i class="fas fa-arrow-right flow-arrow"></i>
        <span>${dstStr}</span>
      </div>
      <div class="attack-card-bottom">
        <span class="attack-conf-pill" id="conf_${detId}">Confidence: ${confVal}%</span>
        <div class="attack-card-actions">
          <span class="proto-tag">${protoStr}</span>
          <button type="button" class="btn-card-detail">Inspect Flow <i class="fas fa-chevron-right"></i></button>
        </div>
      </div>
    `;

    card.addEventListener("click", () => {
      openAttackDetailsModal(att);
    });
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openAttackDetailsModal(att);
      }
    });

    if (emptyAttacksState && emptyAttacksState.nextSibling) {
      attacksListContainer.insertBefore(card, emptyAttacksState.nextSibling);
    } else {
      attacksListContainer.appendChild(card);
    }
  }

  function updateAttackCardElement(detId, att) {
    const card = document.getElementById(`card_${detId}`);
    if (!card) return;
    const timeEl = document.getElementById(`time_${detId}`);
    if (timeEl && att.last_seen_time) {
      timeEl.innerHTML = `<i class="fas fa-clock"></i> ${escapeHtml(att.last_seen_time)}`;
    }
    const confEl = document.getElementById(`conf_${detId}`);
    if (confEl && typeof att.confidence === "number") {
      const countSuffix = att.occurrence_count && att.occurrence_count > 1 ? ` (x${att.occurrence_count})` : "";
      confEl.textContent = `Confidence: ${att.confidence.toFixed(1)}%${countSuffix}`;
    }
  }

  function openAttackDetailsModal(att) {
    if (!attackDetailsModal || !modalAttackBody) return;
    const summary = att.flow_summary || {};
    const label = escapeHtml(att.label || "Threat Detected");
    const conf = typeof att.confidence === "number" ? `${att.confidence.toFixed(2)}%` : "--%";
    const flowDurationMs = summary.flow_duration_us ? (summary.flow_duration_us / 1000).toFixed(2) : "0.0";
    const bytesSec = summary.flow_bytes_per_s ? Number(summary.flow_bytes_per_s).toLocaleString() : "0.0";
    const pktsSec = summary.flow_packets_per_s ? Number(summary.flow_packets_per_s).toLocaleString() : "0.0";
    const avgPktSize = summary.avg_packet_size ? `${Number(summary.avg_packet_size).toFixed(1)} B` : "--";

    if (modalAttackTitle) modalAttackTitle.textContent = `${att.label} — Threat Details`;
    if (modalAttackSubtitle) modalAttackSubtitle.textContent = `Detection Event ID: ${att.detection_id || "N/A"}`;

    modalAttackBody.innerHTML = `
      <div class="modal-meta-grid">
        <div class="modal-meta-item">
          <span class="meta-lbl">Threat Vector</span>
          <span class="meta-val threat-val">${label}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Model Confidence</span>
          <span class="meta-val threat-val">${conf}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Detection Time</span>
          <span class="meta-val">${escapeHtml(att.timestamp || "--:--:--")}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Last Active Seen</span>
          <span class="meta-val">${escapeHtml(att.last_seen_time || att.timestamp || "--:--:--")}</span>
        </div>
        <div class="modal-meta-item full-width">
          <span class="meta-lbl">Associated Flow Identifier</span>
          <span class="meta-val">${escapeHtml(att.flow_id || "N/A")}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Source IP : Port</span>
          <span class="meta-val">${escapeHtml(att.src_ip || "0.0.0.0")} : ${escapeHtml(att.src_port || 0)}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Destination IP : Port</span>
          <span class="meta-val">${escapeHtml(att.dst_ip || "0.0.0.0")} : ${escapeHtml(att.dst_port || 0)}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Transport Protocol</span>
          <span class="meta-val">${escapeHtml(att.protocol || "TCP")}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Monitoring Session ID</span>
          <span class="meta-val">${escapeHtml(att.scan_id || "N/A")}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Flow Duration</span>
          <span class="meta-val">${flowDurationMs} ms (${summary.flow_duration_us || 0} µs)</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Packets in Window</span>
          <span class="meta-val">${summary.window_packets || summary.packets_captured || 0} pkts</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Throughput Rate</span>
          <span class="meta-val">${bytesSec} B/s</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Packet Velocity</span>
          <span class="meta-val">${pktsSec} Pkts/s</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Mean Packet Size</span>
          <span class="meta-val">${avgPktSize}</span>
        </div>
        <div class="modal-meta-item">
          <span class="meta-lbl">Deduplicated Hits</span>
          <span class="meta-val">${att.occurrence_count || 1} window occurrences</span>
        </div>
      </div>
    `;

    attackDetailsModal.style.display = "flex";
  }

  function closeAttackModal() {
    if (attackDetailsModal) {
      attackDetailsModal.style.display = "none";
    }
  }

  async function clearAttackHistory() {
    try {
      await fetch(`${API_BASE_URL}/detected-attacks/clear`, { method: "POST" });
    } catch (e) {
      console.warn("[DDoS-Guard] Failed to notify API of attack history clear:", e);
    }
    detectedAttacksRegistry.clear();
    if (attacksListContainer) {
      const cards = attacksListContainer.querySelectorAll(".attack-card");
      cards.forEach(c => c.remove());
    }
    if (emptyAttacksState) {
      emptyAttacksState.style.display = "flex";
    }
    if (attackCountBadge) {
      attackCountBadge.textContent = "0 Detected";
    }
  }

  // Bind traffic toolbar filters & search
  trafficFilterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      trafficFilterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeTrafficFilter = btn.getAttribute("data-filter") || "all";
      renderLiveTrafficTable();
    });
  });

  if (trafficSearchInput) {
    trafficSearchInput.addEventListener("input", (e) => {
      trafficSearchTerm = e.target.value.trim();
      renderLiveTrafficTable();
    });
  }

  if (clearAttackHistoryBtn) {
    clearAttackHistoryBtn.addEventListener("click", () => {
      clearAttackHistory();
    });
  }

  if (closeAttackModalBtn) {
    closeAttackModalBtn.addEventListener("click", closeAttackModal);
  }

  if (attackModalBackdrop) {
    attackModalBackdrop.addEventListener("click", closeAttackModal);
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && attackDetailsModal && attackDetailsModal.style.display === "flex") {
      closeAttackModal();
    }
  });

  // Load existing detected attacks once on page initialization
  async function loadInitialDetectedAttacks() {
    try {
      const res = await fetch(`${API_BASE_URL}/detected-attacks`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.detected_attacks)) {
          updateDetectedAttacksPanel(data.detected_attacks);
        }
      }
    } catch (e) {}
  }
  loadInitialDetectedAttacks();

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

    // If monitoring is not actively running, do not start capturing automatically.
    // Retain the idle/stopped state until the user explicitly clicks Start Monitoring.
    if (!isScanning) {
      console.log("[AdapterHub] Adapter selection updated while monitoring is stopped/idle. Retaining idle state.");
      return;
    }

    console.log(`[AdapterHub] Auto-triggering capture on '${activeAd ? activeAd.name : val}' (seq: ${currentSeq}, wasScanning: ${isScanning})...`);

    // Safely stop and clean up previous capture worker before starting the new one
    await stopScan(true);
    if (currentSeq !== adapterSwitchSeq) {
      console.log(`[AdapterHub] Discarding outdated switch sequence ${currentSeq} (current: ${adapterSwitchSeq})`);
      return;
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
  checkAndAttachActiveSession();
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
        if (liveStreamBadge && liveStreamStatusText) {
          liveStreamBadge.classList.remove("active");
          liveStreamStatusText.textContent = "Stream Idle";
        }

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
        if (liveStreamBadge && liveStreamStatusText) {
          liveStreamBadge.classList.remove("active");
          liveStreamStatusText.textContent = "Stream Idle";
        }

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
  const ACTIVE_CAPTURE_STATES = [
    "scanning", "starting", "monitoring", "prediction_available", "no_traffic", "insufficient_traffic"
  ];

  async function checkAndAttachActiveSession() {
    try {
      const res = await fetch(`${API_BASE_URL}/scan-status`);
      if (!res.ok) return;
      const data = await res.json();

      if (data.service_state || data.driver_status) {
        updateServiceBadge(data.service_state, data.driver_status);
      }

      const isActive = Boolean(data.is_active || (data.status && ACTIVE_CAPTURE_STATES.includes(data.status)));
      if (isActive && data.scan_id) {
        activeScanId = data.scan_id;
        isScanning = true;
        userManuallyStopped = false;

        // Sync live traffic stream and detected attacks
        const isCapturing = true;
        const totalCaptured = data.packets_captured !== undefined ? data.packets_captured : (data.flow_summary?.packets_captured);
        if (Array.isArray(data.live_packets)) {
          updateLiveTrafficStream(data.live_packets, isCapturing, totalCaptured);
        }
        if (Array.isArray(data.detected_attacks)) {
          updateDetectedAttacksPanel(data.detected_attacks);
        }

        // Apply state to UI
        setUIState(data.status, data);

        // Ensure continuous status polling interval is active
        if (!scanPollInterval) {
          scanPollInterval = setInterval(pollScanStatus, 500);
        }
        console.log(`[DDoS-Guard] Reconnected to active continuous monitoring session: ${activeScanId} (${data.status})`);
      }
    } catch (err) {
      console.warn("[DDoS-Guard] Active session check error:", err);
    }
  }

  async function startScan(opts = {}) {
    const forceRestart = Boolean(opts && opts.forceRestart);
    const isUserExplicitStart = (!opts || opts.switchSeq === undefined);
    const switchSeq = isUserExplicitStart ? ++adapterSwitchSeq : opts.switchSeq;

    if (isScanning && !forceRestart) return;

    activeScanId = null;
    userManuallyStopped = false;
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
      if (!isUserExplicitStart && switchSeq !== adapterSwitchSeq) {
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
      if (!isUserExplicitStart && switchSeq !== adapterSwitchSeq) {
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

      // If already scanning or active session reconnected, reflect running state immediately
      if (startData.status === "already_scanning" || startData.is_active) {
        isScanning = true;
        const targetState = (startData.status === "already_scanning" ? (startData.current_status || "monitoring") : startData.status);
        setUIState(targetState, startData);
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

      // If activeScanId was not yet registered on this client view, adopt active backend session
      if (!activeScanId && data.scan_id && (data.is_active || ACTIVE_CAPTURE_STATES.includes(data.status))) {
        activeScanId = data.scan_id;
        isScanning = true;
      }

      // STRICT CHECK: Reject any poll data from a previous or mismatched scan session
      if (activeScanId && data.scan_id && data.scan_id !== activeScanId) {
        return;
      }

      const status = data.status;
      const isContinuous = data.continuous !== false;

      // Update Live Traffic Stream and Detected Attacks Panel
      const isCapturing = (status === "monitoring" || status === "starting" || status === "scanning" || status === "prediction_available");
      const totalCaptured = data.packets_captured !== undefined ? data.packets_captured : (data.flow_summary?.packets_captured);
      if (Array.isArray(data.live_packets)) {
        updateLiveTrafficStream(data.live_packets, isCapturing, totalCaptured);
      } else {
        updateLiveTrafficStream([], isCapturing, totalCaptured);
      }

      if (Array.isArray(data.detected_attacks)) {
        updateDetectedAttacksPanel(data.detected_attacks);
      }

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
    updateLiveTrafficStream([], false);

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
  const breadcrumbDashboardLink = document.getElementById("breadcrumbDashboardLink");
  const publicDashboardCtaWrap = document.getElementById("publicDashboardCtaWrap");
  const publicDashboardCta = document.getElementById("publicDashboardCta");
  const publicDashboardCtaText = document.getElementById("publicDashboardCtaText");
  const heroDynamicDashboardBtn = document.getElementById("heroDynamicDashboardBtn");
  const heroDynamicDashboardBtnText = document.getElementById("heroDynamicDashboardBtnText");
  const launchDedicatedMonitorBtn = document.getElementById("launchDedicatedMonitorBtn");
  const launchDedicatedPortScannerBtn = document.getElementById("launchDedicatedPortScannerBtn");

  const heroSection = document.getElementById("overview");
  const monitorSection = document.getElementById("check-connection");
  const portScannerSection = document.getElementById("port-scanner");
  const subPlansSection = document.getElementById("subscription-plans");
  const adminConsoleSection = document.getElementById("admin-console");
  const userDashboardSection = document.getElementById("user-dashboard");
  const ndLandingSection = document.getElementById("network-discovery-section");
  const threatSection = document.getElementById("threat-intelligence");
  const preventionSection = document.getElementById("prevention");
  const publicPricingSection = document.getElementById("public-pricing");
  const teamSection = document.getElementById("team");
  const mindMapSection = document.getElementById("system-architecture");
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
    let normalized = navName || "";
    if (normalized === "admin-overview" || normalized === "admin-console") {
      normalized = "admin";
    } else if (normalized === "admin-operators") {
      normalized = "admin-users";
    } else if (normalized === "admin-subscriptions") {
      normalized = "admin-subs";
    }

    sidebarNavItems.forEach(item => {
      const isMatch = item.getAttribute("data-nav") === normalized;
      item.classList.toggle("active", isMatch);
      if (isMatch) {
        item.setAttribute("aria-current", "page");
      } else {
        item.removeAttribute("aria-current");
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
        metaTheme.setAttribute("content", isDark ? "#09090B" : "#FAFAFA");
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
    if (view === "dashboard" || view === "user-dashboard") return "dashboard";
    if (view === "monitoring" || view === "live-monitoring") return "monitoring";
    if (view === "port-scanner" || view === "scanner") return "port-scanner";
    if (view === "plans" || view === "subscriptions" || view === "subscription-plans") return "plans";
    if (view === "admin" || view === "admin-console" || view === "admin-overview") return "admin";
    if (view === "admin-operators") return "admin-users";
    if (view === "admin-subscriptions") return "admin-subs";
    if (view && (view.startsWith("admin-") || view.startsWith("admin_"))) return view;

    const hash = window.location.hash;
    if (hash === "#dashboard" || hash === "#user-dashboard") return "dashboard";
    if (hash === "#live-monitoring" || hash === "#monitoring") return "monitoring";
    if (hash === "#port-scanner-page") return "port-scanner";
    if (hash === "#subscription-plans" || hash === "#plans") return "plans";
    if (hash === "#admin-console" || hash === "#admin" || hash === "#admin-overview") return "admin";
    if (hash === "#admin-operators") return "admin-users";
    if (hash === "#admin-subscriptions") return "admin-subs";
    if (hash && (hash.startsWith("#admin-") || hash.startsWith("#admin_"))) return hash.replace("#", "");

    return "landing";
  }

  // ============================================================================
  // SCOUT Authentication & Identity State Controller
  // ============================================================================
  let currentUser = null;
  let currentUserSubscription = null;

  const authModal = document.getElementById("authModal");
  const authModalCloseBtn = document.getElementById("authModalCloseBtn");
  const authModalBackdrop = document.getElementById("authModalBackdrop");
  const tabSignInBtn = document.getElementById("tabSignInBtn");
  const tabRegisterBtn = document.getElementById("tabRegisterBtn");
  const signInPanel = document.getElementById("signInPanel");
  const registerPanel = document.getElementById("registerPanel");
  const signInForm = document.getElementById("signInForm");
  const registerForm = document.getElementById("registerForm");
  const signInAlert = document.getElementById("signInAlert");
  const registerAlert = document.getElementById("registerAlert");
  const headerSignInBtn = document.getElementById("headerSignInBtn");
  const headerGetStartedBtn = document.getElementById("headerGetStartedBtn");
  const publicAuthActions = document.getElementById("publicAuthActions");
  const userProfileMenu = document.getElementById("userProfileMenu");
  const userProfileDropdownBtn = document.getElementById("userProfileDropdownBtn");
  const userDropdownCard = document.getElementById("userDropdownCard");
  const navUserName = document.getElementById("navUserName");
  const navUserRoleBadge = document.getElementById("navUserRoleBadge");
  const dropdownUserTitle = document.getElementById("dropdownUserTitle");
  const dropdownUserEmail = document.getElementById("dropdownUserEmail");
  const dropdownDashboardLink = document.getElementById("dropdownDashboardLink");
  const dropdownPublicLink = document.getElementById("dropdownPublicLink");
  const dropdownAdminLink = document.getElementById("dropdownAdminLink");
  const sidebarAdminNavGroup = document.getElementById("sidebarAdminNavGroup");
  const sidebarUserNavGroup = document.getElementById("sidebarUserNavGroup");
  const sidebarToolsNavGroup = document.getElementById("sidebarToolsNavGroup");
  const sidebarPublicNavGroup = document.getElementById("sidebarPublicNavGroup");
  const publicTopNavLinks = document.getElementById("publicTopNavLinks");
  const sidebarPendingBadge = document.getElementById("sidebarPendingBadge");
  const signOutBtn = document.getElementById("signOutBtn");
  const switchToRegisterBtn = document.getElementById("switchToRegisterBtn");
  const switchToSignInBtn = document.getElementById("switchToSignInBtn");
  const toggleSignInPwd = document.getElementById("toggleSignInPwd");
  const toggleRegPwd = document.getElementById("toggleRegPwd");

  function openAuthModal(defaultTab = "signin", notice = "") {
    if (!authModal) return;
    authModal.style.display = "flex";
    authModal.setAttribute("aria-hidden", "false");
    document.body.style.overflow = "hidden";
    switchAuthTab(defaultTab);
    if (notice) {
      if (signInAlert) {
        signInAlert.className = "auth-alert error";
        signInAlert.textContent = notice;
        signInAlert.style.display = "block";
      }
    }
  }

  function closeAuthModal() {
    if (!authModal) return;
    authModal.style.display = "none";
    authModal.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "";
    if (signInAlert) signInAlert.style.display = "none";
    if (registerAlert) registerAlert.style.display = "none";
  }

  function switchAuthTab(tab) {
    if (tab === "register") {
      if (tabSignInBtn) {
        tabSignInBtn.classList.remove("active");
        tabSignInBtn.setAttribute("aria-selected", "false");
      }
      if (tabRegisterBtn) {
        tabRegisterBtn.classList.add("active");
        tabRegisterBtn.setAttribute("aria-selected", "true");
      }
      if (signInPanel) signInPanel.style.display = "none";
      if (registerPanel) registerPanel.style.display = "block";
      const u = document.getElementById("regUsername");
      if (u) u.focus();
    } else {
      if (tabRegisterBtn) {
        tabRegisterBtn.classList.remove("active");
        tabRegisterBtn.setAttribute("aria-selected", "false");
      }
      if (tabSignInBtn) {
        tabSignInBtn.classList.add("active");
        tabSignInBtn.setAttribute("aria-selected", "true");
      }
      if (registerPanel) registerPanel.style.display = "none";
      if (signInPanel) signInPanel.style.display = "block";
      const i = document.getElementById("signInIdentifier");
      if (i) i.focus();
    }
  }

  function updateAuthUI(user) {
    currentUser = user;
    if (user) {
      document.body.classList.remove("auth-anonymous", "anonymous-landing");
      document.body.classList.add("auth-authenticated");

      if (user.role === "Admin") {
        document.body.classList.add("auth-admin");
        if (sidebarAdminNavGroup) sidebarAdminNavGroup.style.display = "block";
        if (sidebarUserNavGroup) sidebarUserNavGroup.style.display = "none";
        if (dropdownAdminLink) dropdownAdminLink.style.display = "flex";
        if (dropdownDashboardLink) dropdownDashboardLink.style.display = "none";

        // Dynamic Admin Dashboard CTA for Public Homepage
        if (publicDashboardCtaWrap) publicDashboardCtaWrap.style.display = "flex";
        if (publicDashboardCta) publicDashboardCta.setAttribute("href", "/?view=admin");
        if (publicDashboardCtaText) publicDashboardCtaText.textContent = "Go to Admin Dashboard";

        if (heroDynamicDashboardBtn) {
          heroDynamicDashboardBtn.style.display = "inline-flex";
          heroDynamicDashboardBtn.setAttribute("href", "/?view=admin");
        }
        if (heroDynamicDashboardBtnText) heroDynamicDashboardBtnText.textContent = "Go to Admin Dashboard";

        if (breadcrumbDashboardLink) {
          breadcrumbDashboardLink.setAttribute("href", "/?view=admin");
          breadcrumbDashboardLink.innerHTML = '<i class="fas fa-shield-halved"></i> Admin Console';
        }
      } else {
        document.body.classList.remove("auth-admin");
        if (sidebarAdminNavGroup) sidebarAdminNavGroup.style.display = "none";
        if (sidebarUserNavGroup) sidebarUserNavGroup.style.display = "block";
        if (dropdownAdminLink) dropdownAdminLink.style.display = "none";

        // Dynamic User Dashboard CTA for Public Homepage
        const hasActiveSub = currentUserSubscription && currentUserSubscription.status === "active";
        if (publicDashboardCtaWrap) publicDashboardCtaWrap.style.display = "flex";

        if (hasActiveSub) {
          if (publicDashboardCta) publicDashboardCta.setAttribute("href", "/?view=dashboard");
          if (publicDashboardCtaText) publicDashboardCtaText.textContent = "Go to Dashboard";

          if (heroDynamicDashboardBtn) {
            heroDynamicDashboardBtn.style.display = "inline-flex";
            heroDynamicDashboardBtn.setAttribute("href", "/?view=dashboard");
          }
          if (heroDynamicDashboardBtnText) heroDynamicDashboardBtnText.textContent = "Go to Dashboard";

          if (breadcrumbDashboardLink) {
            breadcrumbDashboardLink.setAttribute("href", "/?view=dashboard");
            breadcrumbDashboardLink.innerHTML = '<i class="fas fa-gauge-high"></i> Dashboard';
          }
          if (dropdownDashboardLink) dropdownDashboardLink.style.display = "flex";
        } else {
          if (publicDashboardCta) publicDashboardCta.setAttribute("href", "/?view=plans");
          if (publicDashboardCtaText) publicDashboardCtaText.textContent = "View Subscription Plans";

          if (heroDynamicDashboardBtn) {
            heroDynamicDashboardBtn.style.display = "inline-flex";
            heroDynamicDashboardBtn.setAttribute("href", "/?view=plans");
          }
          if (heroDynamicDashboardBtnText) heroDynamicDashboardBtnText.textContent = "View Subscription Plans";

          if (breadcrumbDashboardLink) {
            breadcrumbDashboardLink.setAttribute("href", "/?view=plans");
            breadcrumbDashboardLink.innerHTML = '<i class="fas fa-gem"></i> Plans';
          }
          if (dropdownDashboardLink) dropdownDashboardLink.style.display = "none";
        }
      }

      if (sidebarToolsNavGroup) sidebarToolsNavGroup.style.display = "block";
      if (dropdownPublicLink) dropdownPublicLink.style.display = "flex";
      const dropdownPlans = document.getElementById("dropdownPlansLink");
      if (dropdownPlans) dropdownPlans.style.display = "flex";
      if (publicAuthActions) publicAuthActions.style.display = "none";
      if (userProfileMenu) userProfileMenu.style.display = "block";
      if (navUserName) navUserName.textContent = user.full_name || user.username;
      if (navUserRoleBadge) navUserRoleBadge.textContent = user.role;
      if (dropdownUserTitle) dropdownUserTitle.textContent = user.full_name || user.username;
      if (dropdownUserEmail) dropdownUserEmail.textContent = user.email;
    } else {
      document.body.classList.remove("auth-authenticated", "auth-admin");
      document.body.classList.add("auth-anonymous");
      if (sidebarAdminNavGroup) sidebarAdminNavGroup.style.display = "none";
      if (sidebarUserNavGroup) sidebarUserNavGroup.style.display = "none";
      if (sidebarToolsNavGroup) sidebarToolsNavGroup.style.display = "none";
      if (dropdownDashboardLink) dropdownDashboardLink.style.display = "none";
      if (dropdownPublicLink) dropdownPublicLink.style.display = "none";
      const dropdownPlans = document.getElementById("dropdownPlansLink");
      if (dropdownPlans) dropdownPlans.style.display = "none";
      if (dropdownAdminLink) dropdownAdminLink.style.display = "none";
      if (publicDashboardCtaWrap) publicDashboardCtaWrap.style.display = "none";
      if (heroDynamicDashboardBtn) heroDynamicDashboardBtn.style.display = "none";
      if (publicAuthActions) publicAuthActions.style.display = "flex";
      if (userProfileMenu) userProfileMenu.style.display = "none";
      if (userDropdownCard) userDropdownCard.style.display = "none";
    }
  }

  async function checkAuthSession() {
    try {
      const res = await fetch("/api/auth/me", { credentials: "same-origin" });
      if (res.ok) {
        const data = await res.json();
        currentUser = data.user;
        await fetchCurrentUserSubscription();
        updateAuthUI(data.user);
        return data.user;
      } else {
        currentUser = null;
        currentUserSubscription = null;
        updateAuthUI(null);
        return null;
      }
    } catch (_) {
      currentUser = null;
      currentUserSubscription = null;
      updateAuthUI(null);
      return null;
    }
  }

  async function fetchCurrentUserSubscription() {
    try {
      const res = await fetch("/api/subscriptions/my-subscription", { credentials: "same-origin" });
      if (res.ok) {
        const data = await res.json();
        currentUserSubscription = data.subscription;
        if (currentUser) updateAuthUI(currentUser);
        return data.subscription;
      }
    } catch (_) {}
    currentUserSubscription = null;
    if (currentUser) updateAuthUI(currentUser);
    return null;
  }

  // Bind Auth Modal Open & Switch Buttons
  if (headerSignInBtn) headerSignInBtn.addEventListener("click", () => openAuthModal("signin"));
  if (headerGetStartedBtn) headerGetStartedBtn.addEventListener("click", () => openAuthModal("register"));
  if (switchToRegisterBtn) switchToRegisterBtn.addEventListener("click", () => switchAuthTab("register"));
  if (switchToSignInBtn) switchToSignInBtn.addEventListener("click", () => switchAuthTab("signin"));
  if (tabSignInBtn) tabSignInBtn.addEventListener("click", () => switchAuthTab("signin"));
  if (tabRegisterBtn) tabRegisterBtn.addEventListener("click", () => switchAuthTab("register"));
  if (authModalCloseBtn) authModalCloseBtn.addEventListener("click", closeAuthModal);
  if (authModalBackdrop) authModalBackdrop.addEventListener("click", closeAuthModal);

  // Toggle Password Visibilities
  if (toggleSignInPwd) {
    toggleSignInPwd.addEventListener("click", () => {
      const inp = document.getElementById("signInPassword");
      if (inp) {
        inp.type = inp.type === "password" ? "text" : "password";
        toggleSignInPwd.querySelector("i").className = inp.type === "password" ? "fas fa-eye" : "fas fa-eye-slash";
      }
    });
  }
  if (toggleRegPwd) {
    toggleRegPwd.addEventListener("click", () => {
      const inp = document.getElementById("regPassword");
      if (inp) {
        inp.type = inp.type === "password" ? "text" : "password";
        toggleRegPwd.querySelector("i").className = inp.type === "password" ? "fas fa-eye" : "fas fa-eye-slash";
      }
    });
  }

  // User Profile Dropdown Toggle
  if (userProfileDropdownBtn) {
    userProfileDropdownBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!userDropdownCard) return;
      const isOpen = userDropdownCard.style.display === "block";
      userDropdownCard.style.display = isOpen ? "none" : "block";
      userProfileDropdownBtn.setAttribute("aria-expanded", isOpen ? "false" : "true");
    });
  }
  document.addEventListener("click", (e) => {
    if (userDropdownCard && userDropdownCard.style.display === "block") {
      if (!userProfileMenu || !userProfileMenu.contains(e.target)) {
        userDropdownCard.style.display = "none";
        if (userProfileDropdownBtn) userProfileDropdownBtn.setAttribute("aria-expanded", "false");
      }
    }
  });

  // Sign In Form Submit Handler
  if (signInForm) {
    signInForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const identifier = document.getElementById("signInIdentifier")?.value?.trim() || "";
      const password = document.getElementById("signInPassword")?.value || "";
      const submitBtn = document.getElementById("signInSubmitBtn");

      if (!identifier || !password) {
        if (signInAlert) {
          signInAlert.className = "auth-alert error";
          signInAlert.textContent = "Please enter both username/email and password.";
          signInAlert.style.display = "block";
        }
        return;
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        const btnText = submitBtn.querySelector(".auth-btn-text");
        if (btnText) btnText.textContent = "Signing in...";
      }
      if (signInAlert) signInAlert.style.display = "none";

      try {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ username: identifier, password })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          updateAuthUI(data.user);
          await fetchCurrentUserSubscription();
          closeAuthModal();
          if (data.view) {
            switchView(data.view);
          } else if (data.redirect) {
            window.location.href = data.redirect;
          } else if (data.user && data.user.role === "Admin") {
            switchView("admin");
          } else {
            switchView("dashboard");
          }
        } else {
          if (signInAlert) {
            signInAlert.className = "auth-alert error";
            signInAlert.textContent = data.message || "Invalid credentials.";
            signInAlert.style.display = "block";
          }
        }
      } catch (err) {
        if (signInAlert) {
          signInAlert.className = "auth-alert error";
          signInAlert.textContent = "Network error: Unable to connect to authentication service.";
          signInAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          const btnText = submitBtn.querySelector(".auth-btn-text");
          if (btnText) btnText.textContent = "Sign In";
        }
      }
    });
  }

  // Register Form Submit Handler
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("regUsername")?.value?.trim() || "";
      const fullName = document.getElementById("regFullName")?.value?.trim() || "";
      const email = document.getElementById("regEmail")?.value?.trim() || "";
      const password = document.getElementById("regPassword")?.value || "";
      const confirmPassword = document.getElementById("regConfirmPassword")?.value || "";
      const submitBtn = document.getElementById("registerSubmitBtn");

      if (!username || !email || !password || !confirmPassword) {
        if (registerAlert) {
          registerAlert.className = "auth-alert error";
          registerAlert.textContent = "Please fill in all required fields.";
          registerAlert.style.display = "block";
        }
        return;
      }

      if (password !== confirmPassword) {
        if (registerAlert) {
          registerAlert.className = "auth-alert error";
          registerAlert.textContent = "Passwords do not match.";
          registerAlert.style.display = "block";
        }
        return;
      }

      if (submitBtn) {
        submitBtn.disabled = true;
        const btnText = submitBtn.querySelector(".auth-btn-text");
        if (btnText) btnText.textContent = "Creating Account...";
      }
      if (registerAlert) registerAlert.style.display = "none";

      try {
        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            username,
            full_name: fullName,
            email,
            password,
            confirm_password: confirmPassword
          })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          updateAuthUI(data.user);
          await fetchCurrentUserSubscription();
          closeAuthModal();
          switchView("plans");
        } else {
          if (registerAlert) {
            registerAlert.className = "auth-alert error";
            registerAlert.textContent = data.message || "Registration failed.";
            registerAlert.style.display = "block";
          }
        }
      } catch (err) {
        if (registerAlert) {
          registerAlert.className = "auth-alert error";
          registerAlert.textContent = "Network error: Unable to connect to registration service.";
          registerAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          const btnText = submitBtn.querySelector(".auth-btn-text");
          if (btnText) btnText.textContent = "Create Account & Select Plan";
        }
      }
    });
  }

  async function performLogout() {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin"
      });
    } catch (_) {}
    currentUser = null;
    currentUserSubscription = null;
    updateAuthUI(null);
    window.location.replace("/?public=1");
  }

  // Sign Out Handler
  if (signOutBtn) {
    signOutBtn.addEventListener("click", (e) => {
      e.preventDefault();
      performLogout();
    });
  }

  // Switch View: Dedicated Workspace vs Full Landing Page
  function switchView(targetView, updateHistory = true) {
    // Intercept operational tools and dashboard for anonymous visitors
    if ((targetView === "monitoring" || targetView === "port-scanner" || targetView === "dashboard") && !currentUser) {
      openAuthModal("signin", "Authentication required to access SCOUT Operational Tools and Dashboard.");
      if (updateHistory) {
        history.replaceState({ view: "landing" }, "", window.location.pathname);
      }
      targetView = "landing";
    }

    // Intercept operational tools for authenticated users without active subscription
    if ((targetView === "monitoring" || targetView === "port-scanner") && currentUser && currentUser.role !== "Admin") {
      const hasActiveSub = currentUserSubscription && currentUserSubscription.status === "active";
      if (!hasActiveSub) {
        targetView = "plans";
        window.setTimeout(() => {
          const alertBox = document.getElementById("subAlertBox");
          if (alertBox) {
            alertBox.className = "sub-alert-box warning";
            alertBox.innerHTML = '<i class="fas fa-triangle-exclamation"></i> An active subscription is required to access ' + (targetView === "monitoring" ? "Live Network Monitoring" : "Port Scanner") + '. Please select or activate a plan below.';
            alertBox.style.display = "flex";
          }
        }, 120);
      }
    }

    // Intercept User Dashboard for authenticated users without active subscription
    if (targetView === "dashboard" && currentUser && currentUser.role !== "Admin") {
      const hasActiveSub = currentUserSubscription && currentUserSubscription.status === "active";
      if (!hasActiveSub) {
        targetView = "plans";
      }
    }

    // Close mobile drawer on navigation
    document.body.classList.remove("mobile-sidebar-open");
    if (mobileMenuBtn) mobileMenuBtn.setAttribute("aria-expanded", "false");
    if (navbarSidebarToggleBtn) navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");

    // Close any open modals and reset body scroll lock
    if (typeof closeAttackModal === "function") {
      try { closeAttackModal(); } catch (_) {}
    }
    if (typeof window.PortScannerUI !== "undefined" && window.PortScannerUI && typeof window.PortScannerUI.closePortDetailsModal === "function") {
      try { window.PortScannerUI.closePortDetailsModal(); } catch (_) {}
    }
    document.body.style.overflow = "";

    if (targetView === "dashboard") {
      document.title = "SCOUT — Operator Dashboard & Mission Control";
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner", "home-view", "plans-view", "admin-view", "anonymous-landing");
      document.body.classList.add("dashboard-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Operator Dashboard & Mission Control";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (subPlansSection) subPlansSection.style.display = "none";
      if (adminConsoleSection) adminConsoleSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (publicPricingSection) publicPricingSection.style.display = "none";
      if (mindMapSection) mindMapSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";
      if (userDashboardSection) userDashboardSection.style.display = "block";

      setSidebarActive("dashboard");
      window.scrollTo({ top: 0, behavior: "smooth" });

      loadUserDashboard();

      if (updateHistory) {
        history.pushState({ view: "dashboard" }, "", "?view=dashboard");
      }
    } else if (targetView === "monitoring") {
      document.title = "SCOUT — Live Network Monitoring & Intrusion Detection";
      document.body.classList.add("dedicated-mode-monitoring");
      document.body.classList.remove("dedicated-mode-port-scanner", "home-view", "plans-view", "admin-view", "dashboard-view", "anonymous-landing");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Live Network Monitoring & Intrusion Detection";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "block";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (subPlansSection) subPlansSection.style.display = "none";
      if (adminConsoleSection) adminConsoleSection.style.display = "none";
      if (userDashboardSection) userDashboardSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (publicPricingSection) publicPricingSection.style.display = "none";
      if (mindMapSection) mindMapSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("monitoring");
      setTopNavActive("monitoring");
      window.scrollTo({ top: 0, behavior: "smooth" });
      discoverInterfaces(true);
      checkAndAttachActiveSession();

      if (updateHistory) {
        history.pushState({ view: "monitoring" }, "", "?view=monitoring");
      }
    } else if (targetView === "port-scanner") {
      document.title = "SCOUT — Port Scanning & Service Analysis";
      document.body.classList.add("dedicated-mode-port-scanner");
      document.body.classList.remove("dedicated-mode-monitoring", "home-view", "plans-view", "admin-view", "dashboard-view", "anonymous-landing");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Port Scanning & Service Analysis";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "block";
      if (subPlansSection) subPlansSection.style.display = "none";
      if (adminConsoleSection) adminConsoleSection.style.display = "none";
      if (userDashboardSection) userDashboardSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (publicPricingSection) publicPricingSection.style.display = "none";
      if (mindMapSection) mindMapSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";

      setSidebarActive("port-scanner");
      setTopNavActive("port-scanner");
      window.scrollTo({ top: 0, behavior: "smooth" });

      if (typeof window.PortScannerUI !== "undefined" && window.PortScannerUI) {
        if (window.PortScannerUI.handleIncomingTarget) {
          window.PortScannerUI.handleIncomingTarget();
        } else if (window.PortScannerUI.checkAndAttachActivePortScan) {
          window.PortScannerUI.checkAndAttachActivePortScan();
        }
      }

      if (updateHistory) {
        history.pushState({ view: "port-scanner" }, "", "?view=port-scanner");
      }
    } else if (targetView === "plans") {
      document.title = "SCOUT — Subscription Plans & Access Tiers";
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner", "home-view", "admin-view", "dashboard-view", "anonymous-landing");
      document.body.classList.add("plans-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Subscription Plans & Access Tiers";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (publicPricingSection) publicPricingSection.style.display = "none";
      if (mindMapSection) mindMapSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";
      if (adminConsoleSection) adminConsoleSection.style.display = "none";
      if (userDashboardSection) userDashboardSection.style.display = "none";
      if (subPlansSection) subPlansSection.style.display = "block";

      setSidebarActive("plans");
      window.scrollTo({ top: 0, behavior: "smooth" });

      loadUserSubscription();
      loadPlansCatalog();

      if (updateHistory) {
        history.pushState({ view: "plans" }, "", "?view=plans");
      }
    } else if (targetView === "admin" || (targetView && targetView.startsWith("admin-"))) {
      if (!currentUser || currentUser.role !== "Admin") {
        switchView("landing", updateHistory);
        return;
      }

      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner", "home-view", "plans-view", "dashboard-view", "anonymous-landing");
      document.body.classList.add("admin-view");

      let subTab = "overview";
      if (targetView === "admin-users" || targetView === "admin-operators") {
        subTab = "users";
      } else if (targetView === "admin-plans") {
        subTab = "plans";
      } else if (targetView === "admin-subs" || targetView === "admin-subscriptions") {
        subTab = "subscriptions";
      } else if (targetView === "admin-requests") {
        subTab = "requests";
      } else if (targetView === "admin-audit") {
        subTab = "audit";
      } else if (targetView === "admin-profile") {
        subTab = "profile";
      }

      // Hide dedicated tool bar so it does not render a redundant top breadcrumb above admin console
      if (dedicatedToolBar) dedicatedToolBar.style.display = "none";

      if (heroSection) heroSection.style.display = "none";
      if (monitorSection) monitorSection.style.display = "none";
      if (portScannerSection) portScannerSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "none";
      if (threatSection) threatSection.style.display = "none";
      if (preventionSection) preventionSection.style.display = "none";
      if (teamSection) teamSection.style.display = "none";
      if (publicPricingSection) publicPricingSection.style.display = "none";
      if (mindMapSection) mindMapSection.style.display = "none";
      if (footerEl) footerEl.style.display = "none";
      if (subPlansSection) subPlansSection.style.display = "none";
      if (userDashboardSection) userDashboardSection.style.display = "none";
      if (adminConsoleSection) adminConsoleSection.style.display = "block";

      setSidebarActive(targetView);
      window.scrollTo({ top: 0, behavior: "smooth" });

      if (typeof activateAdminTab === "function") {
        activateAdminTab(subTab, false);
      }

      if (updateHistory) {
        history.pushState({ view: targetView }, "", "?view=" + targetView);
      }
    } else {
      document.title = "SCOUT — Autonomous Cyber Threat Defense & Telemetry";
      // Home Page Mode: Live Monitoring, Port Scanner, Plans & Admin Console are NEVER displayed on Home!
      document.body.classList.remove("dedicated-mode-monitoring", "dedicated-mode-port-scanner", "plans-view", "admin-view", "dashboard-view");
      document.body.classList.add("home-view");

      if (!currentUser) {
        document.body.classList.add("anonymous-landing");
      } else {
        document.body.classList.remove("anonymous-landing");
      }

      if (dedicatedToolBar) dedicatedToolBar.style.display = "none";

      if (heroSection) heroSection.style.display = "block";
      if (monitorSection) monitorSection.style.display = "none"; // NEVER on Home
      if (portScannerSection) portScannerSection.style.display = "none"; // NEVER on Home
      if (subPlansSection) subPlansSection.style.display = "none";
      if (adminConsoleSection) adminConsoleSection.style.display = "none";
      if (userDashboardSection) userDashboardSection.style.display = "none";
      if (ndLandingSection) ndLandingSection.style.display = "block";
      if (threatSection) threatSection.style.display = "block";
      if (preventionSection) preventionSection.style.display = "block";
      if (publicPricingSection) publicPricingSection.style.display = "block";
      if (teamSection) teamSection.style.display = "block";
      if (mindMapSection) mindMapSection.style.display = "block";
      if (footerEl) footerEl.style.display = "block";

      setSidebarActive("home");
      setTopNavActive("home");

      loadPublicHomepagePlans();

      if (typeof window.renderMindMapConnectors === "function") {
        setTimeout(window.renderMindMapConnectors, 50);
      } else if (typeof window.initMindMap === "function") {
        setTimeout(window.initMindMap, 50);
      }

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
        if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner") || document.body.classList.contains("plans-view") || document.body.classList.contains("admin-view")) {
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

  // Helper to auto-close mobile drawer after navigation
  function autoCloseSidebarAfterNav() {
    if (window.innerWidth < 992) {
      closeMobileSidebar();
    }
  }

  // Intercept Navigation Link Clicks in Sidebar
  sidebarNavItems.forEach(item => {
    item.addEventListener("click", (e) => {
      const navTarget = item.getAttribute("data-nav");
      const href = item.getAttribute("href") || "";

      if (navTarget === "dashboard") {
        e.preventDefault();
        switchView("dashboard");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "monitoring") {
        e.preventDefault();
        switchView("monitoring");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "port-scanner") {
        e.preventDefault();
        switchView("port-scanner");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "plans") {
        e.preventDefault();
        switchView("plans");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "admin" || (navTarget && navTarget.startsWith("admin-"))) {
        e.preventDefault();
        switchView(navTarget);
        autoCloseSidebarAfterNav();
      } else if (navTarget === "public-site") {
        e.preventDefault();
        switchView("landing");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "home") {
        if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner") || document.body.classList.contains("plans-view") || document.body.classList.contains("admin-view")) {
          e.preventDefault();
          switchView("landing");
          window.scrollTo({ top: 0, behavior: "smooth" });
        } else {
          const overviewSec = document.getElementById("overview");
          if (overviewSec) {
            e.preventDefault();
            overviewSec.scrollIntoView({ behavior: "smooth" });
          } else {
            window.scrollTo({ top: 0, behavior: "smooth" });
          }
          setSidebarActive("home");
          setTopNavActive("home");
        }
        autoCloseSidebarAfterNav();
      } else if (navTarget === "network-discovery") {
        autoCloseSidebarAfterNav();
        // Allow standard navigation to /network-discovery
      } else {
        if (href.includes("#")) {
          const hash = href.substring(href.indexOf("#"));
          if (hash && hash !== "#") {
            const targetEl = document.querySelector(hash);
            if (targetEl) {
              if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner")) {
                switchView("landing", false);
              }
              e.preventDefault();
              targetEl.scrollIntoView({ behavior: "smooth" });
              try { history.pushState(null, "", hash); } catch (_) {}
            }
          }
        }
        autoCloseSidebarAfterNav();
      }
    });
  });

  const sidebarBrandLink = document.getElementById("sidebarBrandLink");
  if (sidebarBrandLink) {
    sidebarBrandLink.addEventListener("click", () => {
      autoCloseSidebarAfterNav();
    });
  }

  if (breadcrumbDashboardLink) {
    breadcrumbDashboardLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (currentUser && currentUser.role === "Admin") {
        switchView("admin");
      } else if (currentUser && currentUserSubscription && currentUserSubscription.status === "active") {
        switchView("dashboard");
      } else if (currentUser) {
        switchView("plans");
      } else {
        switchView("landing");
      }
    });
  }

  if (publicDashboardCta) {
    publicDashboardCta.addEventListener("click", (e) => {
      e.preventDefault();
      if (!currentUser) {
        openAuthModal("signin");
        return;
      }
      if (currentUser.role === "Admin") {
        switchView("admin");
      } else {
        const hasActiveSub = currentUserSubscription && currentUserSubscription.status === "active";
        if (hasActiveSub) {
          switchView("dashboard");
        } else {
          switchView("plans");
        }
      }
    });
  }

  if (heroDynamicDashboardBtn) {
    heroDynamicDashboardBtn.addEventListener("click", (e) => {
      e.preventDefault();
      if (!currentUser) {
        openAuthModal("signin");
        return;
      }
      if (currentUser.role === "Admin") {
        switchView("admin");
      } else {
        const hasActiveSub = currentUserSubscription && currentUserSubscription.status === "active";
        if (hasActiveSub) {
          switchView("dashboard");
        } else {
          switchView("plans");
        }
      }
    });
  }

  const topNavBrandLink = document.querySelector(".top-nav-brand");
  if (topNavBrandLink) {
    topNavBrandLink.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("landing");
    });
  }

  if (dropdownPublicLink) {
    dropdownPublicLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("landing");
    });
  }

  if (dropdownDashboardLink) {
    dropdownDashboardLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      const hasActiveSub = currentUserSubscription && currentUserSubscription.status === "active";
      if (hasActiveSub) {
        switchView("dashboard");
      } else {
        switchView("plans");
      }
    });
  }

  const dropdownPlans = document.getElementById("dropdownPlansLink");
  if (dropdownPlans) {
    dropdownPlans.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("plans");
    });
  }

  if (dropdownAdminLink) {
    dropdownAdminLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("admin");
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
    // Strictly restrict landing-page scrollspy to home-view to prevent
    // clearing or disrupting active navigation state in admin, dashboard, or dedicated views.
    if (!document.body.classList.contains("home-view")) {
      return;
    }
    setSidebarActive("home");
  }

  window.addEventListener("scroll", highlightNavOnScroll, { passive: true });

  const globalTopNavbar = document.getElementById("globalTopNavbar");
  if (globalTopNavbar) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 8) {
        globalTopNavbar.classList.add("is-scrolled");
      } else {
        globalTopNavbar.classList.remove("is-scrolled");
      }
    }, { passive: true });
  }

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
    let activeFilter = "all"; // 'all' | 'open' | 'closed' | 'filtered'
    let searchQuery = "";
    let sortField = "port"; // 'port' | 'state' | 'service' | 'latency'
    let sortDirection = "asc"; // 'asc' | 'desc'
    let selectedPortDetail = null;
    let isAutoScanPending = false;

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

    // KPI Counters (5 Core Metrics + Hosts)
    const kpiGrid = document.getElementById("psKpiGrid");
    const kpiScanned = document.getElementById("psKpiScanned");
    const kpiOpen = document.getElementById("psKpiOpen");
    const kpiClosed = document.getElementById("psKpiClosed");
    const kpiFiltered = document.getElementById("psKpiFiltered");
    const kpiDuration = document.getElementById("psKpiDuration");
    const kpiHosts = document.getElementById("psKpiHosts");
    const kpiCardHosts = document.getElementById("psKpiCardHosts");

    const errorBanner = document.getElementById("psErrorBanner");
    const errorText = document.getElementById("psErrorText");

    const resultsWrapper = document.getElementById("psResultsWrapper");
    const resultsContent = document.getElementById("psResultsContent");
    const filterPills = Array.from(document.querySelectorAll(".ps-filter-pill"));
    const filterAllCount = document.getElementById("psFilterAllCount");
    const filterOpenCount = document.getElementById("psFilterOpenCount");
    const filterClosedCount = document.getElementById("psFilterClosedCount");
    const filterFilteredCount = document.getElementById("psFilterFilteredCount");
    const searchInput = document.getElementById("psSearchInput");

    // Modal Details Elements
    const detailsModal = document.getElementById("psDetailsModal");
    const modalCloseBtn = document.getElementById("psModalCloseBtn");
    const modalFooterCloseBtn = document.getElementById("psModalFooterCloseBtn");
    const modalPortBadge = document.getElementById("psModalPortBadge");
    const modalTitle = document.getElementById("psModalTitle");
    const modalBody = document.getElementById("psModalBody");

    let networkInfoPromise = null;
    function loadNetworkInfo() {
      networkInfoPromise = (async () => {
        try {
          const res = await fetch("/api/port-scan/network-info");
          if (!res.ok) return null;
          const data = await res.json();
          if (data.status === "success") {
            autoDetectedSubnet = data.suggested_subnet || "";
            if (currentMode === "network" && targetInput && !targetInput.value && autoDetectedSubnet) {
              targetInput.value = autoDetectedSubnet;
            }
            if (localIpBadge) {
              const isConn = data.is_connected && data.local_ip && !data.local_ip.startsWith("127.");
              const ipLabel = isConn ? data.local_ip : (data.local_ip || "Offline");
              const typeStr = (data.adapter_type && data.adapter_type !== 'None' && data.adapter_type !== 'Other') ? ` (${data.adapter_type})` : '';
              localIpBadge.innerHTML = `<i class="fas fa-circle-dot"></i> Local IP: ${ipLabel}${typeStr}`;
            }
            return data;
          }
        } catch (e) {
          console.warn("Could not load network info for port scanner:", e);
        }
        return null;
      })();
      return networkInfoPromise;
    }

    function switchMode(mode, preserveValue = false) {
      currentMode = mode;
      hideError();

      modeTabs.forEach(tab => {
        if (!tab) return;
        const isActive = tab.getAttribute("data-mode") === mode;
        tab.classList.toggle("active", isActive);
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
      });

      if (kpiCardHosts) {
        kpiCardHosts.style.display = (mode === "network") ? "flex" : "none";
      }

      if (!targetInput) return;

      if (mode === "localhost") {
        targetInput.value = "127.0.0.1";
        targetInput.readOnly = true;
        targetInput.placeholder = "127.0.0.1";
        if (targetHint) targetHint.textContent = "Loopback interface strictly locked for local inspection.";
        if (autoSubnetBtn) autoSubnetBtn.style.display = "none";
        if (authWrap) authWrap.style.display = "none";
      } else if (mode === "target_ip") {
        if (!preserveValue) {
          targetInput.value = "";
        }
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

    // Conservative, explainable exposure analysis rules (Zero vulnerability fabrication)
    function getExposureAnalysis(port, protocol, service, banner) {
      const p = parseInt(port, 10);
      if (p === 21) {
        return {
          level: "medium",
          badgeClass: "exposure-medium",
          label: "Plaintext FTP",
          category: "File Transfer",
          icon: "fa-triangle-exclamation",
          recommendation: "FTP transmits credentials and file data in cleartext. Consider migrating to SFTP (SSH) or FTPS (TLS).",
          riskText: "Cleartext credentials risk on shared/untrusted network segments."
        };
      }
      if (p === 23) {
        return {
          level: "high",
          badgeClass: "exposure-high",
          label: "Legacy Telnet",
          category: "Remote Access",
          icon: "fa-triangle-exclamation",
          recommendation: "Telnet is an obsolete unencrypted protocol. Replace with SSH (port 22) immediately.",
          riskText: "High exposure: all session keystrokes and credentials pass in cleartext."
        };
      }
      if (p === 80 || p === 8080 || p === 8000) {
        return {
          level: "low",
          badgeClass: "exposure-low",
          label: "Plaintext HTTP",
          category: "Web Server",
          icon: "fa-circle-info",
          recommendation: "Standard web port without TLS. For confidential forms or user data, configure HTTPS on port 443.",
          riskText: "Traffic unencrypted; suitable for public landing pages, insecure for sensitive authentication."
        };
      }
      if (p === 22) {
        return {
          level: "info",
          badgeClass: "exposure-info",
          label: "Encrypted SSH",
          category: "Remote Terminal",
          icon: "fa-lock",
          recommendation: "SSH encrypted terminal. Ensure public-key authentication is enforced and root login is disabled.",
          riskText: "Administrative terminal. Restrict source IPs or rate limit to prevent credential brute-forcing."
        };
      }
      if (p === 3389) {
        return {
          level: "medium",
          badgeClass: "exposure-medium",
          label: "Microsoft RDP",
          category: "Remote Desktop",
          icon: "fa-display",
          recommendation: "Limit RDP reachability to corporate VPN or bastion host with Multi-Factor Authentication (MFA).",
          riskText: "Frequent target of automated network brute force and credential-stuffing attacks."
        };
      }
      if (p === 445 || p === 139 || p === 135) {
        return {
          level: "medium",
          badgeClass: "exposure-medium",
          label: "SMB / RPC Endpoint",
          category: "Windows Infrastructure",
          icon: "fa-network-wired",
          recommendation: "Do not expose SMB or RPC directly to untrusted or external networks. Restrict via firewall.",
          riskText: "Internal network protocol prone to lateral movement and relay attacks if exposed."
        };
      }
      if ([1433, 1521, 3306, 5432, 6379, 27017, 9200].includes(p)) {
        return {
          level: "medium",
          badgeClass: "exposure-medium",
          label: "Database Service",
          category: "Data Store",
          icon: "fa-database",
          recommendation: "Ensure database listening port is restricted to backend application subnets and uses TLS + strong auth.",
          riskText: "Internal data tier component; external internet access should be strictly blocked."
        };
      }
      if ([443, 8443, 990, 993, 995, 636].includes(p)) {
        return {
          level: "safe",
          badgeClass: "exposure-safe",
          label: "Encrypted TLS",
          category: "Secure Channel",
          icon: "fa-shield-halved",
          recommendation: "Transport layer security active. Verify TLS version and certificate renewal periodically.",
          riskText: "Standard secure transport channel."
        };
      }
      return {
        level: "neutral",
        badgeClass: "exposure-neutral",
        label: "Standard Service",
        category: "Network Service",
        icon: "fa-server",
        recommendation: "Standard network service endpoint. Maintain current patches and standard access control.",
        riskText: "Standard service exposure."
      };
    }

    // Sort helper
    function sortPorts(portsList) {
      if (!portsList) return [];
      const list = [...portsList];
      const dir = (sortDirection === "desc") ? -1 : 1;

      list.sort((a, b) => {
        if (sortField === "port") {
          return (Number(a.port) - Number(b.port)) * dir;
        }
        if (sortField === "state") {
          const rank = { "open": 1, "filtered": 2, "closed": 3, "error": 4 };
          const ra = rank[a.state] || 5;
          const rb = rank[b.state] || 5;
          if (ra !== rb) return (ra - rb) * dir;
          return (Number(a.port) - Number(b.port));
        }
        if (sortField === "service") {
          const sa = (a.service || "").toLowerCase();
          const sb = (b.service || "").toLowerCase();
          return sa.localeCompare(sb) * dir;
        }
        if (sortField === "latency") {
          const la = (a.latency_ms !== null && a.latency_ms !== undefined) ? Number(a.latency_ms) : 999999;
          const lb = (b.latency_ms !== null && b.latency_ms !== undefined) ? Number(b.latency_ms) : 999999;
          return (la - lb) * dir;
        }
        return 0;
      });
      return list;
    }

    function showPortDetailsModal(p, hostContext = {}) {
      if (!detailsModal || !modalBody) return;
      selectedPortDetail = { port: p, host: hostContext };

      const proto = p.protocol || "TCP";
      const analysis = getExposureAnalysis(p.port, proto, p.service, p.banner);
      const hostIp = hostContext.host || (targetInput ? targetInput.value : "127.0.0.1");
      const hostName = hostContext.hostname && hostContext.hostname !== hostIp ? ` (${hostContext.hostname})` : "";
      const latencyStr = (p.latency_ms !== null && p.latency_ms !== undefined) ? `${p.latency_ms} ms` : "N/A";

      let stateText = "Open — TCP Handshake Established";
      let stateBadgeClass = "state-open";
      let stateIcon = "fa-circle-check";
      if (p.state === "closed") {
        stateText = "Closed — TCP RST (Connection Refused)";
        stateBadgeClass = "state-closed";
        stateIcon = "fa-circle-xmark";
      } else if (p.state === "filtered") {
        stateText = "Filtered — Timeout (No Response)";
        stateBadgeClass = "state-filtered";
        stateIcon = "fa-circle-exclamation";
      } else if (p.state === "error") {
        stateText = "Error — Network Stack / Socket Exception";
        stateBadgeClass = "state-error";
        stateIcon = "fa-triangle-exclamation";
      }

      if (modalPortBadge) modalPortBadge.textContent = `Port ${p.port} / ${proto}`;
      if (modalTitle) modalTitle.textContent = `${escapeHtml(p.service || "Unknown")} Service`;

      modalBody.innerHTML = `
        <div class="ps-modal-grid">
          <div class="ps-modal-field">
            <span class="ps-field-label">Port State &amp; Method</span>
            <span class="ps-field-value">
              <span class="ps-state-tag ${stateBadgeClass}">
                <i class="fas ${stateIcon}"></i> ${escapeHtml(p.state || "closed").toUpperCase()}
              </span>
            </span>
          </div>
          <div class="ps-modal-field">
            <span class="ps-field-label">Observed Latency (RTT)</span>
            <span class="ps-field-value font-mono">${latencyStr}</span>
          </div>
          <div class="ps-modal-field">
            <span class="ps-field-label">Target Host</span>
            <span class="ps-field-value font-mono">${escapeHtml(hostIp)}${escapeHtml(hostName)}</span>
          </div>
          <div class="ps-modal-field">
            <span class="ps-field-label">Transport Protocol</span>
            <span class="ps-field-value font-mono">${escapeHtml(proto)} Stream Socket</span>
          </div>
        </div>

        <div class="ps-modal-card">
          <div class="ps-modal-card-title">
            <i class="fas fa-tag text-accent"></i> Service Identification
          </div>
          <p class="ps-modal-card-desc">
            <strong>Service Name:</strong> ${escapeHtml(p.service || "Unknown")}<br />
            <strong>Identification Source:</strong> ${escapeHtml(p.service_source || "Standard Port Mapping (Well-Known Registry)")}
          </p>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-top:4px;">
            Note: Service name is mapped from official IANA and well-known service registries. Successful TCP connection indicates the host network stack accepts traffic on this port.
          </div>
        </div>

        <div class="ps-modal-card">
          <div class="ps-modal-card-title">
            <i class="fas fa-terminal text-accent"></i> Service Banner / Interrogation Response
          </div>
          ${p.banner ? `
            <div class="ps-banner-terminal">
              <code>${escapeHtml(p.banner)}</code>
              <button type="button" class="ps-banner-copy-btn" id="psBannerCopyBtn" title="Copy Banner">
                <i class="fas fa-copy"></i> Copy
              </button>
            </div>
          ` : `
            <p class="ps-modal-card-desc text-muted">
              <em>No application greeting banner or HTTP response header was returned by the remote service within the timeout window.</em>
            </p>
          `}
        </div>

        <div class="ps-modal-card">
          <div class="ps-modal-card-title">
            <i class="fas ${analysis.icon} text-accent"></i> Exposure Classification &amp; Operational Considerations
          </div>
          <div style="margin-bottom:6px;">
            <span class="ps-exposure-tag ${analysis.badgeClass}">
              <i class="fas ${analysis.icon}"></i> ${escapeHtml(analysis.label)} (${escapeHtml(analysis.category)})
            </span>
          </div>
          <p class="ps-modal-card-desc">
            ${escapeHtml(analysis.recommendation)}
          </p>
          <div style="font-size:0.75rem;color:var(--text-muted);margin-top:6px;">
            <strong>Exposure Context:</strong> ${escapeHtml(analysis.riskText)}
          </div>
        </div>
      `;

      // Wire copy button
      const copyBtn = modalBody.querySelector("#psBannerCopyBtn");
      if (copyBtn) {
        copyBtn.addEventListener("click", () => {
          navigator.clipboard.writeText(p.banner || "").then(() => {
            copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(() => {
              copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copy';
            }, 1800);
          }).catch(() => {});
        });
      }

      detailsModal.style.display = "flex";
      document.body.style.overflow = "hidden";
    }

    function closePortDetailsModal() {
      if (detailsModal) {
        detailsModal.style.display = "none";
        document.body.style.overflow = "";
      }
      selectedPortDetail = null;
    }

    async function startScan() {
      if (isPortScanning) return;
      hideError();

      let target = (targetInput ? targetInput.value : "").trim();
      if (!target && currentMode === "network" && networkInfoPromise) {
        await networkInfoPromise;
        target = (targetInput ? targetInput.value : "").trim();
        if (!target && autoDetectedSubnet) {
          target = autoDetectedSubnet;
          if (targetInput) targetInput.value = target;
        }
      }
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
          showError("Please enter one or more custom ports (e.g. 80, 443, 8080, 3000-3005).");
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
      if (kpiCardHosts) kpiCardHosts.style.display = (currentMode === "network") ? "flex" : "none";
      if (kpiScanned) kpiScanned.textContent = "0";
      if (kpiOpen) kpiOpen.textContent = "0";
      if (kpiClosed) kpiClosed.textContent = "0";
      if (kpiFiltered) kpiFiltered.textContent = "0";
      if (kpiDuration) kpiDuration.textContent = "0.0s";
      if (kpiHosts) kpiHosts.textContent = "0";

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

        if (data.status === "already_scanning") {
          showError(`A port scan is already running on ${data.target || "another target"}. Stop it or wait for completion before scanning ${target}.`);
          checkAndAttachActivePortScan();
          return;
        }

        if (portScanPollTimer) clearInterval(portScanPollTimer);
        portScanPollTimer = setInterval(pollScanStatus, 350);
        pollScanStatus();

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

        // Accurate live KPI counters
        const scannedCount = data.scanned_ports || 0;
        const totalCount = data.total_ports || 0;
        const displayScanned = (status === "scanning" && totalCount > 0) ? `${scannedCount} / ${totalCount}` : `${scannedCount}`;

        if (kpiScanned) kpiScanned.textContent = displayScanned;
        if (kpiOpen) updateTelemetryCounter(kpiOpen, data.open_ports_count || 0);
        if (kpiClosed) updateTelemetryCounter(kpiClosed, data.closed_ports_count || 0);
        if (kpiFiltered) updateTelemetryCounter(kpiFiltered, data.filtered_ports_count || 0);
        if (kpiDuration) kpiDuration.textContent = `${(data.duration_s || 0).toFixed(1)}s`;
        if (kpiHosts) updateTelemetryCounter(kpiHosts, data.active_hosts_count || 0);

        // Render live interim results only when Port Scanner section is currently visible
        const isScannerVisible = document.body.classList.contains("dedicated-mode-port-scanner");
        if (isScannerVisible && data.results && data.results.length > 0) {
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

          if (isScannerVisible && data.results && data.results.length > 0) {
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

    // Lifecycle reconnection: attaches to active scan or renders last completed scan
    async function checkAndAttachActivePortScan() {
      try {
        const res = await fetch("/api/port-scan/status");
        if (!res.ok) return;
        const data = await res.json();
        lastScanData = data;

        if (data.status === "scanning") {
          isPortScanning = true;
          setBadge("scanning", "Scanning...");
          if (startBtn) {
            startBtn.disabled = true;
            startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Scanning...</span>';
          }
          if (stopBtn) stopBtn.style.display = "inline-flex";
          if (progressBox) {
            progressBox.style.display = "block";
            progressBox.classList.add("ps-scanning");
          }
          if (kpiGrid) kpiGrid.style.display = "grid";
          if (kpiCardHosts) kpiCardHosts.style.display = (data.scan_type === "network") ? "flex" : "none";
          if (data.results && data.results.length > 0) {
            renderResults(data.results);
          }
          if (portScanPollTimer) clearInterval(portScanPollTimer);
          portScanPollTimer = setInterval(pollScanStatus, 350);
        } else if (data.status === "completed" && data.results && data.results.length > 0) {
          setBadge("completed", "Completed");
          if (kpiGrid) kpiGrid.style.display = "grid";
          if (kpiCardHosts) kpiCardHosts.style.display = (data.scan_type === "network") ? "flex" : "none";
          if (kpiScanned) kpiScanned.textContent = `${data.scanned_ports || 0}`;
          if (kpiOpen) kpiOpen.textContent = `${data.open_ports_count || 0}`;
          if (kpiClosed) kpiClosed.textContent = `${data.closed_ports_count || 0}`;
          if (kpiFiltered) kpiFiltered.textContent = `${data.filtered_ports_count || 0}`;
          if (kpiDuration) kpiDuration.textContent = `${(data.duration_s || 0).toFixed(1)}s`;
          if (kpiHosts) kpiHosts.textContent = `${data.active_hosts_count || 0}`;
          if (rescanBtn) rescanBtn.style.display = "inline-flex";
          if (exportGroup) exportGroup.style.display = "inline-flex";
          if (resultsTimestamp && timestampText && data.completed_at_str) {
            timestampText.textContent = `Last scanned at ${data.completed_at_str}`;
            resultsTimestamp.style.display = "inline-flex";
          }
          renderResults(data.results);
        }
      } catch (e) {
        console.warn("Could not check port scan status on attach:", e);
      }
    }

    function reconcilePortsTable(container, ports, hostContext = {}) {
      if (!container) return;
      if (!ports || ports.length === 0) {
        let emptyState = container.querySelector(".ps-empty-state");
        const tableWrap = container.querySelector(".ps-table-responsive-wrap");
        if (tableWrap) tableWrap.remove();
        if (!emptyState) {
          emptyState = document.createElement("div");
          emptyState.className = "ps-empty-state";
          emptyState.innerHTML = '<i class="fas fa-shield-halved"></i>No ports matching the current criteria in this category.';
          container.appendChild(emptyState);
        }
        return;
      }

      const emptyState = container.querySelector(".ps-empty-state");
      if (emptyState) emptyState.remove();

      let tableWrap = container.querySelector(".ps-table-responsive-wrap");
      if (!tableWrap) {
        tableWrap = document.createElement("div");
        tableWrap.className = "ps-table-responsive-wrap";
        tableWrap.innerHTML = `
          <table class="ps-table">
            <thead>
              <tr>
                <th class="sortable-th" data-sort="port" title="Click to sort by Port">
                  Port <i class="fas fa-sort sort-icon"></i>
                </th>
                <th>Protocol</th>
                <th class="sortable-th" data-sort="state" title="Click to sort by State">
                  State <i class="fas fa-sort sort-icon"></i>
                </th>
                <th class="sortable-th" data-sort="service" title="Click to sort by Service">
                  Service &amp; Source <i class="fas fa-sort sort-icon"></i>
                </th>
                <th>Version / Interrogation</th>
                <th class="sortable-th" data-sort="latency" title="Click to sort by Latency">
                  Latency <i class="fas fa-sort sort-icon"></i>
                </th>
                <th>Exposure</th>
                <th style="text-align:right;">Actions</th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        `;
        container.appendChild(tableWrap);

        // Wire sortable table headers
        tableWrap.querySelectorAll("th.sortable-th").forEach(th => {
          th.addEventListener("click", () => {
            const field = th.getAttribute("data-sort");
            if (sortField === field) {
              sortDirection = (sortDirection === "asc") ? "desc" : "asc";
            } else {
              sortField = field;
              sortDirection = "asc";
            }
            if (lastScanData && lastScanData.results) {
              renderResults(lastScanData.results);
            }
          });
        });
      }

      // Update header sort indicator icons
      tableWrap.querySelectorAll("th.sortable-th").forEach(th => {
        const field = th.getAttribute("data-sort");
        const icon = th.querySelector(".sort-icon");
        th.classList.remove("sorted-asc", "sorted-desc");
        if (icon) {
          icon.className = "fas fa-sort sort-icon";
        }
        if (field === sortField) {
          th.classList.add(sortDirection === "asc" ? "sorted-asc" : "sorted-desc");
          if (icon) {
            icon.className = `fas fa-sort-${sortDirection === "asc" ? "up" : "down"} sort-icon`;
          }
        }
      });

      const tbody = tableWrap.querySelector("tbody");
      if (!tbody) return;

      const sorted = sortPorts(ports);
      const currentKeys = new Set(sorted.map(p => `${p.port}_${p.protocol || "TCP"}`));

      // Remove rows no longer present
      tbody.querySelectorAll("tr[data-port]").forEach(tr => {
        const key = `${tr.getAttribute("data-port")}_${tr.getAttribute("data-proto")}`;
        if (!currentKeys.has(key)) {
          tr.remove();
        }
      });

      sorted.forEach((p, idx) => {
        const proto = p.protocol || "TCP";
        const stateClass = p.state === "open" ? "state-open" : (p.state === "filtered" ? "state-filtered" : (p.state === "error" ? "state-error" : "state-closed"));
        const stateIcon = p.state === "open" ? "fa-circle-check" : (p.state === "filtered" ? "fa-circle-exclamation" : (p.state === "error" ? "fa-triangle-exclamation" : "fa-circle-xmark"));
        const latencyText = (p.latency_ms !== null && p.latency_ms !== undefined) ? `${p.latency_ms} ms` : "--";
        const bannerHtml = p.banner ? `<code class="ps-banner-code" title="${escapeHtml(p.banner)}">${escapeHtml(p.banner)}</code>` : '<span class="text-muted">--</span>';
        const sourceHtml = `<span class="ps-source-tag"><i class="fas fa-tag"></i> ${escapeHtml(p.service_source || "Standard Port Mapping")}</span>`;
        const analysis = getExposureAnalysis(p.port, proto, p.service, p.banner);
        const exposureHtml = `<span class="ps-exposure-tag ${analysis.badgeClass}" title="${escapeHtml(analysis.recommendation)}"><i class="fas ${analysis.icon}"></i> ${escapeHtml(analysis.label)}</span>`;
        const portSig = `${p.state}|${p.service}|${p.service_source}|${p.banner}|${p.latency_ms}|${sortField}|${sortDirection}`;

        let tr = tbody.querySelector(`tr[data-port="${p.port}"][data-proto="${proto}"]`);
        if (!tr) {
          tr = document.createElement("tr");
          tr.setAttribute("data-port", String(p.port));
          tr.setAttribute("data-proto", proto);
          tr.setAttribute("data-sig", portSig);
          tr.style.animationDelay = `${Math.min(idx * 22, 350)}ms`;
          tr.innerHTML = `
            <td class="ps-port-num">${p.port}</td>
            <td><span class="ps-proto-tag">${proto}</span></td>
            <td>
              <span class="ps-state-tag ${stateClass}">
                <i class="fas ${stateIcon}"></i> ${(p.state || "closed").toUpperCase()}
              </span>
            </td>
            <td>
              <div class="ps-service-col">
                <span class="ps-service-name">${escapeHtml(p.service || "Unknown")}</span>
                ${sourceHtml}
              </div>
            </td>
            <td>${bannerHtml}</td>
            <td style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-muted);">${latencyText}</td>
            <td>${exposureHtml}</td>
            <td style="text-align:right;">
              <button type="button" class="ps-action-btn" title="Inspect Service Details">
                <i class="fas fa-circle-info"></i> Details
              </button>
            </td>
          `;
          tbody.appendChild(tr);
        } else {
          if (tr.getAttribute("data-sig") !== portSig) {
            tr.setAttribute("data-sig", portSig);
            tr.innerHTML = `
              <td class="ps-port-num">${p.port}</td>
              <td><span class="ps-proto-tag">${proto}</span></td>
              <td>
                <span class="ps-state-tag ${stateClass}">
                  <i class="fas ${stateIcon}"></i> ${(p.state || "closed").toUpperCase()}
                </span>
              </td>
              <td>
                <div class="ps-service-col">
                  <span class="ps-service-name">${escapeHtml(p.service || "Unknown")}</span>
                  ${sourceHtml}
                </div>
              </td>
              <td>${bannerHtml}</td>
              <td style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-muted);">${latencyText}</td>
              <td>${exposureHtml}</td>
              <td style="text-align:right;">
                <button type="button" class="ps-action-btn" title="Inspect Service Details">
                  <i class="fas fa-circle-info"></i> Details
                </button>
              </td>
            `;
          }
          tbody.appendChild(tr);
        }

        // Action button click
        const btn = tr.querySelector(".ps-action-btn");
        if (btn && !btn._hasClickListener) {
          btn._hasClickListener = true;
          btn.addEventListener("click", (e) => {
            e.stopPropagation();
            showPortDetailsModal(p, hostContext);
          });
        }
      });
    }

    function renderResults(hosts) {
      if (!resultsWrapper || !resultsContent) return;
      resultsWrapper.style.display = "block";

      // Compute total counts accurately
      let totalOpen = 0;
      let totalClosed = 0;
      let totalFiltered = 0;
      let totalAll = 0;

      hosts.forEach(h => {
        const allList = (h.all_ports && h.all_ports.length > 0) ? h.all_ports : (h.open_ports || []);
        totalAll += allList.length;
        allList.forEach(p => {
          if (p.state === "open") totalOpen++;
          else if (p.state === "closed") totalClosed++;
          else if (p.state === "filtered" || p.state === "error") totalFiltered++;
        });
      });

      if (filterAllCount) filterAllCount.textContent = totalAll;
      if (filterOpenCount) filterOpenCount.textContent = totalOpen;
      if (filterClosedCount) filterClosedCount.textContent = totalClosed;
      if (filterFilteredCount) filterFilteredCount.textContent = totalFiltered;

      const q = searchQuery.toLowerCase().trim();

      // Filter ports based on active tab ('all', 'open', 'closed', 'filtered')
      function passesStateFilter(p) {
        if (activeFilter === "all") return true;
        if (activeFilter === "open") return p.state === "open";
        if (activeFilter === "closed") return p.state === "closed";
        if (activeFilter === "filtered") return p.state === "filtered" || p.state === "error";
        return true;
      }

      function passesSearchQuery(p) {
        if (!q) return true;
        return String(p.port).includes(q) ||
               (p.service || "").toLowerCase().includes(q) ||
               (p.service_source || "").toLowerCase().includes(q) ||
               (p.banner || "").toLowerCase().includes(q);
      }

      // Render based on scan mode
      if (currentMode === "network") {
        const singleCard = resultsContent.querySelector(".ps-table-card");
        if (singleCard) singleCard.remove();

        const currentHostIps = new Set(hosts.map(h => h.host));

        resultsContent.querySelectorAll(".ps-host-card").forEach(card => {
          const hostIp = card.getAttribute("data-host");
          if (!currentHostIps.has(hostIp)) {
            card.remove();
          }
        });

        if (hosts.length === 0) {
          let emptyState = resultsContent.querySelector(".ps-empty-state");
          if (!emptyState) {
            resultsContent.innerHTML = `<div class="ps-empty-state"><i class="fas fa-search"></i>No hosts or ports match the current filter.</div>`;
          }
          return;
        }

        const globalEmpty = resultsContent.querySelector(":scope > .ps-empty-state");
        if (globalEmpty) globalEmpty.remove();

        hosts.forEach((h, idx) => {
          const allList = (h.all_ports && h.all_ports.length > 0) ? h.all_ports : (h.open_ports || []);
          const filteredPorts = allList.filter(p => passesStateFilter(p) && passesSearchQuery(p));

          const isOpenByDefault = (idx === 0) || (h.open_ports && h.open_ports.length > 0);
          const openBadgeClass = (h.open_ports_count > 0) ? "ps-state-tag state-open" : "ps-state-tag state-closed";
          const openIconClass = (h.open_ports_count > 0) ? "fa-circle-check" : "fa-circle-xmark";

          let hostCard = resultsContent.querySelector(`.ps-host-card[data-host="${escapeHtml(h.host)}"]`);

          if (!hostCard) {
            hostCard = document.createElement("div");
            hostCard.className = `ps-host-card ${isOpenByDefault ? "open" : ""}`;
            hostCard.setAttribute("data-host", h.host);
            hostCard.innerHTML = `
              <div class="ps-host-header">
                <div class="ps-host-title">
                  <span class="ps-host-ip"><i class="fas fa-server"></i> ${escapeHtml(h.host)}</span>
                  ${h.hostname && h.hostname !== h.host ? `<span class="ps-host-name">(${escapeHtml(h.hostname)})</span>` : ""}
                </div>
                <div class="ps-host-meta">
                  <span class="${openBadgeClass}">
                    <i class="fas ${openIconClass}"></i>
                    <span class="ps-host-open-count">${h.open_ports_count} Open</span>
                  </span>
                  <i class="fas fa-chevron-down ps-chevron"></i>
                </div>
              </div>
              <div class="ps-host-body"></div>
            `;
            resultsContent.appendChild(hostCard);
          } else {
            const metaTag = hostCard.querySelector(".ps-host-meta .ps-state-tag");
            if (metaTag) {
              metaTag.className = openBadgeClass;
              metaTag.innerHTML = `<i class="fas ${openIconClass}"></i> <span class="ps-host-open-count">${h.open_ports_count} Open</span>`;
            }
            const hostTitle = hostCard.querySelector(".ps-host-title");
            if (hostTitle) {
              const nameSpan = h.hostname && h.hostname !== h.host ? `<span class="ps-host-name">(${escapeHtml(h.hostname)})</span>` : "";
              hostTitle.innerHTML = `<span class="ps-host-ip"><i class="fas fa-server"></i> ${escapeHtml(h.host)}</span>${nameSpan}`;
            }
            resultsContent.appendChild(hostCard);
          }

          const hostBody = hostCard.querySelector(".ps-host-body");
          reconcilePortsTable(hostBody, filteredPorts, h);
        });

      } else {
        // Single host table (Localhost or Target IP)
        resultsContent.querySelectorAll(".ps-host-card").forEach(c => c.remove());
        const globalEmpty = resultsContent.querySelector(":scope > .ps-empty-state");
        if (globalEmpty) globalEmpty.remove();

        const host = hosts[0] || {};
        const allList = (host.all_ports && host.all_ports.length > 0) ? host.all_ports : (host.open_ports || []);
        const filteredPorts = allList.filter(p => passesStateFilter(p) && passesSearchQuery(p));

        let tableCard = resultsContent.querySelector(".ps-table-card");
        if (!tableCard) {
          tableCard = document.createElement("div");
          tableCard.className = "ps-table-card";
          resultsContent.appendChild(tableCard);
        }

        reconcilePortsTable(tableCard, filteredPorts, host);
      }
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
        let csv = "Host,Hostname,Port,Protocol,State,Service,ServiceSource,Banner,LatencyMs,ExposureClassification,Recommendation\n";
        lastScanData.results.forEach(h => {
          const ports = (h.all_ports && h.all_ports.length > 0) ? h.all_ports : (h.open_ports || []);
          ports.forEach(p => {
            const cleanBanner = (p.banner || "").replace(/"/g, '""');
            const cleanService = (p.service || "").replace(/"/g, '""');
            const cleanSource = (p.service_source || "").replace(/"/g, '""');
            const proto = p.protocol || "TCP";
            const analysis = getExposureAnalysis(p.port, proto, p.service, p.banner);
            const cleanLabel = (analysis.label || "").replace(/"/g, '""');
            const cleanRec = (analysis.recommendation || "").replace(/"/g, '""');

            csv += `"${h.host}","${h.hostname || ""}","${p.port}","${proto}","${p.state}","${cleanService}","${cleanSource}","${cleanBanner}","${p.latency_ms || ""}","${cleanLabel}","${cleanRec}"\n`;
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
      checkAndAttachActivePortScan();

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
        autoSubnetBtn.addEventListener("click", async () => {
          if (!autoDetectedSubnet && networkInfoPromise) {
            await networkInfoPromise;
          }
          if (targetInput && autoDetectedSubnet) {
            targetInput.value = autoDetectedSubnet;
            hideError();
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
          activeFilter = pill.getAttribute("data-filter") || "all";
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

      // Modal close handlers
      if (modalCloseBtn) modalCloseBtn.addEventListener("click", closePortDetailsModal);
      if (modalFooterCloseBtn) modalFooterCloseBtn.addEventListener("click", closePortDetailsModal);
      if (detailsModal) {
        detailsModal.addEventListener("click", (e) => {
          if (e.target === detailsModal) closePortDetailsModal();
        });
      }
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && detailsModal && detailsModal.style.display === "flex") {
          closePortDetailsModal();
        }
      });

      // Delegated Accordion Toggle for Host Cards
      if (resultsContent) {
        resultsContent.addEventListener("click", (e) => {
          const header = e.target.closest(".ps-host-header");
          if (header && !e.target.closest(".ps-action-btn")) {
            const card = header.closest(".ps-host-card");
            if (card) {
              card.classList.toggle("open");
            }
          }
        });
      }

      // Check URL parameters and session triggers (e.g. from Network Discovery Scan Ports action)
      handleIncomingTarget();
    }

    // Helper: Validate target IP or hostname strictly
    function isValidTargetAddress(addr) {
      if (!addr || typeof addr !== "string") return false;
      const clean = addr.trim();
      if (!clean || clean === "Unavailable" || clean === "Unknown" || clean === "N/A" || clean === "Not detected") {
        return false;
      }
      // IPv4 check: 4 octets 0-255
      const octets = clean.split(".");
      if (octets.length === 4) {
        const allValid = octets.every(o => {
          if (!/^\d{1,3}$/.test(o)) return false;
          const n = Number(o);
          return n >= 0 && n <= 255;
        });
        if (allValid) return true;
      }
      // Hostname check: alphanumeric, dots, hyphens
      if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(clean)) {
        return true;
      }
      return false;
    }

    // Handles incoming target from Network Discovery, URL parameters, or navigation state
    async function handleIncomingTarget() {
      let targetParam = "";
      let triggerParam = "";

      try {
        const urlParams = new URLSearchParams(window.location.search);
        targetParam = (urlParams.get("target") || "").trim();
        triggerParam = (urlParams.get("trigger") || "").trim();
      } catch (e) {
        targetParam = "";
      }

      // Check one-time auto-trigger session token from Network Discovery Scan Port action
      let autoTrigger = null;
      try {
        const raw = sessionStorage.getItem("port_scan_auto_trigger");
        if (raw) {
          autoTrigger = JSON.parse(raw);
          // Consume immediately so it never re-fires on page refresh (F5)!
          sessionStorage.removeItem("port_scan_auto_trigger");
        }
      } catch (e) {
        autoTrigger = null;
      }

      // Clean the trigger from URL history state immediately so refresh (F5) does not re-run auto-scan!
      try {
        const cleanParams = new URLSearchParams(window.location.search);
        if (cleanParams.has("trigger")) {
          cleanParams.delete("trigger");
          const cleanQuery = cleanParams.toString() ? `?${cleanParams.toString()}` : "";
          window.history.replaceState({ view: "port-scanner" }, "", `${window.location.pathname}${cleanQuery}`);
        }
      } catch (e) {
        // ignore history state errors
      }

      if (!targetParam && autoTrigger && autoTrigger.ip) {
        targetParam = autoTrigger.ip.trim();
      }

      if (!targetParam) {
        // Normal direct navigation: check and reconnect to any already active or completed scan
        checkAndAttachActivePortScan();
        return;
      }

      // Determine if auto-scan should be triggered:
      // STRICT REQUIREMENT: Auto-scan is permitted ONLY when triggered by an explicit Scan Port click
      // verified by a fresh one-time autoTrigger token. Stale navigation state, normal navigation,
      // and page refresh must NEVER start an auto-scan!
      const isFreshTrigger = Boolean(
        autoTrigger &&
        autoTrigger.ip &&
        (Date.now() - (autoTrigger.timestamp || 0) < 15000) &&
        (!targetParam || targetParam === autoTrigger.ip)
      );
      const isAutoScanRequested = isFreshTrigger;

      // Validate target address
      if (!isValidTargetAddress(targetParam)) {
        switchMode("target_ip", false);
        if (targetInput) targetInput.value = targetParam;
        showError(`Invalid target IP address: '${targetParam || "Unknown"}'. Please enter a valid IPv4 address.`);
        return;
      }

      // Set mode to target_ip, preserve value, and populate field
      switchMode("target_ip", true);
      if (targetInput) {
        targetInput.value = targetParam;
      }

      // Scroll into view
      const scannerSec = document.getElementById("port-scanner") || document.getElementById("portScannerSection");
      if (scannerSec) {
        setTimeout(() => scannerSec.scrollIntoView({ behavior: "smooth" }), 150);
      }

      if (isAutoScanRequested) {
        // Verify not already scanning and not already pending dispatch
        if (isPortScanning || isAutoScanPending) {
          return;
        }
        isAutoScanPending = true;
        // Small delay to ensure DOM and view styles are settled
        setTimeout(() => {
          isAutoScanPending = false;
          startScan();
        }, 120);
      } else {
        // If not an auto-scan (e.g. user refreshed while keeping target in URL, or normal navigation),
        // check/attach to an already active scan, or retain idle state
        checkAndAttachActivePortScan();
      }
    }

    function scanTarget(ip, autoStart = true) {
      if (!isValidTargetAddress(ip)) {
        showError(`Cannot scan target: '${ip || "Unknown"}' is not a valid IPv4 address.`);
        return;
      }
      switchMode("target_ip", true);
      if (targetInput) targetInput.value = ip;
      if (autoStart && !isPortScanning) {
        startScan();
      }
    }

    return {
      init,
      startScan,
      stopScan,
      scanTarget,
      handleIncomingTarget,
      checkAndAttachActivePortScan,
      showPortDetailsModal,
      closePortDetailsModal
    };
  })();
  window.PortScannerUI = PortScannerUI;

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
      const nodeRgb = isDark ? "163, 230, 53" : "101, 163, 13";

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

  function initThreatIntelVideo() {
    const video = document.getElementById("threatIntelBgVideo");
    if (!video) return;

    // Strict muted and volume zero enforcement
    video.muted = true;
    video.volume = 0;
    video.removeAttribute("controls");

    video.addEventListener("volumechange", () => {
      if (!video.muted || video.volume > 0) {
        video.muted = true;
        video.volume = 0;
      }
    });

    // Respect prefers-reduced-motion
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      try { video.pause(); } catch (e) {}
      return;
    }

    // Autoplay attempt
    const tryPlay = () => {
      video.muted = true;
      video.volume = 0;
      const promise = video.play();
      if (promise !== undefined) {
        promise.catch(() => {
          // Fallback on first user gesture if browser blocks immediate autoplay
          const resumeOnInteract = () => {
            video.muted = true;
            video.volume = 0;
            video.play().catch(() => {});
            document.removeEventListener("click", resumeOnInteract);
            document.removeEventListener("touchstart", resumeOnInteract);
            document.removeEventListener("keydown", resumeOnInteract);
          };
          document.addEventListener("click", resumeOnInteract, { once: true, passive: true });
          document.addEventListener("touchstart", resumeOnInteract, { once: true, passive: true });
          document.addEventListener("keydown", resumeOnInteract, { once: true, passive: true });
        });
      }
    };

    tryPlay();

    // IntersectionObserver to pause when scrolled out of view and resume when visible
    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting && !document.hidden) {
            if (video.paused) {
              video.muted = true;
              video.volume = 0;
              video.play().catch(() => {});
            }
          } else {
            if (!video.paused) {
              video.pause();
            }
          }
        });
      }, { threshold: 0.05 });

      const section = video.closest(".threat-intel-section");
      if (section) observer.observe(section);
    }

    // Visibility change handling (tab inactive)
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        if (!video.paused) video.pause();
      } else {
        const section = video.closest(".threat-intel-section");
        if (section) {
          const rect = section.getBoundingClientRect();
          if (rect.top < window.innerHeight && rect.bottom > 0) {
            video.muted = true;
            video.volume = 0;
            video.play().catch(() => {});
          }
        }
      }
    });
  }

  function initDefensiveVideo() {
    const video = document.getElementById("defensiveBgVideo");
    if (!video) return;

    // Strict muted and volume zero enforcement
    video.muted = true;
    video.volume = 0;
    video.removeAttribute("controls");

    video.addEventListener("volumechange", () => {
      if (!video.muted || video.volume > 0) {
        video.muted = true;
        video.volume = 0;
      }
    });

    // Respect prefers-reduced-motion
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      try { video.pause(); } catch (e) {}
      return;
    }

    // Autoplay attempt
    const tryPlay = () => {
      video.muted = true;
      video.volume = 0;
      const promise = video.play();
      if (promise !== undefined) {
        promise.catch(() => {
          // Fallback on first user gesture if browser blocks immediate autoplay
          const resumeOnInteract = () => {
            video.muted = true;
            video.volume = 0;
            video.play().catch(() => {});
            document.removeEventListener("click", resumeOnInteract);
            document.removeEventListener("touchstart", resumeOnInteract);
            document.removeEventListener("keydown", resumeOnInteract);
          };
          document.addEventListener("click", resumeOnInteract, { once: true, passive: true });
          document.addEventListener("touchstart", resumeOnInteract, { once: true, passive: true });
          document.addEventListener("keydown", resumeOnInteract, { once: true, passive: true });
        });
      }
    };

    tryPlay();

    // IntersectionObserver to pause when scrolled out of view and resume when visible
    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting && !document.hidden) {
            if (video.paused) {
              video.muted = true;
              video.volume = 0;
              video.play().catch(() => {});
            }
          } else {
            if (!video.paused) {
              video.pause();
            }
          }
        });
      }, { threshold: 0.05 });

      const section = video.closest(".prevention-section");
      if (section) observer.observe(section);
    }

    // Visibility change handling (tab inactive)
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        if (!video.paused) video.pause();
      } else {
        const section = video.closest(".prevention-section");
        if (section) {
          const rect = section.getBoundingClientRect();
          if (rect.top < window.innerHeight && rect.bottom > 0) {
            video.muted = true;
            video.volume = 0;
            video.play().catch(() => {});
          }
        }
      }
    });
  }

  // ============================================================================
  // SCOUT Subscription Plans & Admin Management Controller
  // ============================================================================

  // User Profile Dropdown Navigation Links
  if (dropdownDashboardLink) {
    dropdownDashboardLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("dashboard");
    });
  }
  if (dropdownPublicLink) {
    dropdownPublicLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("landing");
    });
  }
  const dropdownPlansLink = document.getElementById("dropdownPlansLink");
  if (dropdownPlansLink) {
    dropdownPlansLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("plans");
    });
  }
  if (dropdownAdminLink) {
    dropdownAdminLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (userDropdownCard) userDropdownCard.style.display = "none";
      switchView("admin");
    });
  }

  // User Dashboard Tool Launch Listeners
  const dashLaunchMonitorBtn = document.getElementById("dashLaunchMonitorBtn");
  if (dashLaunchMonitorBtn) {
    dashLaunchMonitorBtn.addEventListener("click", () => switchView("monitoring"));
  }
  const dashLaunchPortBtn = document.getElementById("dashLaunchPortBtn");
  if (dashLaunchPortBtn) {
    dashLaunchPortBtn.addEventListener("click", () => switchView("port-scanner"));
  }
  const dashLaunchNdBtn = document.getElementById("dashLaunchNdBtn");
  if (dashLaunchNdBtn) {
    dashLaunchNdBtn.addEventListener("click", () => {
      window.location.href = "/network-discovery";
    });
  }
  const dashViewMonitorThreats = document.getElementById("dashViewMonitorThreats");
  if (dashViewMonitorThreats) {
    dashViewMonitorThreats.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("monitoring");
    });
  }

  // User Subscription UI Elements
  const subStatusDot = document.getElementById("subStatusDot");
  const subStatusText = document.getElementById("subStatusText");
  const subStatusTitle = document.getElementById("subStatusTitle");
  const subStatusMessage = document.getElementById("subStatusMessage");
  const subMetaRow = document.getElementById("subMetaRow");
  const subMetaStart = document.getElementById("subMetaStart");
  const subMetaEnd = document.getElementById("subMetaEnd");
  const subMetaTier = document.getElementById("subMetaTier");
  const subAlertBox = document.getElementById("subAlertBox");
  const plansCatalogGrid = document.getElementById("plansCatalogGrid");
  const subUserRole = document.getElementById("subUserRole");

  // Date Formatter Helper
  function formatUtcDate(dateStr) {
    if (!dateStr) return "—";
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
    } catch (_) {
      return dateStr;
    }
  }

  // ============================================================================
  // User Dashboard Mission Control Controller
  // ============================================================================
  async function loadUserDashboard() {
    if (!currentUser) {
      switchView("landing");
      return;
    }

    const opName = document.getElementById("dashOperatorName");
    const avatar = document.getElementById("dashUserAvatar");
    const email = document.getElementById("dashUserEmail");
    const role = document.getElementById("dashUserRole");
    const statusPill = document.getElementById("dashStatusPill");
    const planName = document.getElementById("dashPlanName");
    const countdown = document.getElementById("dashExpirationCountdown");

    const displayName = currentUser.full_name || currentUser.username || "Operator";
    if (opName) opName.textContent = displayName;
    if (avatar) avatar.textContent = displayName.charAt(0).toUpperCase();
    if (email) email.textContent = currentUser.email || "";
    if (role) role.textContent = currentUser.role || "Operator";

    const sub = currentUserSubscription;
    const isAdmin = currentUser.role === "Admin";

    if (isAdmin) {
      if (statusPill) {
        statusPill.className = "dash-status-pill active";
        statusPill.innerHTML = '<span class="status-pulse-dot"></span> System Root Clearance';
      }
      if (planName) planName.textContent = "Enterprise Root (Unlimited)";
      if (countdown) countdown.textContent = "Perpetual Administrator Access";
    } else if (sub && sub.status === "active") {
      if (statusPill) {
        statusPill.className = "dash-status-pill active";
        statusPill.innerHTML = '<span class="status-pulse-dot"></span> Active Clearance';
      }
      if (planName) planName.textContent = (sub.plan && sub.plan.name) || sub.plan_id || "Active Plan";

      let remainingText = "Active";
      if (sub.end_date) {
        try {
          const end = new Date(sub.end_date);
          const now = new Date();
          const diffDays = Math.ceil((end - now) / (1000 * 60 * 60 * 24));
          remainingText = diffDays > 0 ? `${diffDays} Days Remaining` : "Expiring Today";
        } catch (_) {}
      }
      if (countdown) countdown.textContent = remainingText;
    } else if (sub && sub.status === "pending") {
      if (statusPill) {
        statusPill.className = "dash-status-pill pending";
        statusPill.innerHTML = '<span class="status-pulse-dot"></span> Verification Pending';
      }
      if (planName) planName.textContent = (sub.plan && sub.plan.name) || sub.plan_id || "Requested Plan";
      if (countdown) countdown.textContent = "Awaiting Administrator Approval";
    } else {
      if (statusPill) {
        statusPill.className = "dash-status-pill expired";
        statusPill.innerHTML = '<span class="status-pulse-dot"></span> Inactive';
      }
      if (planName) planName.textContent = "No Active Subscription";
      if (countdown) countdown.textContent = "Subscription Required";
    }

    // Entitlement checks for tool launchpad cards
    const features = isAdmin ? {
      can_live_monitoring: true,
      can_port_scan: true,
      can_network_discovery: true
    } : ((sub && sub.status === "active" && sub.plan && sub.plan.features) || {});

    // Tool 1: Live Monitoring
    const canMonitor = isAdmin || Boolean(features.can_live_monitoring);
    const monitorCard = document.getElementById("dashToolMonitorCard");
    const monitorBadge = document.getElementById("dashMonitoringEntitlementBadge");
    const launchMonitorBtn = document.getElementById("dashLaunchMonitorBtn");
    if (monitorCard) {
      if (canMonitor) {
        monitorCard.classList.remove("locked");
        if (monitorBadge) {
          monitorBadge.className = "tool-entitlement-badge";
          monitorBadge.innerHTML = '<i class="fas fa-circle-check"></i> Unlocked';
        }
        if (launchMonitorBtn) {
          launchMonitorBtn.disabled = false;
          launchMonitorBtn.innerHTML = '<span>Launch Telemetry</span> <i class="fas fa-arrow-right"></i>';
        }
      } else {
        monitorCard.classList.add("locked");
        if (monitorBadge) {
          monitorBadge.className = "tool-entitlement-badge locked";
          monitorBadge.innerHTML = '<i class="fas fa-lock"></i> Locked';
        }
        if (launchMonitorBtn) {
          launchMonitorBtn.disabled = true;
          launchMonitorBtn.innerHTML = '<span>Plan Upgrade Required</span> <i class="fas fa-lock"></i>';
        }
      }
    }

    // Tool 2: Port Scanner
    const canPort = isAdmin || Boolean(features.can_port_scan);
    const portCard = document.getElementById("dashToolPortCard");
    const portBadge = document.getElementById("dashPortEntitlementBadge");
    const launchPortBtn = document.getElementById("dashLaunchPortBtn");
    if (portCard) {
      if (canPort) {
        portCard.classList.remove("locked");
        if (portBadge) {
          portBadge.className = "tool-entitlement-badge";
          portBadge.innerHTML = '<i class="fas fa-circle-check"></i> Unlocked';
        }
        if (launchPortBtn) {
          launchPortBtn.disabled = false;
          launchPortBtn.innerHTML = '<span>Launch Scanner</span> <i class="fas fa-arrow-right"></i>';
        }
      } else {
        portCard.classList.add("locked");
        if (portBadge) {
          portBadge.className = "tool-entitlement-badge locked";
          portBadge.innerHTML = '<i class="fas fa-lock"></i> Locked';
        }
        if (launchPortBtn) {
          launchPortBtn.disabled = true;
          launchPortBtn.innerHTML = '<span>Plan Upgrade Required</span> <i class="fas fa-lock"></i>';
        }
      }
    }

    // Tool 3: Network Discovery
    const canNd = isAdmin || Boolean(features.can_network_discovery);
    const ndCard = document.getElementById("dashToolNdCard");
    const ndBadge = document.getElementById("dashNdEntitlementBadge");
    const launchNdBtn = document.getElementById("dashLaunchNdBtn");
    if (ndCard) {
      if (canNd) {
        ndCard.classList.remove("locked");
        if (ndBadge) {
          ndBadge.className = "tool-entitlement-badge";
          ndBadge.innerHTML = '<i class="fas fa-circle-check"></i> Unlocked';
        }
        if (launchNdBtn) {
          launchNdBtn.disabled = false;
          launchNdBtn.innerHTML = '<span>Launch Discovery</span> <i class="fas fa-arrow-right"></i>';
        }
      } else {
        ndCard.classList.add("locked");
        if (ndBadge) {
          ndBadge.className = "tool-entitlement-badge locked";
          ndBadge.innerHTML = '<i class="fas fa-lock"></i> Locked';
        }
        if (launchNdBtn) {
          launchNdBtn.disabled = true;
          launchNdBtn.innerHTML = '<span>Plan Upgrade Required</span> <i class="fas fa-lock"></i>';
        }
      }
    }

    // Secondary Row Details
    const detailTier = document.getElementById("userDashDetailTier");
    const detailStatus = document.getElementById("userDashDetailStatus");
    const detailStart = document.getElementById("userDashDetailStartDate");
    const detailEnd = document.getElementById("userDashDetailEndDate");
    const detailRemaining = document.getElementById("userDashDetailRemaining");

    if (isAdmin) {
      if (detailTier) detailTier.textContent = "Root Enterprise";
      if (detailStatus) detailStatus.textContent = "Active Clearance";
      if (detailStart) detailStart.textContent = "System Root";
      if (detailEnd) detailEnd.textContent = "Perpetual";
      if (detailRemaining) detailRemaining.textContent = "Unlimited Access";
    } else if (sub) {
      if (detailTier) detailTier.textContent = (sub.plan && sub.plan.name) || sub.plan_id;
      if (detailStatus) detailStatus.textContent = sub.status ? sub.status.toUpperCase() : "—";
      if (detailStart) detailStart.textContent = formatUtcDate(sub.start_date || sub.created_at);
      if (detailEnd) detailEnd.textContent = formatUtcDate(sub.end_date);

      let remStr = "—";
      if (sub.status === "active" && sub.end_date) {
        try {
          const diffDays = Math.ceil((new Date(sub.end_date) - new Date()) / (1000 * 60 * 60 * 24));
          remStr = diffDays > 0 ? `${diffDays} days` : "Expires today";
        } catch (_) {}
      } else if (sub.status === "pending") {
        remStr = "Awaiting Approval";
      } else if (sub.status === "expired") {
        remStr = "Expired";
      }
      if (detailRemaining) detailRemaining.textContent = remStr;
    } else {
      if (detailTier) detailTier.textContent = "None";
      if (detailStatus) detailStatus.textContent = "Unsubscribed";
      if (detailStart) detailStart.textContent = "—";
      if (detailEnd) detailEnd.textContent = "—";
      if (detailRemaining) detailRemaining.textContent = "No Active Period";
    }

    // Telemetry Snapshot count
    const threatCount = document.getElementById("userDashThreatCount");
    if (threatCount) {
      threatCount.textContent = detectedAttacksRegistry ? detectedAttacksRegistry.size : 0;
    }

    // Operator Profile & Password Management forms
    const userFullNameInput = document.getElementById("userDashFullNameInput");
    const userEmailInput = document.getElementById("userDashEmailInput");
    const userSaveProfileBtn = document.getElementById("userDashSaveProfileBtn");
    const userProfileMsg = document.getElementById("userDashProfileMsg");

    if (userFullNameInput) userFullNameInput.value = currentUser.full_name || "";
    if (userEmailInput) userEmailInput.value = currentUser.email || "";

    if (userSaveProfileBtn) {
      userSaveProfileBtn.onclick = async () => {
        const fn = userFullNameInput ? userFullNameInput.value.trim() : "";
        const em = userEmailInput ? userEmailInput.value.trim() : "";
        userSaveProfileBtn.disabled = true;
        userSaveProfileBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Updating...';
        try {
          const resp = await fetch("/api/auth/profile", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ full_name: fn, email: em })
          });
          const rData = await resp.json();
          if (resp.ok && rData.status === "success") {
            if (userProfileMsg) {
              userProfileMsg.style.color = "#10B981";
              userProfileMsg.textContent = rData.message || "Profile updated!";
            }
            if (rData.user) {
              currentUser = rData.user;
              loadUserDashboard();
            }
          } else {
            if (userProfileMsg) {
              userProfileMsg.style.color = "#EF4444";
              userProfileMsg.textContent = rData.message || "Update failed.";
            }
          }
        } catch (_) {
          if (userProfileMsg) {
            userProfileMsg.style.color = "#EF4444";
            userProfileMsg.textContent = "Network error updating profile.";
          }
        } finally {
          userSaveProfileBtn.disabled = false;
          userSaveProfileBtn.innerHTML = '<i class="fas fa-save"></i> <span>Update Profile</span>';
        }
      };
    }

    const curPwInput = document.getElementById("userDashCurrentPassword");
    const newPwInput = document.getElementById("userDashNewPassword");
    const confirmPwInput = document.getElementById("userDashConfirmPassword");
    const userChangePwBtn = document.getElementById("userDashChangePasswordBtn");
    const userPwMsg = document.getElementById("userDashPasswordMsg");

    if (userChangePwBtn) {
      userChangePwBtn.onclick = async () => {
        const curPw = curPwInput ? curPwInput.value : "";
        const newPw = newPwInput ? newPwInput.value : "";
        const confPw = confirmPwInput ? confirmPwInput.value : "";
        if (!curPw || !newPw || !confPw) {
          if (userPwMsg) {
            userPwMsg.style.color = "#EF4444";
            userPwMsg.textContent = "All password fields are required.";
          }
          return;
        }
        if (newPw !== confPw) {
          if (userPwMsg) {
            userPwMsg.style.color = "#EF4444";
            userPwMsg.textContent = "New passwords do not match.";
          }
          return;
        }
        userChangePwBtn.disabled = true;
        userChangePwBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Changing...';
        try {
          const resp = await fetch("/api/auth/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ current_password: curPw, new_password: newPw, confirm_new_password: confPw })
          });
          const rData = await resp.json();
          if (resp.ok && rData.status === "success") {
            if (userPwMsg) {
              userPwMsg.style.color = "#10B981";
              userPwMsg.textContent = rData.message || "Password changed successfully!";
            }
            if (curPwInput) curPwInput.value = "";
            if (newPwInput) newPwInput.value = "";
            if (confirmPwInput) confirmPwInput.value = "";
          } else {
            if (userPwMsg) {
              userPwMsg.style.color = "#EF4444";
              userPwMsg.textContent = rData.message || "Password change failed.";
            }
          }
        } catch (_) {
          if (userPwMsg) {
            userPwMsg.style.color = "#EF4444";
            userPwMsg.textContent = "Network error changing password.";
          }
        } finally {
          userChangePwBtn.disabled = false;
          userChangePwBtn.innerHTML = '<i class="fas fa-lock-rotate"></i> <span>Change Password</span>';
        }
      };
    }
  }

  // Load User Subscription Status
  async function loadUserSubscription() {
    if (!currentUser) {
      if (subStatusDot) subStatusDot.className = "sub-status-dot";
      if (subStatusText) subStatusText.textContent = "Anonymous Visitor";
      if (subUserRole) subUserRole.textContent = "Public";
      if (subStatusTitle) subStatusTitle.textContent = "Sign In to Access Subscriptions";
      if (subStatusMessage) subStatusMessage.textContent = "Create an account or sign in to request access and manage threat intelligence entitlements.";
      if (subMetaRow) subMetaRow.style.display = "none";
      return;
    }

    if (subUserRole) subUserRole.textContent = currentUser.role || "Operator";

    if (currentUser.role === "Admin") {
      if (subStatusDot) subStatusDot.className = "sub-status-dot active";
      if (subStatusText) subStatusText.textContent = "Active Clearance";
      if (subStatusTitle) subStatusTitle.textContent = "Administrator Access Granted";
      if (subStatusMessage) subStatusMessage.textContent = "You hold full security administrative clearance with unrestricted access to all operational modules.";
      if (subMetaRow) {
        subMetaRow.style.display = "flex";
        if (subMetaStart) subMetaStart.textContent = "System Root";
        if (subMetaEnd) subMetaEnd.textContent = "Perpetual";
        if (subMetaTier) subMetaTier.textContent = "Full Enterprise Clearance";
      }
      return;
    }

    try {
      const sub = await fetchCurrentUserSubscription();
      if (!sub) {
        if (subStatusDot) subStatusDot.className = "sub-status-dot";
        if (subStatusText) subStatusText.textContent = "No Active Subscription";
        if (subStatusTitle) subStatusTitle.textContent = "Select an Operational Tier";
        if (subStatusMessage) subStatusMessage.textContent = "Choose an intelligence tier below to unlock live monitoring, port scanner, and network discovery.";
        if (subMetaRow) subMetaRow.style.display = "none";
        return;
      }

      if (sub.status === "active") {
        if (subStatusDot) subStatusDot.className = "sub-status-dot active";
        if (subStatusText) subStatusText.textContent = "Active Subscription";
        if (subStatusTitle) subStatusTitle.textContent = sub.plan ? sub.plan.name : "Active Plan";
        if (subStatusMessage) subStatusMessage.textContent = "Your subscription is currently active. All authorized tool modules are unlocked.";
        if (subMetaRow) {
          subMetaRow.style.display = "flex";
          if (subMetaStart) subMetaStart.textContent = formatUtcDate(sub.start_date);
          if (subMetaEnd) subMetaEnd.textContent = formatUtcDate(sub.end_date);
          if (subMetaTier) subMetaTier.textContent = sub.plan_id;
        }
      } else if (sub.status === "pending") {
        if (subStatusDot) subStatusDot.className = "sub-status-dot pending";
        if (subStatusText) subStatusText.textContent = "Pending Approval";
        if (subStatusTitle) subStatusTitle.textContent = sub.plan ? `Request Pending: ${sub.plan.name}` : "Request Pending";
        if (subStatusMessage) subStatusMessage.textContent = "Your request has been submitted to system administrators. Access will activate upon verification.";
        if (subMetaRow) {
          subMetaRow.style.display = "flex";
          if (subMetaStart) subMetaStart.textContent = formatUtcDate(sub.created_at || sub.start_date);
          if (subMetaEnd) subMetaEnd.textContent = "Awaiting Activation";
          if (subMetaTier) subMetaTier.textContent = sub.plan_id;
        }
      } else if (sub.status === "expired") {
        if (subStatusDot) subStatusDot.className = "sub-status-dot expired";
        if (subStatusText) subStatusText.textContent = "Subscription Expired";
        if (subStatusTitle) subStatusTitle.textContent = "Plan Validity Concluded";
        if (subStatusMessage) subStatusMessage.textContent = `Your previous subscription expired on ${formatUtcDate(sub.end_date)}. Please select a plan to renew access.`;
        if (subMetaRow) {
          subMetaRow.style.display = "flex";
          if (subMetaStart) subMetaStart.textContent = formatUtcDate(sub.start_date);
          if (subMetaEnd) subMetaEnd.textContent = formatUtcDate(sub.end_date);
          if (subMetaTier) subMetaTier.textContent = sub.plan_id;
        }
      } else {
        if (subStatusDot) subStatusDot.className = "sub-status-dot canceled";
        if (subStatusText) subStatusText.textContent = sub.status.toUpperCase();
        if (subStatusTitle) subStatusTitle.textContent = `Subscription ${sub.status}`;
        if (subStatusMessage) subStatusMessage.textContent = "Please select a plan below to request access.";
        if (subMetaRow) subMetaRow.style.display = "none";
      }
    } catch (_) {
      if (subStatusTitle) subStatusTitle.textContent = "Subscription Service Unavailable";
      if (subStatusMessage) subStatusMessage.textContent = "Unable to fetch subscription status. Please refresh.";
    }
  }

  // Load and Render Plans Catalog
  async function loadPlansCatalog() {
    if (!plansCatalogGrid) return;
    plansCatalogGrid.innerHTML = `
      <div class="plans-loading-placeholder">
        <i class="fas fa-circle-notch fa-spin"></i> Loading subscription catalog...
      </div>
    `;

    try {
      const res = await fetch("/api/plans");
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        plansCatalogGrid.innerHTML = `<div class="plans-loading-placeholder">Unable to load plans catalog.</div>`;
        return;
      }

      const plans = data.plans || [];
      if (plans.length === 0) {
        plansCatalogGrid.innerHTML = `<div class="plans-loading-placeholder">No active plans currently available.</div>`;
        return;
      }

      const activeSub = currentUserSubscription;
      const isSubActive = activeSub && activeSub.status === "active";
      const isSubPending = activeSub && activeSub.status === "pending";

      let html = "";
      for (const p of plans) {
        const isFeatured = p.id === "SCOUT-PRO";
        const isCurrentPlan = isSubActive && activeSub.plan_id === p.id;
        const isPendingPlan = isSubPending && activeSub.plan_id === p.id;

        const priceDisplay = p.price === 0 ? "Free" : `$${p.price.toFixed(2)}`;
        const durationDisplay = p.duration_days ? `/ ${p.duration_days} Days` : "";

        const f = p.features || {};
        const canMonitor = f.can_live_monitoring !== false;
        const canPort = f.can_port_scan !== false;
        const canNd = f.can_network_discovery === true;
        const maxScans = f.max_concurrent_scans || 1;

        let btnHtml = "";
        if (!currentUser) {
          btnHtml = `<button type="button" class="btn-plan-select" data-plan-trigger="auth"><i class="fas fa-lock"></i> Sign In to Select</button>`;
        } else if (currentUser.role === "Admin") {
          btnHtml = `<button type="button" class="btn-plan-select current" disabled><i class="fas fa-shield-halved"></i> Admin Unrestricted</button>`;
        } else if (isCurrentPlan) {
          btnHtml = `<button type="button" class="btn-plan-select current" disabled><i class="fas fa-circle-check"></i> Current Plan</button>`;
        } else if (isPendingPlan) {
          btnHtml = `<button type="button" class="btn-plan-select pending" disabled><i class="fas fa-clock"></i> Pending Approval</button>`;
        } else {
          btnHtml = `<button type="button" class="btn-plan-select" data-plan-id="${escapeHtml(p.id)}"><i class="fas fa-arrow-right"></i> Select Plan</button>`;
        }

        html += `
          <div class="plan-card ${isFeatured ? 'featured' : ''}">
            ${isFeatured ? '<span class="plan-featured-badge">Recommended</span>' : ''}
            <div>
              <div class="plan-header">
                <div class="plan-name">${escapeHtml(p.name)}</div>
                <div class="plan-desc">${escapeHtml(p.description || '')}</div>
              </div>
              <div class="plan-price-wrap">
                <span class="plan-price">${priceDisplay}</span>
                <span class="plan-duration">${durationDisplay}</span>
              </div>
              <ul class="plan-features-list">
                <li class="plan-feature-item ${canMonitor ? '' : 'disabled'}">
                  <i class="fas ${canMonitor ? 'fa-check' : 'fa-xmark'}"></i>
                  <span>Live Traffic Telemetry & 15-Class AI Intrusion Detection</span>
                </li>
                <li class="plan-feature-item ${canPort ? '' : 'disabled'}">
                  <i class="fas ${canPort ? 'fa-check' : 'fa-xmark'}"></i>
                  <span>Active Port Scanning & TCP Service Enumeration</span>
                </li>
                <li class="plan-feature-item ${canNd ? '' : 'disabled'}">
                  <i class="fas ${canNd ? 'fa-check' : 'fa-xmark'}"></i>
                  <span>Subnet Reconnaissance & Network Discovery</span>
                </li>
                <li class="plan-feature-item">
                  <i class="fas fa-check"></i>
                  <span>Max Concurrent Scans: <strong>${maxScans}</strong></span>
                </li>
              </ul>
            </div>
            <div>
              ${btnHtml}
            </div>
          </div>
        `;
      }

      plansCatalogGrid.innerHTML = html;

      // Bind button click listeners
      plansCatalogGrid.querySelectorAll(".btn-plan-select").forEach(btn => {
        btn.addEventListener("click", () => {
          if (btn.getAttribute("data-plan-trigger") === "auth") {
            openAuthModal("signin", "Please sign in or create an account to request a subscription plan.");
          } else {
            const planId = btn.getAttribute("data-plan-id");
            if (planId) requestSubscription(planId, btn);
          }
        });
      });
    } catch (_) {
      plansCatalogGrid.innerHTML = `<div class="plans-loading-placeholder">Network error loading plans catalog.</div>`;
    }
  }

  // Request Plan Handler
  async function requestSubscription(planId, btnEl) {
    if (!planId) return;
    if (btnEl) {
      btnEl.disabled = true;
      btnEl.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Requesting...';
    }

    try {
      const res = await fetch("/api/subscriptions/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ plan_id: planId })
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        if (subAlertBox) {
          subAlertBox.className = "sub-alert-box success";
          subAlertBox.innerHTML = '<i class="fas fa-circle-check"></i> ' + (data.message || "Subscription request submitted! An administrator will review your account.");
          subAlertBox.style.display = "flex";
        }
        await loadUserSubscription();
        await loadPlansCatalog();
      } else {
        if (subAlertBox) {
          subAlertBox.className = "sub-alert-box warning";
          subAlertBox.innerHTML = '<i class="fas fa-triangle-exclamation"></i> ' + (data.message || "Failed to submit subscription request.");
          subAlertBox.style.display = "flex";
        }
        if (btnEl) {
          btnEl.disabled = false;
          btnEl.innerHTML = '<i class="fas fa-arrow-right"></i> Select Plan';
        }
      }
    } catch (_) {
      if (subAlertBox) {
        subAlertBox.className = "sub-alert-box warning";
        subAlertBox.innerHTML = '<i class="fas fa-triangle-exclamation"></i> Network error submitting request.';
        subAlertBox.style.display = "flex";
      }
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.innerHTML = '<i class="fas fa-arrow-right"></i> Select Plan';
      }
    }
  }

  // ============================================================================
  // Admin Management Console Controller
  // ============================================================================
  const adminTabBtns = document.querySelectorAll(".admin-tab-btn");
  const adminPanels = {
    overview: document.getElementById("adminPanelOverview"),
    requests: document.getElementById("adminPanelRequests"),
    subscriptions: document.getElementById("adminPanelSubscriptions"),
    users: document.getElementById("adminPanelUsers"),
    plans: document.getElementById("adminPanelPlans"),
    audit: document.getElementById("adminPanelAudit"),
    profile: document.getElementById("adminPanelProfile")
  };

  function activateAdminTab(tabKey, updateUrl = true) {
    if (!tabKey) tabKey = "overview";
    adminTabBtns.forEach(b => {
      if (b.getAttribute("data-admin-tab") === tabKey) {
        b.classList.add("active");
      } else {
        b.classList.remove("active");
      }
    });

    Object.keys(adminPanels).forEach(key => {
      if (adminPanels[key]) {
        adminPanels[key].style.display = key === tabKey ? "block" : "none";
      }
    });

    if (tabKey === "overview") loadAdminMetrics();
    else if (tabKey === "requests") loadAdminRequests();
    else if (tabKey === "subscriptions") loadAdminSubscriptions();
    else if (tabKey === "users") loadAdminUsers();
    else if (tabKey === "plans") loadAdminPlans();
    else if (tabKey === "audit") loadAdminAuditLogs();
    else if (tabKey === "profile") loadAdminProfile();

    const titleMap = {
      overview: "SCOUT Administrative Console — Platform Overview",
      users: "SCOUT Admin — Operator & User Accounts",
      plans: "SCOUT Admin — Subscription Plans Catalog",
      subscriptions: "SCOUT Admin — Global Subscription Registry",
      requests: "SCOUT Admin — Pending Subscription Requests",
      audit: "SCOUT Admin — Security Audit Logs",
      profile: "SCOUT Admin — Profile & Security"
    };
    if (titleMap[tabKey]) {
      document.title = titleMap[tabKey];
    }
    if (dedicatedToolTitle && titleMap[tabKey]) {
      dedicatedToolTitle.textContent = titleMap[tabKey];
    }

    let viewKey = "admin";
    if (tabKey === "users") viewKey = "admin-users";
    else if (tabKey === "plans") viewKey = "admin-plans";
    else if (tabKey === "subscriptions") viewKey = "admin-subs";
    else if (tabKey === "requests") viewKey = "admin-requests";
    else if (tabKey === "audit") viewKey = "admin-audit";
    else if (tabKey === "profile") viewKey = "admin-profile";

    // Keep active sidebar navigation item persistently synchronized on all tab switches
    setSidebarActive(viewKey);

    if (updateUrl) {
      const targetQuery = "?view=" + viewKey;
      if (window.location.search !== targetQuery) {
        history.pushState({ view: viewKey }, "", targetQuery);
      } else {
        history.replaceState({ view: viewKey }, "", targetQuery);
      }
    }
  }

  adminTabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const tabKey = btn.getAttribute("data-admin-tab");
      activateAdminTab(tabKey, true);
    });
  });

  // Admin Quick Action Shortcut Buttons
  const adminShortcutBtns = document.querySelectorAll(".admin-shortcut-btn[data-jump-tab]");
  adminShortcutBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const jumpTarget = btn.getAttribute("data-jump-tab");
      const targetTab = document.querySelector(`.admin-tab-btn[data-admin-tab="${jumpTarget}"]`);
      if (targetTab) targetTab.click();
    });
  });

  const adminRefreshAllBtn = document.getElementById("adminRefreshAllBtn");
  if (adminRefreshAllBtn) {
    adminRefreshAllBtn.addEventListener("click", () => {
      loadAdminDashboard();
    });
  }

  async function loadAdminDashboard() {
    loadAdminMetrics();
    loadAdminRequests();
    loadAdminSubscriptions();
    loadAdminUsers();
    loadAdminPlans();
    loadAdminAuditLogs();
    loadAdminProfile();
  }

  // Load Database Platform Activity Metrics for Admin (Zero Mock Data)
  async function loadAdminMetrics() {
    const totalUsersEl = document.getElementById("adminMetricTotalUsers");
    const activeUsersEl = document.getElementById("adminMetricActiveUsers");
    const inactiveUsersEl = document.getElementById("adminMetricInactiveUsers");
    const totalSubsEl = document.getElementById("adminMetricTotalSubscribers");
    const pendingSubsEl = document.getElementById("adminMetricPendingSubs");
    const activeSubsEl = document.getElementById("adminMetricActiveSubs");
    const expiredSubsEl = document.getElementById("adminMetricExpiredSubs");
    const canceledSubsEl = document.getElementById("adminMetricCanceledSubs");
    const plansEl = document.getElementById("adminMetricPlans");
    const inactivePlansEl = document.getElementById("adminMetricInactivePlans");

    try {
      const res = await fetch("/api/admin/metrics", { credentials: "same-origin" });
      const data = await res.json();
      if (res.ok && data.status === "success" && data.metrics) {
        const m = data.metrics;
        if (totalUsersEl) totalUsersEl.textContent = m.total_users ?? 0;
        if (activeUsersEl) activeUsersEl.textContent = m.active_users ?? 0;
        if (inactiveUsersEl) inactiveUsersEl.textContent = m.inactive_users ?? 0;
        if (totalSubsEl) totalSubsEl.textContent = m.total_subscribers ?? 0;
        if (pendingSubsEl) pendingSubsEl.textContent = m.pending_subscriptions ?? 0;
        if (activeSubsEl) activeSubsEl.textContent = m.active_subscriptions ?? 0;
        if (expiredSubsEl) expiredSubsEl.textContent = m.expired_subscriptions ?? 0;
        if (canceledSubsEl) canceledSubsEl.textContent = m.canceled_subscriptions ?? 0;
        if (plansEl) plansEl.textContent = m.available_plans ?? 0;
        if (inactivePlansEl) inactivePlansEl.textContent = m.inactive_plans ?? 0;

        const countBadge = document.getElementById("adminPendingCountBadge");
        if (countBadge) {
          countBadge.textContent = m.pending_subscriptions;
          countBadge.style.display = m.pending_subscriptions > 0 ? "inline-block" : "none";
        }
        if (sidebarPendingBadge) {
          sidebarPendingBadge.textContent = m.pending_subscriptions;
          sidebarPendingBadge.style.display = m.pending_subscriptions > 0 ? "inline-block" : "none";
        }
        const sidebarRequestsBadge = document.getElementById("sidebarRequestsBadge");
        if (sidebarRequestsBadge) {
          sidebarRequestsBadge.textContent = m.pending_subscriptions;
          sidebarRequestsBadge.style.display = m.pending_subscriptions > 0 ? "inline-block" : "none";
        }
      }
    } catch (_) {}
  }


  // Admin Profile & Security Loader
  async function loadAdminProfile() {
    const dispName = document.getElementById("adminProfileDispName");
    const dispUser = document.getElementById("adminProfileDispUsername");
    const dispEmail = document.getElementById("adminProfileDispEmail");
    const dispStatus = document.getElementById("adminProfileDispStatus");
    const dispJoined = document.getElementById("adminProfileDispJoined");
    const dispLastLogin = document.getElementById("adminProfileDispLastLogin");
    const fullNameInput = document.getElementById("adminProfileFullNameInput");
    const emailInput = document.getElementById("adminProfileEmailInput");

    try {
      const res = await fetch("/api/auth/me", { credentials: "same-origin" });
      const data = await res.json();
      if (res.ok && data.status === "success" && data.user) {
        const u = data.user;
        if (dispName) dispName.textContent = u.full_name || u.username;
        if (dispUser) dispUser.textContent = u.username;
        if (dispEmail) dispEmail.textContent = u.email;
        if (dispStatus) {
          dispStatus.textContent = u.is_active ? "Active" : "Disabled";
          dispStatus.className = u.is_active ? "info-val text-success" : "info-val text-danger";
        }
        if (dispJoined) dispJoined.textContent = formatUtcDate(u.created_at);
        if (dispLastLogin) dispLastLogin.textContent = u.last_login_at ? formatUtcDate(u.last_login_at) : "Current Session";
        if (fullNameInput) fullNameInput.value = u.full_name || "";
        if (emailInput) emailInput.value = u.email || "";
      }
    } catch (_) {}
  }

  // Subscription Administrative Lifecycle Actions
  async function activateSubscription(subId, btn) {
    if (!subId) return;
    if (!confirm(`Approve and activate subscription #${subId}?\n\nThis will provision immediate cybersecurity access and initialize billing terms.`)) {
      return;
    }

    const originalContent = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Approving...';
    }

    try {
      const res = await fetch(`/api/admin/subscriptions/${subId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ notes: "Approved by administrator via SCOUT Admin Console" })
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        loadAdminRequests();
        loadAdminSubscriptions();
        loadAdminMetrics();
      } else {
        alert(data.message || "Failed to approve subscription.");
      }
    } catch (_) {
      alert("Network error approving subscription.");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalContent;
      }
    }
  }

  async function rejectSubscription(subId, btn) {
    if (!subId) return;
    const reason = prompt(`Enter rejection reason for subscription #${subId} (optional):`, "Request rejected by administrator.");
    if (reason === null) return; // User cancelled

    const originalContent = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Rejecting...';
    }

    try {
      const res = await fetch(`/api/admin/subscriptions/${subId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ reason: reason.trim() || "Request rejected by administrator." })
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        loadAdminRequests();
        loadAdminSubscriptions();
        loadAdminMetrics();
      } else {
        alert(data.message || "Failed to reject subscription.");
      }
    } catch (_) {
      alert("Network error rejecting subscription.");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalContent;
      }
    }
  }

  async function cancelSubscription(subId, btn) {
    if (!subId) return;
    const reason = prompt(`Are you sure you want to terminate subscription #${subId}?\n\nEnter cancellation reason (optional):`, "Canceled by administrator.");
    if (reason === null) return; // User cancelled

    const originalContent = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Canceling...';
    }

    try {
      const res = await fetch(`/api/admin/subscriptions/${subId}/cancel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ reason: reason.trim() || "Canceled by administrator." })
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        loadAdminSubscriptions();
        loadAdminMetrics();
      } else {
        alert(data.message || "Failed to cancel subscription.");
      }
    } catch (_) {
      alert("Network error canceling subscription.");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalContent;
      }
    }
  }

  // Load Pending Requests & Approvals with Card-Based Layout and Fallback Table Sync
  async function loadAdminRequests() {
    const cardsGrid = document.getElementById("adminRequestsCardsGrid");
    const tbody = document.getElementById("adminRequestsTbody");
    const countBadge = document.getElementById("adminPendingCountBadge");
    const pendingMetric = document.getElementById("adminMetricPendingSubs");
    if (!cardsGrid && !tbody) return;

    if (cardsGrid) {
      cardsGrid.innerHTML = `
        <div class="admin-cards-state loading-state">
          <div class="state-icon-wrap"><i class="fas fa-circle-notch fa-spin"></i></div>
          <h4>Loading Pending Requests...</h4>
          <p>Fetching operator subscription approval queue.</p>
        </div>
      `;
    }
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4"><i class="fas fa-circle-notch fa-spin"></i> Loading requests...</td></tr>`;
    }

    try {
      const res = await fetch("/api/admin/subscriptions?status=pending", { credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state error-state">
              <div class="state-icon-wrap"><i class="fas fa-triangle-exclamation"></i></div>
              <h4>Unable to Load Requests</h4>
              <p>${escapeHtml(data.message || "Failed to retrieve pending subscriptions.")}</p>
            </div>
          `;
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">Unable to load requests.</td></tr>`;
        return;
      }

      const requests = data.subscriptions || [];
      if (pendingMetric) pendingMetric.textContent = requests.length;
      if (countBadge) {
        countBadge.textContent = requests.length;
        countBadge.style.display = requests.length > 0 ? "inline-block" : "none";
      }
      const sbBadge = document.getElementById("sidebarPendingBadge");
      if (sbBadge) {
        sbBadge.textContent = requests.length;
        sbBadge.style.display = requests.length > 0 ? "inline-block" : "none";
      }
      const srBadge = document.getElementById("sidebarRequestsBadge");
      if (srBadge) {
        srBadge.textContent = requests.length;
        srBadge.style.display = requests.length > 0 ? "inline-block" : "none";
      }

      if (requests.length === 0) {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state empty-state">
              <div class="state-icon-wrap"><i class="fas fa-clipboard-check"></i></div>
              <h4>All Clear — No Pending Requests</h4>
              <p>All operator subscription requests have been reviewed and approved or rejected.</p>
            </div>
          `;
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted"><i class="fas fa-circle-check"></i> No pending subscription requests. All accounts are up to date.</td></tr>`;
        return;
      }

      let cardsHtml = "";
      let rowsHtml = "";
      for (const r of requests) {
        const opName = r.username || (r.user && (r.user.username || r.user.email)) || `User #${r.user_id}`;
        const opSub = r.user_email || (r.user && r.user.email) || "";
        const initials = opName.split(/\s+/).map(w => w[0]).filter(Boolean).slice(0, 2).join("").toUpperCase() || "OP";
        const planName = r.plan_name || (r.plan && r.plan.name) || r.plan_code || `Plan #${r.plan_id}`;
        const priceStr = (r.plan_price !== undefined && r.plan_price !== null) ? `$${r.plan_price.toFixed(2)}${r.plan_duration ? ' / ' + r.plan_duration : ''}` : (r.plan ? `$${r.plan.price.toFixed(2)}` : "—");
        const dateStr = formatUtcDate(r.created_at || r.start_date);

        cardsHtml += `
          <div class="admin-request-card" data-card-request-id="${r.id}">
            <div class="request-card-header">
              <div class="request-user-info">
                <div class="admin-user-avatar">${escapeHtml(initials)}</div>
                <div class="request-user-details">
                  <span class="request-username">${escapeHtml(opName)}</span>
                  ${opSub ? `<span class="request-email text-muted">${escapeHtml(opSub)}</span>` : ''}
                </div>
              </div>
              <div class="request-badge-wrap">
                <span class="sub-badge pending"><i class="fas fa-clock"></i> Pending Approval</span>
              </div>
            </div>
            <div class="request-card-body">
              <div class="request-data-grid">
                <div class="request-data-item">
                  <span class="request-data-label"><i class="fas fa-shield-halved"></i> Requested Plan</span>
                  <span class="request-data-val font-semibold">${escapeHtml(planName)}</span>
                </div>
                <div class="request-data-item">
                  <span class="request-data-label"><i class="fas fa-receipt"></i> Plan Pricing</span>
                  <span class="request-data-val">${escapeHtml(priceStr)}</span>
                </div>
                <div class="request-data-item">
                  <span class="request-data-label"><i class="fas fa-calendar-alt"></i> Request Date</span>
                  <span class="request-data-val">${dateStr}</span>
                </div>
                <div class="request-data-item">
                  <span class="request-data-label"><i class="fas fa-fingerprint"></i> Subscription ID</span>
                  <span class="request-data-val"><code>#${r.id}</code></span>
                </div>
              </div>
            </div>
            <div class="request-card-footer">
              <button type="button" class="btn-admin-action activate" data-act-id="${r.id}" title="Approve and activate subscription">
                <i class="fas fa-check"></i> Approve Request
              </button>
              <button type="button" class="btn-admin-action reject" data-rej-id="${r.id}" title="Reject request">
                <i class="fas fa-xmark"></i> Reject
              </button>
            </div>
          </div>
        `;

        rowsHtml += `
          <tr>
            <td>
              <strong>${escapeHtml(opName)}</strong>
              ${opSub ? `<br><small class="text-muted">${escapeHtml(opSub)}</small>` : ''}
            </td>
            <td><span class="sub-badge active">${escapeHtml(planName)}</span></td>
            <td>${priceStr}</td>
            <td>${dateStr}</td>
            <td><span class="sub-badge pending">Pending</span></td>
            <td>
              <div class="admin-action-btn-group">
                <button type="button" class="btn-admin-action activate" data-act-id="${r.id}" title="Approve and activate subscription">
                  <i class="fas fa-check"></i> Approve
                </button>
                <button type="button" class="btn-admin-action reject" data-rej-id="${r.id}" title="Reject request">
                  <i class="fas fa-xmark"></i> Reject
                </button>
              </div>
            </td>
          </tr>
        `;
      }

      if (cardsGrid) cardsGrid.innerHTML = cardsHtml;
      if (tbody) tbody.innerHTML = rowsHtml;

      const bindActions = (container) => {
        if (!container) return;
        container.querySelectorAll("[data-act-id]").forEach(btn => {
          btn.addEventListener("click", () => activateSubscription(btn.getAttribute("data-act-id"), btn));
        });
        container.querySelectorAll("[data-rej-id]").forEach(btn => {
          btn.addEventListener("click", () => rejectSubscription(btn.getAttribute("data-rej-id"), btn));
        });
      };

      bindActions(cardsGrid);
      bindActions(tbody);
    } catch (_) {
      if (cardsGrid) {
        cardsGrid.innerHTML = `
          <div class="admin-cards-state error-state">
            <div class="state-icon-wrap"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>Network Error Loading Requests</h4>
            <p>Unable to connect to the backend subscription service.</p>
          </div>
        `;
      }
      if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">Network error loading requests.</td></tr>`;
    }
  }

  // Load All Subscriptions with Responsive Card-Based Layout, Search & Status Filtering
  async function loadAdminSubscriptions() {
    const cardsGrid = document.getElementById("adminSubsCardsGrid");
    const tbody = document.getElementById("adminSubsTbody");
    const activeMetric = document.getElementById("adminMetricActiveSubs");
    const filterSelect = document.getElementById("adminSubStatusFilter");
    const searchInput = document.getElementById("adminSubSearchInput");
    if (!cardsGrid && !tbody) return;

    const filterStatus = filterSelect ? filterSelect.value : "all";
    const searchVal = searchInput ? searchInput.value.trim() : "";

    if (cardsGrid) {
      cardsGrid.innerHTML = `
        <div class="admin-cards-state loading-state">
          <div class="state-icon-wrap"><i class="fas fa-circle-notch fa-spin"></i></div>
          <h4>Loading Subscriptions...</h4>
          <p>Fetching operator subscriptions and active licenses.</p>
        </div>
      `;
    }
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4"><i class="fas fa-circle-notch fa-spin"></i> Loading subscriptions...</td></tr>`;
    }

    try {
      const params = new URLSearchParams();
      if (filterStatus !== "all") params.set("status", filterStatus);
      if (searchVal) params.set("search", searchVal);
      const url = params.toString() ? `/api/admin/subscriptions?${params.toString()}` : `/api/admin/subscriptions`;

      const res = await fetch(url, { credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state error-state">
              <div class="state-icon-wrap"><i class="fas fa-triangle-exclamation"></i></div>
              <h4>Unable to Load Subscriptions</h4>
              <p>${escapeHtml(data.message || "Failed to retrieve subscription records.")}</p>
            </div>
          `;
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">Unable to load subscriptions.</td></tr>`;
        return;
      }

      const subs = data.subscriptions || [];
      const activeCount = subs.filter(s => s.status === "active").length;
      if (activeMetric && filterStatus === "all" && !searchVal) activeMetric.textContent = activeCount;

      if (subs.length === 0) {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state empty-state">
              <div class="state-icon-wrap"><i class="fas fa-box-archive"></i></div>
              <h4>No Subscriptions Found</h4>
              <p>No operator subscription records match the selected status filter or search query.</p>
            </div>
          `;
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No subscriptions found matching query or filter.</td></tr>`;
        return;
      }

      let cardsHtml = "";
      let rowsHtml = "";
      for (const s of subs) {
        const opName = s.username || (s.user && (s.user.username || s.user.email)) || `User #${s.user_id}`;
        const opEmail = s.user_email || (s.user && s.user.email) || "";
        const initials = opName.split(/\s+/).map(w => w[0]).filter(Boolean).slice(0, 2).join("").toUpperCase() || "OP";
        const planName = s.plan_name || (s.plan && s.plan.name) || s.plan_code || s.plan_id;
        const statusClass = s.status === "active" ? "active" : (s.status === "pending" ? "pending" : (s.status === "expired" ? "expired" : "canceled"));
        const statusIcon = s.status === "active" ? "fa-circle-check" : (s.status === "pending" ? "fa-clock" : (s.status === "expired" ? "fa-circle-exclamation" : "fa-ban"));

        let actionBtns = `
          <button type="button" class="btn-admin-action dates" data-dates-id="${s.id}" data-start="${s.start_date || ''}" data-end="${s.end_date || ''}" title="Adjust subscription dates">
            <i class="fas fa-calendar"></i> Dates
          </button>
        `;
        if (s.status === "pending") {
          actionBtns += `
            <button type="button" class="btn-admin-action activate" data-act-id="${s.id}" title="Approve and activate subscription">
              <i class="fas fa-check"></i> Approve
            </button>
            <button type="button" class="btn-admin-action reject" data-rej-id="${s.id}" title="Reject request">
              <i class="fas fa-xmark"></i> Reject
            </button>
          `;
        } else if (s.status === "active") {
          actionBtns += `
            <button type="button" class="btn-admin-action activate" data-extend-id="${s.id}" data-user="${escapeHtml(opName)}" data-plan="${escapeHtml(planName)}" title="Extend active subscription">
              <i class="fas fa-calendar-plus"></i> Extend
            </button>
            <button type="button" class="btn-admin-action cancel" data-canc-id="${s.id}" title="Cancel subscription">
              <i class="fas fa-ban"></i> Cancel
            </button>
          `;
        } else if (s.status === "expired") {
          actionBtns += `
            <button type="button" class="btn-admin-action activate" data-renew-id="${s.id}" data-user="${escapeHtml(opName)}" data-plan="${escapeHtml(planName)}" title="Renew expired subscription">
              <i class="fas fa-rotate"></i> Renew
            </button>
          `;
        } else if (s.status === "canceled") {
          actionBtns += `
            <button type="button" class="btn-admin-action activate" data-renew-id="${s.id}" data-user="${escapeHtml(opName)}" data-plan="${escapeHtml(planName)}" title="Re-activate canceled subscription">
              <i class="fas fa-rotate"></i> Re-activate
            </button>
          `;
        }

        cardsHtml += `
          <div class="admin-sub-card status-${statusClass}" data-card-sub-id="${s.id}">
            <div class="sub-card-header">
              <div class="sub-user-info">
                <div class="admin-user-avatar">${escapeHtml(initials)}</div>
                <div class="sub-user-details">
                  <span class="sub-username">${escapeHtml(opName)}</span>
                  ${opEmail ? `<span class="sub-email text-muted">${escapeHtml(opEmail)}</span>` : ''}
                </div>
              </div>
              <div class="sub-badge-wrap">
                <span class="sub-badge ${statusClass}"><i class="fas ${statusIcon}"></i> ${escapeHtml(s.status.toUpperCase())}</span>
              </div>
            </div>
            <div class="sub-card-body">
              <div class="sub-data-grid">
                <div class="sub-data-item">
                  <span class="sub-data-label"><i class="fas fa-shield-halved"></i> Plan</span>
                  <span class="sub-data-val font-semibold">${escapeHtml(planName)}</span>
                </div>
                <div class="sub-data-item">
                  <span class="sub-data-label"><i class="fas fa-fingerprint"></i> Subscription ID</span>
                  <span class="sub-data-val"><code>#${s.id}</code></span>
                </div>
                <div class="sub-data-item">
                  <span class="sub-data-label"><i class="fas fa-calendar-day"></i> Start Date</span>
                  <span class="sub-data-val">${formatUtcDate(s.start_date)}</span>
                </div>
                <div class="sub-data-item">
                  <span class="sub-data-label"><i class="fas fa-hourglass-end"></i> Expiration Date</span>
                  <span class="sub-data-val">${formatUtcDate(s.end_date)}</span>
                </div>
              </div>
            </div>
            <div class="sub-card-footer">
              <div class="admin-action-btn-group">
                ${actionBtns}
              </div>
            </div>
          </div>
        `;

        rowsHtml += `
          <tr>
            <td><code>#${s.id}</code></td>
            <td><strong>${escapeHtml(opName)}</strong></td>
            <td>${escapeHtml(planName)}</td>
            <td><span class="sub-badge ${statusClass}">${escapeHtml(s.status)}</span></td>
            <td>${formatUtcDate(s.start_date)}</td>
            <td>${formatUtcDate(s.end_date)}</td>
            <td>
              <div class="admin-action-btn-group">
                ${actionBtns}
              </div>
            </td>
          </tr>
        `;
      }

      if (cardsGrid) cardsGrid.innerHTML = cardsHtml;
      if (tbody) tbody.innerHTML = rowsHtml;

      const bindActions = (container) => {
        if (!container) return;
        container.querySelectorAll("[data-act-id]").forEach(btn => {
          btn.addEventListener("click", () => activateSubscription(btn.getAttribute("data-act-id"), btn));
        });
        container.querySelectorAll("[data-rej-id]").forEach(btn => {
          btn.addEventListener("click", () => rejectSubscription(btn.getAttribute("data-rej-id"), btn));
        });
        container.querySelectorAll("[data-canc-id]").forEach(btn => {
          btn.addEventListener("click", () => cancelSubscription(btn.getAttribute("data-canc-id"), btn));
        });
        container.querySelectorAll("[data-dates-id]").forEach(btn => {
          btn.addEventListener("click", () => {
            openAdminDateModal(btn.getAttribute("data-dates-id"), btn.getAttribute("data-start"), btn.getAttribute("data-end"));
          });
        });
        container.querySelectorAll("[data-renew-id]").forEach(btn => {
          btn.addEventListener("click", () => {
            openAdminRenewModal({
              id: btn.getAttribute("data-renew-id"),
              user: btn.getAttribute("data-user"),
              plan: btn.getAttribute("data-plan")
            });
          });
        });
        container.querySelectorAll("[data-extend-id]").forEach(btn => {
          btn.addEventListener("click", () => {
            openAdminExtendModal({
              id: btn.getAttribute("data-extend-id"),
              user: btn.getAttribute("data-user"),
              plan: btn.getAttribute("data-plan")
            });
          });
        });
      };

      bindActions(cardsGrid);
      bindActions(tbody);
    } catch (_) {
      if (cardsGrid) {
        cardsGrid.innerHTML = `
          <div class="admin-cards-state error-state">
            <div class="state-icon-wrap"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>Network Error Loading Subscriptions</h4>
            <p>Unable to connect to the backend subscription service.</p>
          </div>
        `;
      }
      if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">Network error loading subscriptions.</td></tr>`;
    }
  }

  // Load Operators / Users with Search and Filtering
  // Load Operators / Users with Search, Role, Status, and Subscription Filtering
  // Load Operators / Users with Responsive Card-Based Layout, Search, and Multi-Filtering
  async function loadAdminUsers() {
    const cardsGrid = document.getElementById("adminUsersCardsGrid");
    const targetTbody = document.getElementById("adminUsersTbody");
    const searchInput = document.getElementById("adminUserSearchInput");
    const roleFilter = document.getElementById("adminUserRoleFilter");
    const statusFilter = document.getElementById("adminUserStatusFilter");
    const subStatusFilter = document.getElementById("adminUserSubStatusFilter");
    if (!cardsGrid && !targetTbody) return;

    if (cardsGrid) {
      cardsGrid.innerHTML = `
        <div class="admin-cards-state loading-state">
          <div class="state-icon-wrap"><i class="fas fa-circle-notch fa-spin"></i></div>
          <h4>Loading Operator Accounts...</h4>
          <p>Fetching real-time user records and subscription statuses.</p>
        </div>
      `;
    }
    if (targetTbody) {
      targetTbody.innerHTML = `<tr><td colspan="9" class="text-center py-4"><i class="fas fa-circle-notch fa-spin"></i> Loading operators...</td></tr>`;
    }

    const searchVal = searchInput ? searchInput.value.trim() : "";
    const roleVal = roleFilter ? roleFilter.value : "";
    const statusVal = statusFilter ? statusFilter.value : "";
    const subStatusVal = subStatusFilter ? subStatusFilter.value : "";

    const params = new URLSearchParams();
    if (searchVal) params.set("search", searchVal);
    if (roleVal) params.set("role", roleVal);
    if (statusVal) params.set("status", statusVal);
    if (subStatusVal) params.set("sub_status", subStatusVal);

    try {
      const url = params.toString() ? `/api/admin/users?${params.toString()}` : `/api/admin/users`;
      const res = await fetch(url, { credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        const errorMsg = data.message || "Unable to load operators.";
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state error-state">
              <div class="state-icon-wrap text-danger"><i class="fas fa-triangle-exclamation"></i></div>
              <h4>Unable to Load Operators</h4>
              <p>${escapeHtml(errorMsg)}</p>
              <button type="button" class="btn-admin-action activate" id="retryLoadUsersBtn"><i class="fas fa-rotate"></i> Try Again</button>
            </div>
          `;
          const retryBtn = document.getElementById("retryLoadUsersBtn");
          if (retryBtn) retryBtn.addEventListener("click", loadAdminUsers);
        }
        if (targetTbody) targetTbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger py-4">${escapeHtml(errorMsg)}</td></tr>`;
        return;
      }

      const users = data.users || [];
      if (users.length === 0) {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state empty-state">
              <div class="state-icon-wrap"><i class="fas fa-users-slash"></i></div>
              <h4>No Operators Found</h4>
              <p>No operator accounts match the active search query or filter criteria.</p>
            </div>
          `;
        }
        if (targetTbody) targetTbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-muted"><i class="fas fa-users-slash"></i> No operators match the query or filter criteria.</td></tr>`;
        return;
      }

      let cardsHtml = "";
      let rowsHtml = "";

      for (const u of users) {
        const isSelf = currentUser && currentUser.id === u.id;
        const sub = u.current_subscription;
        const nameToUse = u.full_name || u.username || "Operator";
        const initials = nameToUse.split(/\s+/).map(w => w[0]).filter(Boolean).slice(0, 2).join("").toUpperCase() || "OP";

        // Role Info
        const isAdmin = u.role === "Admin";
        const roleClass = isAdmin ? "admin" : "user";
        const roleIcon = isAdmin ? "fa-shield-halved" : "fa-user";

        // Account Status Info
        const isActive = !!u.is_active;
        const statusClass = isActive ? "active" : "suspended";
        const statusIcon = isActive ? "fa-circle-check" : "fa-user-lock";
        const statusLabel = isActive ? "Active" : "Suspended";

        // Subscription Tier Info
        let subStatusClass = "none";
        let subStatusDisplay = "None";
        let subPlanTitle = "No Active Subscription";
        let subTimingText = "No active license assigned";

        if (sub) {
          subStatusClass = (sub.status || "active").toLowerCase();
          subStatusDisplay = sub.status ? sub.status.charAt(0).toUpperCase() + sub.status.slice(1) : "Active";
          subPlanTitle = sub.plan_name || (sub.status === "pending" ? "Pending Approval" : "Subscription Plan");
          if (sub.end_date) {
            subTimingText = `Expires ${formatUtcDate(sub.end_date)}`;
          } else if (sub.status === "pending") {
            subTimingText = "Awaiting admin provisioning";
          } else {
            subTimingText = "Active ongoing license";
          }
        }

        // Action Buttons for Card
        let cardActionsHtml = `
          <button type="button" class="btn-card-action btn-card-details" data-view-user="${u.id}" title="View operator dossier, credentials, and full subscription lifecycle">
            <i class="fas fa-folder-open"></i> Details
          </button>
        `;

        if (!isSelf) {
          if (isActive) {
            cardActionsHtml += `
              <button type="button" class="btn-card-action btn-card-suspend" data-user-toggle="${u.id}" data-action="suspend" title="Suspend operator account and terminate active sessions">
                <i class="fas fa-user-lock"></i> Suspend
              </button>
            `;
          } else {
            cardActionsHtml += `
              <button type="button" class="btn-card-action btn-card-activate" data-user-toggle="${u.id}" data-action="activate" title="Reactivate operator account and permit login access">
                <i class="fas fa-user-check"></i> Restore
              </button>
            `;
          }

          if (isAdmin) {
            cardActionsHtml += `
              <button type="button" class="btn-card-action btn-card-role-demote" data-user-role="${u.id}" data-new-role="User" title="Demote administrator to standard user">
                <i class="fas fa-arrow-down"></i> Demote
              </button>
            `;
          } else {
            cardActionsHtml += `
              <button type="button" class="btn-card-action btn-card-role-promote" data-user-role="${u.id}" data-new-role="Admin" title="Promote operator to Administrator">
                <i class="fas fa-arrow-up"></i> Make Admin
              </button>
            `;
          }

          cardActionsHtml += `
            <button type="button" class="btn-card-action btn-card-delete" data-delete-user="${u.id}" data-username="${escapeHtml(u.username)}" title="Delete or safely archive operator account">
              <i class="fas fa-trash-can"></i>
            </button>
          `;
        } else {
          cardActionsHtml += `
            <div class="user-card-self-badge">
              <i class="fas fa-user-shield"></i> You (Current Account)
            </div>
          `;
        }

        // Card Template
        cardsHtml += `
          <div class="admin-user-card role-${roleClass} status-${statusClass}" id="adminUserCard_${u.id}">
            <!-- Card Header: Identity & Badges -->
            <div class="user-card-header">
              <div class="user-card-identity">
                <div class="user-card-avatar avatar-${roleClass}">
                  <span class="avatar-initials">${initials}</span>
                  <span class="avatar-status-pip pip-${statusClass}" title="Status: ${statusLabel}"></span>
                </div>
                <div class="user-card-names">
                  <div class="user-card-title-row">
                    <h4 class="user-card-username" title="${escapeHtml(u.username)}">${escapeHtml(u.username)}</h4>
                    <span class="user-id-chip">#${u.id}</span>
                  </div>
                  <div class="user-card-fullname">${escapeHtml(u.full_name || 'No display name configured')}</div>
                </div>
              </div>
              <div class="user-card-badge-col">
                <span class="user-role-badge role-${roleClass}">
                  <i class="fas ${roleIcon}"></i> ${escapeHtml(u.role)}
                </span>
                <span class="user-status-pill status-${statusClass}">
                  <i class="fas ${statusIcon}"></i> ${statusLabel}
                </span>
              </div>
            </div>

            <!-- Card Body: Contact & Activity Meta -->
            <div class="user-card-body">
              <div class="user-card-meta-list">
                <div class="user-card-meta-item" title="${escapeHtml(u.email)}">
                  <i class="fas fa-envelope meta-icon"></i>
                  <span class="meta-text text-truncate">${escapeHtml(u.email)}</span>
                </div>
                <div class="user-card-meta-row">
                  <div class="user-card-meta-item" title="Registration Date">
                    <i class="fas fa-calendar-plus meta-icon"></i>
                    <span class="meta-text"><small class="text-muted">Joined:</small> ${formatUtcDate(u.created_at)}</span>
                  </div>
                  <div class="user-card-meta-item" title="Last Login Timestamp">
                    <i class="fas fa-clock meta-icon"></i>
                    <span class="meta-text"><small class="text-muted">Last Login:</small> ${u.last_login_at ? formatUtcDate(u.last_login_at) : 'Never'}</span>
                  </div>
                </div>
              </div>

              <!-- Subscription Tier Box -->
              <div class="user-card-sub-box sub-box-${subStatusClass}">
                <div class="user-card-sub-top">
                  <span class="sub-tier-label" title="${escapeHtml(subPlanTitle)}">
                    <i class="fas fa-id-card"></i> ${escapeHtml(subPlanTitle)}
                  </span>
                  <span class="card-sub-badge sub-${subStatusClass}">${escapeHtml(subStatusDisplay)}</span>
                </div>
                <div class="user-card-sub-bottom">
                  <span class="sub-timing-text"><i class="fas fa-hourglass-half"></i> ${subTimingText}</span>
                </div>
              </div>
            </div>

            <!-- Dedicated Actions Area -->
            <div class="user-card-actions">
              ${cardActionsHtml}
            </div>
          </div>
        `;

        // Synchronize fallback table row for backward compatibility
        rowsHtml += `
          <tr>
            <td><code>#${u.id}</code></td>
            <td><strong>${escapeHtml(u.username)}</strong>${u.full_name ? `<br><small class="text-muted">${escapeHtml(u.full_name)}</small>` : ''}</td>
            <td>${escapeHtml(u.email)}</td>
            <td><span class="user-role-badge ${isAdmin ? 'admin-badge' : ''}">${escapeHtml(u.role)}</span></td>
            <td><span class="sub-badge ${isActive ? 'active' : 'expired'}">${statusLabel}</span></td>
            <td>${u.last_login_at ? formatUtcDate(u.last_login_at) : 'Never'}</td>
            <td>${formatUtcDate(u.created_at)}</td>
            <td>${escapeHtml(subPlanTitle)}</td>
            <td>${cardActionsHtml}</td>
          </tr>
        `;
      }

      if (cardsGrid) cardsGrid.innerHTML = cardsHtml;
      if (targetTbody) targetTbody.innerHTML = rowsHtml;

      // Bind Event Listeners across Cards Grid and Table
      const containers = [cardsGrid, targetTbody].filter(Boolean);
      containers.forEach(container => {
        container.querySelectorAll("[data-view-user]").forEach(btn => {
          btn.addEventListener("click", () => {
            openAdminUserDetails(btn.getAttribute("data-view-user"));
          });
        });

        container.querySelectorAll("[data-user-toggle]").forEach(btn => {
          btn.addEventListener("click", () => {
            const uid = btn.getAttribute("data-user-toggle");
            const action = btn.getAttribute("data-action");
            toggleUserActive(uid, action === "activate", btn);
          });
        });

        container.querySelectorAll("[data-user-role]").forEach(btn => {
          btn.addEventListener("click", () => {
            const uid = btn.getAttribute("data-user-role");
            const newRole = btn.getAttribute("data-new-role");
            toggleUserRole(uid, newRole, btn);
          });
        });

        container.querySelectorAll("[data-delete-user]").forEach(btn => {
          btn.addEventListener("click", () => {
            const uid = btn.getAttribute("data-delete-user");
            const username = btn.getAttribute("data-username");
            deleteAdminUser(uid, username, btn);
          });
        });
      });

    } catch (err) {
      if (cardsGrid) {
        cardsGrid.innerHTML = `
          <div class="admin-cards-state error-state">
            <div class="state-icon-wrap text-danger"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>Network Error Loading Operators</h4>
            <p>Could not connect to server. Please verify network connectivity and try again.</p>
            <button type="button" class="btn-admin-action activate" id="retryLoadUsersBtn"><i class="fas fa-rotate"></i> Try Again</button>
          </div>
        `;
        const retryBtn = document.getElementById("retryLoadUsersBtn");
        if (retryBtn) retryBtn.addEventListener("click", loadAdminUsers);
      }
      if (targetTbody) targetTbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger py-4">Network error loading operators.</td></tr>`;
    }
  }

  // Operator Moderation Handlers: Toggle Active Status
  async function toggleUserActive(userId, targetActive, btn) {
    if (!userId) return;
    const actionText = targetActive ? "reactivate" : "suspend";
    if (!targetActive) {
      if (!confirm("Are you sure you want to suspend this operator account? Active sessions will be terminated and login access will be blocked.")) return;
    }
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>'; }
    try {
      const res = await fetch(`/api/admin/users/${userId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ is_active: targetActive })
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.message || `Failed to ${actionText} operator.`);
      } else {
        if (typeof showToast === "function") showToast(data.message || `Account ${actionText}d successfully.`, "success");
      }
      await loadAdminUsers();
      if (typeof loadAdminMetrics === "function") loadAdminMetrics();
    } catch (_) {
      alert(`Network error attempting to ${actionText} account.`);
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
    }
  }

  // Operator Moderation Handlers: Delete / Archive Account
  async function deleteAdminUser(userId, username, btn) {
    if (!userId) return;
    const confirmed = confirm(`Are you sure you want to delete or archive operator '${username || '#' + userId}'?\n\nIf the operator has historical subscriptions, the account will be safely archived to preserve audit integrity. Otherwise, it will be permanently deleted.`);
    if (!confirmed) return;
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>'; }
    try {
      const res = await fetch(`/api/admin/users/${userId}`, {
        method: "DELETE",
        credentials: "same-origin"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.message || "Failed to delete/archive user.");
      } else {
        if (typeof showToast === "function") showToast(data.message || "User account successfully processed.", "success");
        await loadAdminUsers();
        if (typeof loadAdminMetrics === "function") loadAdminMetrics();
      }
    } catch (_) {
      alert("Network error processing user deletion.");
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
    }
  }

  // Operator Dossier Modal Controller
  const adminUserDetailsModal = document.getElementById("adminUserDetailsModal");
  const adminUserDetailsModalCloseBtn = document.getElementById("adminUserDetailsModalCloseBtn");
  const adminUserDetailsModalBackdrop = document.getElementById("adminUserDetailsModalBackdrop");
  const adminUserDetailsAlert = document.getElementById("adminUserDetailsAlert");

  async function openAdminUserDetails(userId) {
    if (!adminUserDetailsModal || !userId) return;
    if (adminUserDetailsAlert) adminUserDetailsAlert.style.display = "none";
    adminUserDetailsModal.style.display = "flex";
    document.body.style.overflow = "hidden";

    const dId = document.getElementById("dossierUserId");
    const dUser = document.getElementById("dossierUsername");
    const dEmail = document.getElementById("dossierEmail");
    const dName = document.getElementById("dossierFullName");
    const dRole = document.getElementById("dossierRole");
    const dStatus = document.getElementById("dossierStatus");
    const dCreated = document.getElementById("dossierCreated");
    const dLogin = document.getElementById("dossierLastLogin");
    const actionsToolbar = document.getElementById("adminDossierActions");
    const historyTbody = document.getElementById("adminUserSubsHistoryTbody");

    if (historyTbody) historyTbody.innerHTML = `<tr><td colspan="6" class="text-center py-3"><i class="fas fa-circle-notch fa-spin"></i> Loading subscription history...</td></tr>`;

    try {
      const res = await fetch(`/api/admin/users/${userId}`, { credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || data.status !== "success" || !data.user) {
        if (adminUserDetailsAlert) {
          adminUserDetailsAlert.className = "auth-alert error";
          adminUserDetailsAlert.textContent = data.message || "Failed to load operator record.";
          adminUserDetailsAlert.style.display = "block";
        }
        return;
      }

      const u = data.user;
      if (dId) dId.textContent = `#${u.id}`;
      if (dUser) dUser.textContent = u.username;
      if (dEmail) dEmail.textContent = u.email;
      if (dName) dName.textContent = u.full_name || "—";
      if (dRole) dRole.textContent = u.role;
      if (dStatus) {
        dStatus.textContent = u.is_active ? "Active" : "Suspended";
        dStatus.className = u.is_active ? "dossier-val text-success" : "dossier-val text-danger";
      }
      if (dCreated) dCreated.textContent = formatUtcDate(u.created_at);
      if (dLogin) dLogin.textContent = u.last_login_at ? formatUtcDate(u.last_login_at) : "Never Logged In";

      // Populate Admin Edit Inputs
      const editNameInput = document.getElementById("adminUserEditFullName");
      const editEmailInput = document.getElementById("adminUserEditEmail");
      const editSaveBtn = document.getElementById("adminUserEditSaveBtn");
      const editMsg = document.getElementById("adminUserEditMsg");
      if (editNameInput) editNameInput.value = u.full_name || "";
      if (editEmailInput) editEmailInput.value = u.email || "";
      if (editMsg) editMsg.style.display = "none";
      if (editSaveBtn) {
        editSaveBtn.onclick = async () => {
          const fn = editNameInput ? editNameInput.value.trim() : "";
          const em = editEmailInput ? editEmailInput.value.trim() : "";
          editSaveBtn.disabled = true;
          editSaveBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Saving...';
          try {
            const resp = await fetch(`/api/admin/users/${u.id}`, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              credentials: "same-origin",
              body: JSON.stringify({ full_name: fn, email: em })
            });
            const rData = await resp.json();
            if (resp.ok && rData.status === "success") {
              if (editMsg) {
                editMsg.style.display = "block";
                editMsg.style.background = "rgba(16, 185, 129, 0.15)";
                editMsg.style.color = "#10B981";
                editMsg.textContent = rData.message || "Profile updated successfully.";
              }
              openAdminUserDetails(u.id);
              if (typeof loadAdminUsers === "function") loadAdminUsers();
            } else {
              if (editMsg) {
                editMsg.style.display = "block";
                editMsg.style.background = "rgba(239, 68, 68, 0.15)";
                editMsg.style.color = "#EF4444";
                editMsg.textContent = rData.message || "Update failed.";
              }
            }
          } catch (err) {
            if (editMsg) {
              editMsg.style.display = "block";
              editMsg.style.background = "rgba(239, 68, 68, 0.15)";
              editMsg.style.color = "#EF4444";
              editMsg.textContent = "Network error updating profile.";
            }
          } finally {
            editSaveBtn.disabled = false;
            editSaveBtn.innerHTML = '<i class="fas fa-save"></i> Save Profile';
          }
        };
      }

      // Render Modal Actions
      const isSelf = currentUser && currentUser.id === u.id;
      if (actionsToolbar) {
        if (isSelf) {
          actionsToolbar.innerHTML = `<span class="text-muted"><i class="fas fa-info-circle"></i> This is your currently authenticated Administrator account.</span>`;
        } else {
          actionsToolbar.innerHTML = `
            <button type="button" class="btn-admin-action ${u.is_active ? 'reject' : 'activate'}" id="dossierToggleStatusBtn">
              <i class="fas ${u.is_active ? 'fa-user-lock' : 'fa-user-check'}"></i> ${u.is_active ? 'Suspend Account' : 'Reactivate Account'}
            </button>
            <button type="button" class="btn-admin-action cancel" id="dossierToggleRoleBtn">
              <i class="fas ${u.role === 'Admin' ? 'fa-arrow-down' : 'fa-arrow-up'}"></i> ${u.role === 'Admin' ? 'Demote to User' : 'Promote to Admin'}
            </button>
            <button type="button" class="btn-admin-action" id="dossierDeleteBtn" style="background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3);">
              <i class="fas fa-trash-can"></i> Delete / Archive Account
            </button>
          `;
          const toggleStatusBtn = document.getElementById("dossierToggleStatusBtn");
          if (toggleStatusBtn) {
            toggleStatusBtn.addEventListener("click", () => {
              toggleUserActive(u.id, !u.is_active, toggleStatusBtn).then(() => openAdminUserDetails(u.id));
            });
          }
          const toggleRoleBtn = document.getElementById("dossierToggleRoleBtn");
          if (toggleRoleBtn) {
            toggleRoleBtn.addEventListener("click", () => {
              const targetRole = u.role === "Admin" ? "User" : "Admin";
              toggleUserRole(u.id, targetRole, toggleRoleBtn).then(() => openAdminUserDetails(u.id));
            });
          }
          const deleteBtn = document.getElementById("dossierDeleteBtn");
          if (deleteBtn) {
            deleteBtn.addEventListener("click", async () => {
              if (!confirm(`Are you sure you want to remove or archive operator '${u.username}'? Subscriptions will be preserved.`)) return;
              deleteBtn.disabled = true;
              try {
                const dRes = await fetch(`/api/admin/users/${u.id}`, {
                  method: "DELETE",
                  credentials: "same-origin"
                });
                const dData = await dRes.json();
                if (dRes.ok && dData.status === "success") {
                  if (typeof showToast === "function") showToast(dData.message, "success");
                  if (adminUserDetailsModal) adminUserDetailsModal.style.display = "none";
                  document.body.style.overflow = "";
                  if (typeof loadAdminUsers === "function") loadAdminUsers();
                  if (typeof loadAdminMetrics === "function") loadAdminMetrics();
                } else {
                  alert(dData.message || "Failed to delete/archive user.");
                }
              } catch (err) {
                alert("Network error processing user deletion.");
              } finally {
                deleteBtn.disabled = false;
              }
            });
          }
        }
      }

      // Render Subscriptions History
      const subs = u.subscriptions || [];
      if (historyTbody) {
        if (subs.length === 0) {
          historyTbody.innerHTML = `<tr><td colspan="6" class="text-center py-3 text-muted">No historical subscription records found.</td></tr>`;
        } else {
          let hHtml = "";
          for (const s of subs) {
            const bClass = s.status === "active" ? "active" : (s.status === "pending" ? "pending" : (s.status === "expired" ? "expired" : "canceled"));
            hHtml += `
              <tr>
                <td><strong>#${s.id}</strong></td>
                <td>${escapeHtml(s.plan_name || s.plan_code || 'Plan')}</td>
                <td><span class="sub-badge ${bClass}">${escapeHtml(s.status)}</span></td>
                <td>${formatUtcDate(s.start_date)}</td>
                <td>${formatUtcDate(s.end_date)}</td>
                <td><small class="text-muted">${escapeHtml(s.admin_notes || s.cancellation_reason || '—')}</small></td>
              </tr>
            `;
          }
          historyTbody.innerHTML = hHtml;
        }
      }
    } catch (_) {
      if (adminUserDetailsAlert) {
        adminUserDetailsAlert.className = "auth-alert error";
        adminUserDetailsAlert.textContent = "Network error loading dossier.";
        adminUserDetailsAlert.style.display = "block";
      }
    }
  }

  if (adminUserDetailsModalCloseBtn) {
    adminUserDetailsModalCloseBtn.addEventListener("click", () => {
      if (adminUserDetailsModal) adminUserDetailsModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }
  if (adminUserDetailsModalBackdrop) {
    adminUserDetailsModalBackdrop.addEventListener("click", () => {
      if (adminUserDetailsModal) adminUserDetailsModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }



  // Load Plan Catalog for Admin with Responsive Card-Based Layout and Fallback Table Sync
  let adminPlansCache = [];
  async function loadAdminPlans() {
    const cardsGrid = document.getElementById("adminPlansCardsGrid");
    const tbody = document.getElementById("adminPlansTbody");
    const plansMetric = document.getElementById("adminMetricPlans");
    if (!cardsGrid && !tbody) return;

    if (cardsGrid) {
      cardsGrid.innerHTML = `
        <div class="admin-cards-state loading-state">
          <div class="state-icon-wrap"><i class="fas fa-circle-notch fa-spin"></i></div>
          <h4>Loading Subscription Plans...</h4>
          <p>Fetching active and archived plan specifications.</p>
        </div>
      `;
    }
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4"><i class="fas fa-circle-notch fa-spin"></i> Loading plans...</td></tr>`;
    }

    try {
      const res = await fetch("/api/admin/plans", { credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state error-state">
              <div class="state-icon-wrap"><i class="fas fa-triangle-exclamation"></i></div>
              <h4>Unable to Load Plans</h4>
              <p>${escapeHtml(data.message || "Failed to retrieve subscription plan catalog.")}</p>
            </div>
          `;
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">Unable to load plans.</td></tr>`;
        return;
      }

      const plans = data.plans || [];
      adminPlansCache = plans;
      if (plansMetric) plansMetric.textContent = plans.filter(p => p.is_active).length;

      if (plans.length === 0) {
        if (cardsGrid) {
          cardsGrid.innerHTML = `
            <div class="admin-cards-state empty-state">
              <div class="state-icon-wrap"><i class="fas fa-layer-group"></i></div>
              <h4>No Subscription Plans Configured</h4>
              <p>No plans have been created yet. Click "Create New Plan" to configure your first subscription tier.</p>
            </div>
          `;
        }
        if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted">No plans configured yet. Click "Create New Plan" to add one.</td></tr>`;
        return;
      }

      let cardsHtml = "";
      let rowsHtml = "";
      for (const p of plans) {
        const codeDisplay = p.plan_code || p.id;
        const priceStr = `${escapeHtml(p.currency || 'USD')} ${p.price === 0 ? 'Free' : '$' + p.price.toFixed(2)}`;
        const durationStr = `${p.duration_value} ${p.duration_unit || 'days'}`;
        const f = p.features || {};
        const feats = [];
        if (f.can_live_monitoring) feats.push("Live Telemetry");
        if (f.can_port_scan) feats.push("Port Scanner");
        if (f.can_network_discovery) feats.push("Network Discovery");
        const featsStr = feats.join(", ") || "None";
        const subsCount = p.total_subscribers ?? p.subscribers_count ?? 0;
        const activeSubsCount = p.active_subscribers ?? 0;

        cardsHtml += `
          <div class="admin-plan-card ${p.is_active ? 'plan-active' : 'plan-archived'}" data-card-plan-id="${p.id}">
            <div class="plan-card-header">
              <div class="plan-code-wrap">
                <span class="plan-code-chip">${escapeHtml(codeDisplay)}</span>
                <span class="sub-badge ${p.is_active ? 'active' : 'expired'}">
                  <i class="fas ${p.is_active ? 'fa-circle-check' : 'fa-archive'}"></i>
                  ${p.is_active ? 'Active' : 'Archived'}
                </span>
              </div>
              <h3 class="plan-card-name">${escapeHtml(p.name)}</h3>
              ${p.description ? `<p class="plan-card-desc">${escapeHtml(p.description)}</p>` : '<p class="plan-card-desc text-muted italic">No public description provided.</p>'}
            </div>
            <div class="plan-card-pricing">
              <div class="plan-price-wrap">
                <span class="plan-price-val">${p.price === 0 ? 'Free' : '$' + p.price.toFixed(2)}</span>
                <span class="plan-price-term">${p.price === 0 ? '' : escapeHtml(p.currency || 'USD')} / ${escapeHtml(durationStr)}</span>
              </div>
              <div class="plan-sub-badge" title="${activeSubsCount} active subscriber(s) out of ${subsCount} total">
                <i class="fas fa-users"></i> ${subsCount} subscribers <span class="active-count">(${activeSubsCount} active)</span>
              </div>
            </div>
            <div class="plan-card-features">
              <span class="plan-features-title"><i class="fas fa-shield-halved"></i> Entitlements & Features:</span>
              <ul class="plan-features-list">
                <li class="${f.can_live_monitoring ? 'enabled' : 'disabled'}">
                  <i class="fas ${f.can_live_monitoring ? 'fa-check' : 'fa-xmark'}"></i> Live Telemetry & Monitoring
                </li>
                <li class="${f.can_port_scan ? 'enabled' : 'disabled'}">
                  <i class="fas ${f.can_port_scan ? 'fa-check' : 'fa-xmark'}"></i> Port Vulnerability Scanner
                </li>
                <li class="${f.can_network_discovery ? 'enabled' : 'disabled'}">
                  <i class="fas ${f.can_network_discovery ? 'fa-check' : 'fa-xmark'}"></i> Network Discovery & Mapping
                </li>
              </ul>
            </div>
            <div class="plan-card-footer">
              <button type="button" class="btn-admin-action dates" data-plan-edit-id="${p.id}" title="Edit plan parameters">
                <i class="fas fa-pen-to-square"></i> Edit
              </button>
              <button type="button" class="btn-admin-action ${p.is_active ? 'reject' : 'activate'}" data-plan-status-id="${p.id}" data-new-status="${!p.is_active}" title="${p.is_active ? 'Deactivate and archive plan' : 'Restore and activate plan'}">
                ${p.is_active ? '<i class="fas fa-power-off"></i> Archive' : '<i class="fas fa-check"></i> Restore'}
              </button>
              <button type="button" class="btn-admin-action cancel" data-plan-delete-id="${p.id}" data-plan-name="${escapeHtml(p.name)}" data-plan-subs="${subsCount}" title="Delete or Archive Plan">
                <i class="fas fa-trash-can"></i>
              </button>
            </div>
          </div>
        `;

        rowsHtml += `
          <tr>
            <td><code>${escapeHtml(codeDisplay)}</code></td>
            <td><strong>${escapeHtml(p.name)}</strong></td>
            <td>${priceStr}</td>
            <td>${durationStr}</td>
            <td><small>${escapeHtml(featsStr)}</small></td>
            <td><span class="sub-badge ${subsCount > 0 ? 'active' : 'expired'}" title="${activeSubsCount} currently active"><i class="fas fa-users"></i> ${subsCount} (${activeSubsCount} active)</span></td>
            <td><span class="sub-badge ${p.is_active ? 'active' : 'expired'}">${p.is_active ? 'Active' : 'Archived'}</span></td>
            <td>
              <div class="admin-action-btn-group">
                <button type="button" class="btn-admin-action dates" data-plan-edit-id="${p.id}" title="Edit plan parameters">
                  <i class="fas fa-pen-to-square"></i> Edit
                </button>
                <button type="button" class="btn-admin-action ${p.is_active ? 'reject' : 'activate'}" data-plan-status-id="${p.id}" data-new-status="${!p.is_active}" title="${p.is_active ? 'Deactivate' : 'Activate'} plan">
                  ${p.is_active ? '<i class="fas fa-power-off"></i> Archive' : '<i class="fas fa-check"></i> Restore'}
                </button>
                <button type="button" class="btn-admin-action cancel" data-plan-delete-id="${p.id}" data-plan-name="${escapeHtml(p.name)}" data-plan-subs="${subsCount}" title="Delete or Archive Plan">
                  <i class="fas fa-trash-can"></i>
                </button>
              </div>
            </td>
          </tr>
        `;
      }

      if (cardsGrid) cardsGrid.innerHTML = cardsHtml;
      if (tbody) tbody.innerHTML = rowsHtml;

      const bindActions = (container) => {
        if (!container) return;
        container.querySelectorAll("[data-plan-edit-id]").forEach(btn => {
          btn.addEventListener("click", () => {
            const pid = parseInt(btn.getAttribute("data-plan-edit-id"), 10);
            const targetPlan = adminPlansCache.find(x => x.id === pid);
            if (targetPlan) openEditPlanModal(targetPlan);
          });
        });

        container.querySelectorAll("[data-plan-status-id]").forEach(btn => {
          btn.addEventListener("click", () => {
            const pid = btn.getAttribute("data-plan-status-id");
            const nst = btn.getAttribute("data-new-status") === "true";
            togglePlanActive(pid, nst, btn);
          });
        });

        container.querySelectorAll("[data-plan-delete-id]").forEach(btn => {
          btn.addEventListener("click", () => {
            const pid = btn.getAttribute("data-plan-delete-id");
            const name = btn.getAttribute("data-plan-name");
            const subs = parseInt(btn.getAttribute("data-plan-subs") || "0", 10);
            deletePlan(pid, name, subs);
          });
        });
      };

      bindActions(cardsGrid);
      bindActions(tbody);
    } catch (_) {
      if (cardsGrid) {
        cardsGrid.innerHTML = `
          <div class="admin-cards-state error-state">
            <div class="state-icon-wrap"><i class="fas fa-triangle-exclamation"></i></div>
            <h4>Network Error Loading Plans</h4>
            <p>Unable to connect to the backend plan catalog service.</p>
          </div>
        `;
      }
      if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger py-4">Network error loading plans.</td></tr>`;
    }
  }

  function openCreatePlanModal() {
    if (!adminPlanModal) return;
    const modalTitle = document.getElementById("adminPlanModalTitle");
    const modeInput = document.getElementById("planFormMode");
    const dbIdInput = document.getElementById("planFormDbId");
    const codeInput = document.getElementById("planFormCode");
    const nameInput = document.getElementById("planFormName");
    const descInput = document.getElementById("planFormDescription");
    const priceInput = document.getElementById("planFormPrice");
    const currInput = document.getElementById("planFormCurrency");
    const durValInput = document.getElementById("planFormDurationValue");
    const durUnitInput = document.getElementById("planFormDurationUnit");
    const monCheck = document.getElementById("planFormCanLiveMonitoring");
    const portCheck = document.getElementById("planFormCanPortScan");
    const ndCheck = document.getElementById("planFormCanNetworkDiscovery");
    const activeCheck = document.getElementById("planFormIsActive");

    if (modalTitle) modalTitle.textContent = "Create Subscription Plan";
    if (modeInput) modeInput.value = "create";
    if (dbIdInput) dbIdInput.value = "";
    if (codeInput) { codeInput.value = ""; codeInput.disabled = false; }
    if (nameInput) nameInput.value = "";
    if (descInput) descInput.value = "";
    if (priceInput) priceInput.value = "49.00";
    if (currInput) currInput.value = "USD";
    if (durValInput) durValInput.value = "30";
    if (durUnitInput) durUnitInput.value = "days";
    if (monCheck) monCheck.checked = true;
    if (portCheck) portCheck.checked = true;
    if (ndCheck) ndCheck.checked = false;
    if (activeCheck) activeCheck.checked = true;

    if (adminPlanAlert) adminPlanAlert.style.display = "none";
    adminPlanModal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }

  function openEditPlanModal(plan) {
    if (!adminPlanModal || !plan) return;
    const modalTitle = document.getElementById("adminPlanModalTitle");
    const modeInput = document.getElementById("planFormMode");
    const dbIdInput = document.getElementById("planFormDbId");
    const codeInput = document.getElementById("planFormCode");
    const nameInput = document.getElementById("planFormName");
    const descInput = document.getElementById("planFormDescription");
    const priceInput = document.getElementById("planFormPrice");
    const currInput = document.getElementById("planFormCurrency");
    const durValInput = document.getElementById("planFormDurationValue");
    const durUnitInput = document.getElementById("planFormDurationUnit");
    const monCheck = document.getElementById("planFormCanLiveMonitoring");
    const portCheck = document.getElementById("planFormCanPortScan");
    const ndCheck = document.getElementById("planFormCanNetworkDiscovery");
    const activeCheck = document.getElementById("planFormIsActive");

    if (modalTitle) modalTitle.textContent = `Edit Plan: ${plan.name}`;
    if (modeInput) modeInput.value = "edit";
    if (dbIdInput) dbIdInput.value = plan.id;
    if (codeInput) { codeInput.value = plan.plan_code || plan.id; codeInput.disabled = true; }
    if (nameInput) nameInput.value = plan.name || "";
    if (descInput) descInput.value = plan.description || "";
    if (priceInput) priceInput.value = plan.price !== undefined ? plan.price : "0";
    if (currInput) currInput.value = plan.currency || "USD";
    if (durValInput) durValInput.value = plan.duration_value || 30;
    if (durUnitInput) durUnitInput.value = plan.duration_unit || "days";

    const f = plan.features || {};
    if (monCheck) monCheck.checked = Boolean(f.can_live_monitoring);
    if (portCheck) portCheck.checked = Boolean(f.can_port_scan);
    if (ndCheck) ndCheck.checked = Boolean(f.can_network_discovery);
    if (activeCheck) activeCheck.checked = Boolean(plan.is_active);

    if (adminPlanAlert) adminPlanAlert.style.display = "none";
    adminPlanModal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }

  async function deletePlan(planId, name, subsCount) {
    if (!planId) return;
    const msg = subsCount > 0 
      ? `Plan "${name}" has ${subsCount} associated subscription(s).\n\nTo preserve historical data integrity, this plan will be safely archived (deactivated) rather than permanently removed.\n\nProceed with archiving?`
      : `Are you sure you want to permanently delete plan "${name}"? This operation cannot be undone.`;

    if (!confirm(msg)) return;

    try {
      const res = await fetch(`/api/admin/plans/${planId}`, {
        method: "DELETE",
        credentials: "same-origin"
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.message || "Failed to remove plan.");
      }
      loadAdminPlans();
      loadAdminMetrics();
      loadPublicHomepagePlans();
    } catch (_) {
      alert("Network error processing plan removal.");
    }
  }

  async function togglePlanActive(planId, newStatus, btn) {
    if (!planId) return;
    const actionLabel = newStatus ? "restore and activate" : "archive (deactivate)";
    if (!confirm(`Are you sure you want to ${actionLabel} plan #${planId}?\n\n${newStatus ? "The plan will become visible for subscription requests." : "The plan will be hidden from public selection, but existing subscribers will retain their terms."}`)) {
      return;
    }

    const originalContent = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
    }

    try {
      const res = await fetch(`/api/admin/plans/${planId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ is_active: newStatus })
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        loadAdminPlans();
        loadAdminMetrics();
        loadPublicHomepagePlans();
      } else {
        alert(data.message || "Failed to update plan status.");
      }
    } catch (_) {
      alert("Network error updating plan status.");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = originalContent;
      }
    }
  }

  // Admin Modals Handlers
  const adminPlanModal = document.getElementById("adminPlanModal");
  const adminPlanModalCloseBtn = document.getElementById("adminPlanModalCloseBtn");
  const adminPlanCancelBtn = document.getElementById("adminPlanCancelBtn");
  const adminPlanModalBackdrop = document.getElementById("adminPlanModalBackdrop");
  const adminCreatePlanBtn = document.getElementById("adminCreatePlanBtn");
  const adminPlanForm = document.getElementById("adminPlanForm");
  const adminPlanAlert = document.getElementById("adminPlanAlert");

  if (adminCreatePlanBtn) {
    adminCreatePlanBtn.addEventListener("click", () => {
      openCreatePlanModal();
    });
  }
  if (adminPlanModalCloseBtn) {
    adminPlanModalCloseBtn.addEventListener("click", () => {
      if (adminPlanModal) adminPlanModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }
  if (adminPlanCancelBtn) {
    adminPlanCancelBtn.addEventListener("click", () => {
      if (adminPlanModal) adminPlanModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }
  if (adminPlanModalBackdrop) {
    adminPlanModalBackdrop.addEventListener("click", () => {
      if (adminPlanModal) adminPlanModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }

  if (adminPlanForm) {
    adminPlanForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const mode = document.getElementById("planFormMode")?.value || "create";
      const dbId = document.getElementById("planFormDbId")?.value;
      const planCode = document.getElementById("planFormCode")?.value?.trim();
      const name = document.getElementById("planFormName")?.value?.trim();
      const description = document.getElementById("planFormDescription")?.value?.trim();
      const price = parseFloat(document.getElementById("planFormPrice")?.value || "0");
      const currency = document.getElementById("planFormCurrency")?.value?.trim() || "USD";
      const durationValue = parseInt(document.getElementById("planFormDurationValue")?.value || "30", 10);
      const durationUnit = document.getElementById("planFormDurationUnit")?.value || "days";
      const canLiveMonitoring = document.getElementById("planFormCanLiveMonitoring")?.checked ?? true;
      const canPortScan = document.getElementById("planFormCanPortScan")?.checked ?? true;
      const canNetworkDiscovery = document.getElementById("planFormCanNetworkDiscovery")?.checked ?? false;
      const isActive = document.getElementById("planFormIsActive")?.checked ?? true;

      if (!name || (mode === "create" && !planCode)) {
        if (adminPlanAlert) {
          adminPlanAlert.className = "auth-alert error";
          adminPlanAlert.textContent = "Please fill in all required plan fields.";
          adminPlanAlert.style.display = "block";
        }
        return;
      }

      if (price < 0 || isNaN(price)) {
        if (adminPlanAlert) {
          adminPlanAlert.className = "auth-alert error";
          adminPlanAlert.textContent = "Price must be a valid non-negative number.";
          adminPlanAlert.style.display = "block";
        }
        return;
      }

      if (durationValue <= 0 || isNaN(durationValue)) {
        if (adminPlanAlert) {
          adminPlanAlert.className = "auth-alert error";
          adminPlanAlert.textContent = "Duration term must be greater than zero.";
          adminPlanAlert.style.display = "block";
        }
        return;
      }

      const payload = {
        name,
        description,
        price,
        currency,
        duration_value: durationValue,
        duration_unit: durationUnit,
        is_active: isActive,
        features: {
          can_live_monitoring: canLiveMonitoring,
          can_port_scan: canPortScan,
          can_network_discovery: canNetworkDiscovery
        }
      };

      if (mode === "create") {
        payload.plan_code = planCode;
      }

      const submitBtn = document.getElementById("adminPlanSubmitBtn");
      if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Saving...'; }

      try {
        const url = mode === "edit" ? `/api/admin/plans/${dbId}` : `/api/admin/plans`;
        const method = mode === "edit" ? "PUT" : "POST";
        const res = await fetch(url, {
          method,
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          if (adminPlanModal) adminPlanModal.style.display = "none";
          document.body.style.overflow = "";
          loadAdminPlans();
          loadAdminMetrics();
          loadPublicHomepagePlans();
        } else {
          if (adminPlanAlert) {
            adminPlanAlert.className = "auth-alert error";
            adminPlanAlert.textContent = data.message || "Failed to save plan.";
            adminPlanAlert.style.display = "block";
          }
        }
      } catch (_) {
        if (adminPlanAlert) {
          adminPlanAlert.className = "auth-alert error";
          adminPlanAlert.textContent = "Network error saving plan.";
          adminPlanAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<span class="auth-btn-text">Save Plan Configuration</span> <i class="fas fa-check auth-btn-icon"></i>'; }
      }
    });
  }

  // Admin Date Adjustment Modal
  const adminDateModal = document.getElementById("adminDateModal");
  const adminDateModalCloseBtn = document.getElementById("adminDateModalCloseBtn");
  const adminDateModalBackdrop = document.getElementById("adminDateModalBackdrop");
  const adminDateForm = document.getElementById("adminDateForm");
  const adminDateAlert = document.getElementById("adminDateAlert");

  function openAdminDateModal(subId, startIso, endIso) {
    if (!adminDateModal) return;
    const subIdInput = document.getElementById("dateSubId");
    const endInput = document.getElementById("dateNewEndDate");
    if (subIdInput) subIdInput.value = subId;
    if (endInput && endIso) {
      try {
        endInput.value = new Date(endIso).toISOString().slice(0, 16);
      } catch (_) {}
    }
    if (adminDateAlert) adminDateAlert.style.display = "none";
    adminDateModal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }

  if (adminDateModalCloseBtn) {
    adminDateModalCloseBtn.addEventListener("click", () => {
      if (adminDateModal) adminDateModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }
  if (adminDateModalBackdrop) {
    adminDateModalBackdrop.addEventListener("click", () => {
      if (adminDateModal) adminDateModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }

  if (adminDateForm) {
    adminDateForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const subId = document.getElementById("dateSubId")?.value;
      const endVal = document.getElementById("dateNewEndDate")?.value;
      if (!subId || !endVal) return;

      try {
        const res = await fetch(`/api/admin/subscriptions/${subId}/adjust-dates`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            end_date: new Date(endVal).toISOString()
          })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          if (adminDateModal) adminDateModal.style.display = "none";
          document.body.style.overflow = "";
          loadAdminSubscriptions();
        } else {
          if (adminDateAlert) {
            adminDateAlert.className = "auth-alert error";
            adminDateAlert.textContent = data.message || "Failed to adjust dates.";
            adminDateAlert.style.display = "block";
          }
        }
      } catch (_) {
        if (adminDateAlert) {
          adminDateAlert.className = "auth-alert error";
          adminDateAlert.textContent = "Network error adjusting dates.";
          adminDateAlert.style.display = "block";
        }
      }
    });
  }

  // Admin Renew Subscription Modal
  const adminRenewSubModal = document.getElementById("adminRenewSubModal");
  const adminRenewSubModalCloseBtn = document.getElementById("adminRenewSubModalCloseBtn");
  const adminRenewSubModalBackdrop = document.getElementById("adminRenewSubModalBackdrop");
  const adminRenewSubForm = document.getElementById("adminRenewSubForm");
  const adminRenewSubAlert = document.getElementById("adminRenewSubAlert");

  function openAdminRenewModal(subInfo) {
    if (!adminRenewSubModal || !subInfo) return;
    const idInput = document.getElementById("renewSubId");
    const targetDisp = document.getElementById("renewSubTargetDisplay");
    const notesInput = document.getElementById("renewSubNotes");

    if (idInput) idInput.value = subInfo.id;
    if (targetDisp) targetDisp.textContent = `Subscription #${subInfo.id} · ${subInfo.user} (${subInfo.plan})`;
    if (notesInput) notesInput.value = "Administrative renewal under approved policy";
    if (adminRenewSubAlert) adminRenewSubAlert.style.display = "none";

    adminRenewSubModal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }

  if (adminRenewSubModalCloseBtn) {
    adminRenewSubModalCloseBtn.addEventListener("click", () => {
      if (adminRenewSubModal) adminRenewSubModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }
  if (adminRenewSubModalBackdrop) {
    adminRenewSubModalBackdrop.addEventListener("click", () => {
      if (adminRenewSubModal) adminRenewSubModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }

  if (adminRenewSubForm) {
    adminRenewSubForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const subId = document.getElementById("renewSubId")?.value;
      const notes = document.getElementById("renewSubNotes")?.value?.trim();
      if (!subId) return;

      const submitBtn = document.getElementById("adminRenewSubSubmitBtn");
      if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Renewing...'; }

      try {
        const res = await fetch(`/api/admin/subscriptions/${subId}/renew`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ notes })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          if (adminRenewSubModal) adminRenewSubModal.style.display = "none";
          document.body.style.overflow = "";
          loadAdminSubscriptions();
          loadAdminMetrics();
        } else {
          if (adminRenewSubAlert) {
            adminRenewSubAlert.className = "auth-alert error";
            adminRenewSubAlert.textContent = data.message || "Failed to renew subscription.";
            adminRenewSubAlert.style.display = "block";
          }
        }
      } catch (_) {
        if (adminRenewSubAlert) {
          adminRenewSubAlert.className = "auth-alert error";
          adminRenewSubAlert.textContent = "Network error renewing subscription.";
          adminRenewSubAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<span class="auth-btn-text">Confirm & Renew Subscription</span> <i class="fas fa-rotate auth-btn-icon"></i>'; }
      }
    });
  }

  // Admin Extend Subscription Modal
  const adminExtendSubModal = document.getElementById("adminExtendSubModal");
  const adminExtendSubModalCloseBtn = document.getElementById("adminExtendSubModalCloseBtn");
  const adminExtendSubModalBackdrop = document.getElementById("adminExtendSubModalBackdrop");
  const adminExtendSubForm = document.getElementById("adminExtendSubForm");
  const adminExtendSubAlert = document.getElementById("adminExtendSubAlert");

  function openAdminExtendModal(subInfo) {
    if (!adminExtendSubModal || !subInfo) return;
    const idInput = document.getElementById("extendSubId");
    const targetDisp = document.getElementById("extendSubTargetDisplay");
    const valInput = document.getElementById("extendDurationValue");
    const unitInput = document.getElementById("extendDurationUnit");
    const notesInput = document.getElementById("extendSubNotes");

    if (idInput) idInput.value = subInfo.id;
    if (targetDisp) targetDisp.textContent = `Subscription #${subInfo.id} · ${subInfo.user} (${subInfo.plan})`;
    if (valInput) valInput.value = "30";
    if (unitInput) unitInput.value = "days";
    if (notesInput) notesInput.value = "Administrative extension courtesy grant";
    if (adminExtendSubAlert) adminExtendSubAlert.style.display = "none";

    adminExtendSubModal.style.display = "flex";
    document.body.style.overflow = "hidden";
  }

  if (adminExtendSubModalCloseBtn) {
    adminExtendSubModalCloseBtn.addEventListener("click", () => {
      if (adminExtendSubModal) adminExtendSubModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }
  if (adminExtendSubModalBackdrop) {
    adminExtendSubModalBackdrop.addEventListener("click", () => {
      if (adminExtendSubModal) adminExtendSubModal.style.display = "none";
      document.body.style.overflow = "";
    });
  }

  // Duration Presets (+7d, +30d, +90d)
  document.querySelectorAll(".duration-presets-group .preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = btn.getAttribute("data-preset-val");
      const unit = btn.getAttribute("data-preset-unit");
      const valInput = document.getElementById("extendDurationValue");
      const unitInput = document.getElementById("extendDurationUnit");
      if (valInput && val) valInput.value = val;
      if (unitInput && unit) unitInput.value = unit;
    });
  });

  if (adminExtendSubForm) {
    adminExtendSubForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const subId = document.getElementById("extendSubId")?.value;
      const durationValue = parseInt(document.getElementById("extendDurationValue")?.value || "30", 10);
      const durationUnit = document.getElementById("extendDurationUnit")?.value || "days";
      const notes = document.getElementById("extendSubNotes")?.value?.trim();
      if (!subId) return;

      const submitBtn = document.getElementById("adminExtendSubSubmitBtn");
      if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Extending...'; }

      try {
        const res = await fetch(`/api/admin/subscriptions/${subId}/extend`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            duration_value: durationValue,
            duration_unit: durationUnit,
            notes
          })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          if (adminExtendSubModal) adminExtendSubModal.style.display = "none";
          document.body.style.overflow = "";
          loadAdminSubscriptions();
          loadAdminMetrics();
        } else {
          if (adminExtendSubAlert) {
            adminExtendSubAlert.className = "auth-alert error";
            adminExtendSubAlert.textContent = data.message || "Failed to extend subscription.";
            adminExtendSubAlert.style.display = "block";
          }
        }
      } catch (_) {
        if (adminExtendSubAlert) {
          adminExtendSubAlert.className = "auth-alert error";
          adminExtendSubAlert.textContent = "Network error extending subscription.";
          adminExtendSubAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<span class="auth-btn-text">Apply Extension</span> <i class="fas fa-calendar-plus auth-btn-icon"></i>'; }
      }
    });
  }

  // Load and Render Public Homepage Dynamic Plans Catalog
  async function loadPublicHomepagePlans() {
    const container = document.getElementById("publicHomepagePlansGrid");
    if (!container) return;

    try {
      const res = await fetch("/api/subscriptions/plans");
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        container.innerHTML = `<div class="plans-loading-placeholder text-danger">Unable to load public plans.</div>`;
        return;
      }

      const plans = data.plans || [];
      if (plans.length === 0) {
        container.innerHTML = `<div class="plans-loading-placeholder text-muted">No public plans currently offered. Please check back soon.</div>`;
        return;
      }

      const activeSub = currentUserSubscription;
      const isSubActive = activeSub && activeSub.status === "active";
      const isSubPending = activeSub && activeSub.status === "pending";

      let html = "";
      for (const p of plans) {
        const isFeatured = p.plan_code === "SCOUT-PRO" || p.id === "SCOUT-PRO";
        const isCurrentPlan = isSubActive && (activeSub.plan_id === p.id || activeSub.plan_code === p.plan_code);
        const isPendingPlan = isSubPending && (activeSub.plan_id === p.id || activeSub.plan_code === p.plan_code);

        const priceDisplay = p.price === 0 ? "Free" : `$${p.price.toFixed(2)}`;
        const durationDisplay = `/ ${p.duration_value} ${p.duration_unit || 'days'}`;

        const f = p.features || {};
        const canMonitor = f.can_live_monitoring !== false;
        const canPort = f.can_port_scan !== false;
        const canNd = f.can_network_discovery === true;

        let btnHtml = "";
        if (!currentUser) {
          btnHtml = `<button type="button" class="btn-public-plan-cta" data-public-plan-action="auth"><i class="fas fa-arrow-right"></i> Get Started with ${escapeHtml(p.name)}</button>`;
        } else if (currentUser.role === "Admin") {
          btnHtml = `<button type="button" class="btn-public-plan-cta current" disabled><i class="fas fa-shield-halved"></i> Root Administrator</button>`;
        } else if (isCurrentPlan) {
          btnHtml = `<button type="button" class="btn-public-plan-cta current" disabled><i class="fas fa-circle-check"></i> Current Active Plan</button>`;
        } else if (isPendingPlan) {
          btnHtml = `<button type="button" class="btn-public-plan-cta pending" disabled><i class="fas fa-clock"></i> Activation Pending</button>`;
        } else {
          btnHtml = `<button type="button" class="btn-public-plan-cta" data-public-plan-id="${p.id}"><i class="fas fa-bolt"></i> Select ${escapeHtml(p.name)}</button>`;
        }

        html += `
          <div class="public-plan-card ${isFeatured ? 'featured' : ''}">
            ${isFeatured ? '<span class="public-plan-featured-badge"><i class="fas fa-star"></i> Recommended Tier</span>' : ''}
            <div>
              <div class="public-plan-header">
                <div class="public-plan-code">${escapeHtml(p.plan_code || 'SCOUT')}</div>
                <h3 class="public-plan-name">${escapeHtml(p.name)}</h3>
                <p class="public-plan-desc">${escapeHtml(p.description || 'Full enterprise threat intelligence and detection capabilities.')}</p>
              </div>
              <div class="public-plan-pricing-box">
                <span class="public-plan-price">${priceDisplay}</span>
                <span class="public-plan-term">${durationDisplay}</span>
              </div>
              <ul class="public-plan-features-list">
                <li class="public-plan-feature-item ${canMonitor ? 'enabled' : 'disabled'}">
                  <i class="fas ${canMonitor ? 'fa-check' : 'fa-xmark'}"></i>
                  <span>Real-Time Traffic Telemetry & 15-Class Hostile ML Inference</span>
                </li>
                <li class="public-plan-feature-item ${canPort ? 'enabled' : 'disabled'}">
                  <i class="fas ${canPort ? 'fa-check' : 'fa-xmark'}"></i>
                  <span>Active Port Security Scanning & Vulnerability Enumeration</span>
                </li>
                <li class="public-plan-feature-item ${canNd ? 'enabled' : 'disabled'}">
                  <i class="fas ${canNd ? 'fa-check' : 'fa-xmark'}"></i>
                  <span>Autonomous Subnet Host & Asset Discovery</span>
                </li>
              </ul>
            </div>
            <div>
              ${btnHtml}
            </div>
          </div>
        `;
      }

      container.innerHTML = html;

      container.querySelectorAll("[data-public-plan-action='auth']").forEach(btn => {
        btn.addEventListener("click", () => {
          openAuthModal("register", "Create your SCOUT account to access security telemetry and activate plans.");
        });
      });

      container.querySelectorAll("[data-public-plan-id]").forEach(btn => {
        btn.addEventListener("click", () => {
          const pid = btn.getAttribute("data-public-plan-id");
          if (pid) requestSubscription(pid, btn);
        });
      });
    } catch (_) {
      container.innerHTML = `<div class="plans-loading-placeholder text-danger">Network error connecting to plan catalog.</div>`;
    }
  }

  // Refresh Buttons
  const refreshRequestsBtn = document.getElementById("refreshRequestsBtn");
  if (refreshRequestsBtn) refreshRequestsBtn.addEventListener("click", () => {
    loadAdminRequests();
    loadAdminMetrics();
  });

  const refreshSubsBtn = document.getElementById("refreshSubsBtn");
  if (refreshSubsBtn) refreshSubsBtn.addEventListener("click", () => {
    loadAdminSubscriptions();
    loadAdminMetrics();
  });

  const refreshUsersBtn = document.getElementById("refreshUsersBtn");
  if (refreshUsersBtn) refreshUsersBtn.addEventListener("click", () => {
    loadAdminUsers();
    loadAdminMetrics();
  });

  const adminSubSearchInput = document.getElementById("adminSubSearchInput");
  if (adminSubSearchInput) {
    let debounceTimer;
    adminSubSearchInput.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(loadAdminSubscriptions, 300);
    });
  }

  const adminUserSearchInput = document.getElementById("adminUserSearchInput");
  if (adminUserSearchInput) {
    let debounceTimer;
    adminUserSearchInput.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(loadAdminUsers, 300);
    });
  }

  const adminUserRoleFilter = document.getElementById("adminUserRoleFilter");
  if (adminUserRoleFilter) adminUserRoleFilter.addEventListener("change", loadAdminUsers);

  const adminUserStatusFilter = document.getElementById("adminUserStatusFilter");
  if (adminUserStatusFilter) adminUserStatusFilter.addEventListener("change", loadAdminUsers);

  const adminUserSubStatusFilter = document.getElementById("adminUserSubStatusFilter");
  if (adminUserSubStatusFilter) adminUserSubStatusFilter.addEventListener("change", loadAdminUsers);

  // Load Subscription Security Audit Logs with Real Data & Event Action Badges
  async function loadAdminAuditLogs() {
    const tbody = document.getElementById("adminAuditTbody");
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4"><i class="fas fa-circle-notch fa-spin"></i> Loading audit logs...</td></tr>`;

    try {
      const res = await fetch("/api/admin/audit-logs", { credentials: "same-origin" });
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger"><i class="fas fa-triangle-exclamation"></i> ${escapeHtml(data.message || "Failed to load audit logs.")}</td></tr>`;
        return;
      }

      const logs = data.audit_logs || [];
      if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted"><i class="fas fa-circle-check"></i> No administrative audit events recorded yet.</td></tr>`;
        return;
      }

      let rowsHtml = "";
      for (const log of logs) {
        const timeStr = log.timestamp ? formatUtcDate(log.timestamp) : "—";
        const action = (log.action || "UNKNOWN").toUpperCase();

        let badgeClass = "badge-muted";
        let actionIcon = "fa-circle-dot";
        if (action === "APPROVED" || action === "ACTIVATED") {
          badgeClass = "badge-green";
          actionIcon = "fa-circle-check";
        } else if (action === "CREATED" || action === "REQUESTED") {
          badgeClass = "badge-cyan";
          actionIcon = "fa-plus";
        } else if (action === "REJECTED" || action === "CANCELLED" || action === "CANCELED" || action === "SUSPENDED") {
          badgeClass = "badge-coral";
          actionIcon = "fa-ban";
        } else if (action === "EXTENDED" || action === "RENEWED") {
          badgeClass = "badge-blue";
          actionIcon = "fa-rotate";
        } else if (action === "DATES_ADJUSTED" || action === "UPDATED") {
          badgeClass = "badge-amber";
          actionIcon = "fa-pen-to-square";
        }

        const actionBadge = `<span class="sub-badge ${badgeClass}" style="display:inline-flex; align-items:center; gap:5px;"><i class="fas ${actionIcon}"></i> ${escapeHtml(action)}</span>`;

        const subjectUser = log.subject_user || (log.subscription_id ? `Sub #${log.subscription_id}` : "—");
        const subjectEmail = log.subject_email || "";
        const subjectHtml = `
          <div class="audit-subject-wrap">
            <span class="audit-subject-name font-medium">${escapeHtml(subjectUser)}</span>
            ${subjectEmail ? `<br><small class="audit-subject-email text-muted">${escapeHtml(subjectEmail)}</small>` : ""}
          </div>
        `;

        const planName = log.plan_name || (log.subscription_id ? `Sub #${log.subscription_id}` : "—");
        const actorHtml = log.actor_id 
          ? `<span class="badge-actor" style="display:inline-flex; align-items:center; gap:5px; font-size:0.75rem; padding:2px 8px; border-radius:4px; background:rgba(59,130,246,0.15); color:#60A5FA; border:1px solid rgba(59,130,246,0.3);"><i class="fas fa-user-shield"></i> Admin #${escapeHtml(String(log.actor_id))}</span>`
          : `<span class="text-muted"><i class="fas fa-robot"></i> System</span>`;

        const detailsText = log.details || "—";

        rowsHtml += `
          <tr>
            <td style="white-space:nowrap; font-family:var(--font-mono, monospace); font-size:0.8rem; color:var(--text-muted);"><i class="fas fa-clock"></i> ${escapeHtml(timeStr)}</td>
            <td>${actionBadge}</td>
            <td>${subjectHtml}</td>
            <td><span class="font-medium">${escapeHtml(planName)}</span></td>
            <td>${actorHtml}</td>
            <td style="max-width:320px; font-size:0.84rem; word-break:break-word;">${escapeHtml(detailsText)}</td>
          </tr>
        `;
      }
      tbody.innerHTML = rowsHtml;
    } catch (err) {
      console.error("Error loading admin audit logs:", err);
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger"><i class="fas fa-triangle-exclamation"></i> Network error fetching audit logs.</td></tr>`;
    }
  }

  const refreshAuditBtn = document.getElementById("refreshAuditBtn");
  if (refreshAuditBtn) refreshAuditBtn.addEventListener("click", () => {
    loadAdminAuditLogs();
    loadAdminMetrics();
  });

  // Admin Metric Cards Interactive Navigation with Pre-Applied Filters
  const metricCardBindings = [
    {
      id: "adminMetricTotalUsersCard",
      action: () => {
        activateAdminTab("users", true);
        if (adminUserStatusFilter) {
          adminUserStatusFilter.value = "";
          loadAdminUsers();
        }
      }
    },
    {
      id: "adminMetricActiveUsersCard",
      action: () => {
        activateAdminTab("users", true);
        if (adminUserStatusFilter) {
          adminUserStatusFilter.value = "active";
          loadAdminUsers();
        }
      }
    },
    {
      id: "adminMetricInactiveUsersCard",
      action: () => {
        activateAdminTab("users", true);
        if (adminUserStatusFilter) {
          adminUserStatusFilter.value = "disabled";
          loadAdminUsers();
        }
      }
    },
    {
      id: "adminMetricTotalSubscribersCard",
      action: () => {
        activateAdminTab("subscriptions", true);
        if (adminSubStatusFilter) {
          adminSubStatusFilter.value = "all";
          loadAdminSubscriptions();
        }
      }
    },
    {
      id: "adminMetricActiveSubsCard",
      action: () => {
        activateAdminTab("subscriptions", true);
        if (adminSubStatusFilter) {
          adminSubStatusFilter.value = "active";
          loadAdminSubscriptions();
        }
      }
    },
    {
      id: "adminPendingCard",
      action: () => {
        activateAdminTab("requests", true);
      }
    },
    {
      id: "adminMetricExpiredSubsCard",
      action: () => {
        activateAdminTab("subscriptions", true);
        if (adminSubStatusFilter) {
          adminSubStatusFilter.value = "expired";
          loadAdminSubscriptions();
        }
      }
    },
    {
      id: "adminMetricCanceledSubsCard",
      action: () => {
        activateAdminTab("subscriptions", true);
        if (adminSubStatusFilter) {
          adminSubStatusFilter.value = "canceled";
          loadAdminSubscriptions();
        }
      }
    },
    {
      id: "adminMetricPlansCard",
      action: () => {
        activateAdminTab("plans", true);
      }
    },
    {
      id: "adminMetricInactivePlansCard",
      action: () => {
        activateAdminTab("plans", true);
      }
    }
  ];

  metricCardBindings.forEach(binding => {
    const cardEl = document.getElementById(binding.id);
    if (cardEl) {
      cardEl.addEventListener("click", binding.action);
      cardEl.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          binding.action();
        }
      });
    }
  });

  const adminSubStatusFilter = document.getElementById("adminSubStatusFilter");
  if (adminSubStatusFilter) adminSubStatusFilter.addEventListener("change", loadAdminSubscriptions);

  // Admin Profile Update Form Handler
  const adminProfileForm = document.getElementById("adminProfileForm");
  const adminProfileAlert = document.getElementById("adminProfileAlert");
  if (adminProfileForm) {
    adminProfileForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fullName = document.getElementById("adminProfileFullNameInput")?.value?.trim();
      const email = document.getElementById("adminProfileEmailInput")?.value?.trim();
      const submitBtn = document.getElementById("adminProfileSubmitBtn");

      if (!email) {
        if (adminProfileAlert) {
          adminProfileAlert.className = "auth-alert error";
          adminProfileAlert.textContent = "Email address cannot be empty.";
          adminProfileAlert.style.display = "block";
        }
        return;
      }

      if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Saving...'; }

      try {
        const res = await fetch("/api/auth/profile", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ full_name: fullName, email: email })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          if (adminProfileAlert) {
            adminProfileAlert.className = "auth-alert success";
            adminProfileAlert.textContent = "Profile updated successfully.";
            adminProfileAlert.style.display = "block";
          }
          loadAdminProfile();
        } else {
          if (adminProfileAlert) {
            adminProfileAlert.className = "auth-alert error";
            adminProfileAlert.textContent = data.message || "Failed to update profile.";
            adminProfileAlert.style.display = "block";
          }
        }
      } catch (_) {
        if (adminProfileAlert) {
          adminProfileAlert.className = "auth-alert error";
          adminProfileAlert.textContent = "Network error updating profile.";
          adminProfileAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<span class="auth-btn-text">Save Profile Changes</span> <i class="fas fa-floppy-disk auth-btn-icon"></i>';
        }
      }
    });
  }

  // Admin Password Change Form Handler
  const adminPasswordForm = document.getElementById("adminPasswordForm");
  const adminPasswordAlert = document.getElementById("adminPasswordAlert");
  if (adminPasswordForm) {
    adminPasswordForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const currPwd = document.getElementById("adminCurrentPasswordInput")?.value;
      const newPwd = document.getElementById("adminNewPasswordInput")?.value;
      const confPwd = document.getElementById("adminConfirmPasswordInput")?.value;
      const submitBtn = document.getElementById("adminPasswordSubmitBtn");

      if (!currPwd || !newPwd || !confPwd) {
        if (adminPasswordAlert) {
          adminPasswordAlert.className = "auth-alert error";
          adminPasswordAlert.textContent = "All password fields are required.";
          adminPasswordAlert.style.display = "block";
        }
        return;
      }
      if (newPwd !== confPwd) {
        if (adminPasswordAlert) {
          adminPasswordAlert.className = "auth-alert error";
          adminPasswordAlert.textContent = "New passwords do not match.";
          adminPasswordAlert.style.display = "block";
        }
        return;
      }

      if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Updating...'; }

      try {
        const res = await fetch("/api/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            current_password: currPwd,
            new_password: newPwd,
            confirm_new_password: confPwd
          })
        });
        const data = await res.json();
        if (res.ok && data.status === "success") {
          if (adminPasswordAlert) {
            adminPasswordAlert.className = "auth-alert success";
            adminPasswordAlert.textContent = "Password changed successfully! All previous sessions revoked.";
            adminPasswordAlert.style.display = "block";
          }
          adminPasswordForm.reset();
        } else {
          if (adminPasswordAlert) {
            adminPasswordAlert.className = "auth-alert error";
            adminPasswordAlert.textContent = data.message || "Failed to update password.";
            adminPasswordAlert.style.display = "block";
          }
        }
      } catch (_) {
        if (adminPasswordAlert) {
          adminPasswordAlert.className = "auth-alert error";
          adminPasswordAlert.textContent = "Network error updating password.";
          adminPasswordAlert.style.display = "block";
        }
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<span class="auth-btn-text">Update Password</span> <i class="fas fa-lock auth-btn-icon"></i>';
        }
      }
    });
  }

  const refreshProfileBtn = document.getElementById("refreshProfileBtn");
  if (refreshProfileBtn) refreshProfileBtn.addEventListener("click", loadAdminProfile);

  const adminPanelLogoutBtn = document.getElementById("adminPanelLogoutBtn");
  if (adminPanelLogoutBtn) {
    adminPanelLogoutBtn.addEventListener("click", (e) => {
      e.preventDefault();
      performLogout();
    });
  }

  // Initialize Hero Visual Enhancements & Background Videos
  initCyberBackgroundCanvas();
  initHeroStatsAnimation();
  initThreatIntelVideo();
  initDefensiveVideo();

  // Initialize Port Scanner UI
  PortScannerUI.init();

  // Check auth session before initial view switch
  checkAuthSession().finally(() => {
    const initialView = getQueryView();
    const urlParams = new URLSearchParams(window.location.search);
    const isExplicitPublic = urlParams.get("public") === "1" || urlParams.get("view") === "home" || urlParams.get("view") === "landing";

    // If initialView is landing (or no view in URL) and user is authenticated and not requesting explicit public view:
    if ((initialView === "landing" || !urlParams.has("view")) && currentUser && !isExplicitPublic) {
      if (currentUser.role === "Admin") {
        switchView("admin", false);
      } else if (currentUserSubscription && currentUserSubscription.status === "active") {
        switchView("dashboard", false);
      } else {
        switchView("plans", false);
      }
    } else {
      switchView(initialView, false);
    }
  });

  // Lifecycle Decoupled: Navigating between sections or leaving the page does NOT
  // terminate backend packet capture. Capture continues until user explicitly clicks Stop.
});