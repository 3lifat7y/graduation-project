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
      checkAndAttachActiveSession();

      if (updateHistory) {
        history.pushState({ view: "monitoring" }, "", "?view=monitoring");
      }
    } else if (targetView === "port-scanner") {
      document.body.classList.add("dedicated-mode-port-scanner");
      document.body.classList.remove("dedicated-mode-monitoring", "home-view");

      if (dedicatedToolBar) dedicatedToolBar.style.display = "flex";
      if (dedicatedToolTitle) dedicatedToolTitle.textContent = "Port Scanning & Service Analysis";

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

      if (typeof PortScannerUI !== "undefined" && PortScannerUI.checkAndAttachActivePortScan) {
        PortScannerUI.checkAndAttachActivePortScan();
      }

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

  // Helper to auto-close (mobile) or auto-collapse (desktop) sidebar after navigation
  function autoCloseSidebarAfterNav() {
    if (window.innerWidth < 992) {
      closeMobileSidebar();
    } else {
      if (!document.body.classList.contains("sidebar-collapsed")) {
        document.body.classList.add("sidebar-collapsed");
        localStorage.setItem("nss_sidebar_collapsed", "true");
        if (navbarSidebarToggleBtn) {
          navbarSidebarToggleBtn.setAttribute("aria-expanded", "false");
        }
      }
    }
  }

  // Intercept Navigation Link Clicks in Sidebar
  sidebarNavItems.forEach(item => {
    item.addEventListener("click", (e) => {
      const navTarget = item.getAttribute("data-nav");
      const href = item.getAttribute("href") || "";

      if (navTarget === "monitoring") {
        e.preventDefault();
        switchView("monitoring");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "port-scanner") {
        e.preventDefault();
        switchView("port-scanner");
        autoCloseSidebarAfterNav();
      } else if (navTarget === "home") {
        if (document.body.classList.contains("dedicated-mode-monitoring") || document.body.classList.contains("dedicated-mode-port-scanner")) {
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

    function switchMode(mode) {
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

        // Render live interim results if any hosts found
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

      // Check URL parameters (e.g. from Network Discovery card Scan Ports link)
      try {
        const urlParams = new URLSearchParams(window.location.search);
        const targetParam = urlParams.get("target");
        if (targetParam) {
          switchMode("target_ip");
          if (targetInput) targetInput.value = targetParam;
          const scannerSec = document.getElementById("port-scanner") || document.getElementById("portScannerSection");
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
      stopScan,
      checkAndAttachActivePortScan,
      showPortDetailsModal,
      closePortDetailsModal
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

  // Lifecycle Decoupled: Navigating between sections or leaving the page does NOT
  // terminate backend packet capture. Capture continues until user explicitly clicks Stop.
});