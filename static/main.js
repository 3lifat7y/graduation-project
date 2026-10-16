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

  // Adapter & Service Badges
  const adapterChip = document.getElementById("adapterChip");
  const adapterName = document.getElementById("adapterName");
  const adapterIp = document.getElementById("adapterIp");
  const driverStatusBadge = document.getElementById("driverStatusBadge");
  const adapterIcon = document.getElementById("adapterIcon");
  const headerHealthDot = document.getElementById("headerHealthDot");
  const headerHealthLabel = document.getElementById("headerHealthLabel");

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
      labelText = "WinDivert: Ready";
      badgeClass = "driver-badge driver-ready";
      healthClass = "running";
      healthText = "WinDivert Ready";
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
  }

  async function loadAdapterInfo() {
    try {
      const res = await fetch(`${API_BASE_URL}/adapter-info`);
      if (!res.ok) throw new Error("Failed to query adapter info");
      const data = await res.json();

      if (data.status === "success" && data.adapter) {
        const ad = data.adapter;
        const drv = data.driver_status || {};
        const svc = data.service_state || drv.service_state || {};

        if (adapterName) adapterName.textContent = `${ad.name} (${ad.type})`;
        if (adapterIp) adapterIp.textContent = `IPv4: ${ad.primary_ip || "DHCP"}`;

        if (adapterIcon) {
          adapterIcon.className = (ad.type === "Ethernet") ? "fas fa-ethernet" : "fas fa-wifi";
        }

        updateServiceBadge(svc, drv);
      }
    } catch (err) {
      console.warn("Could not load adapter info:", err);
      if (adapterName) adapterName.textContent = "Network Adapter: Ready";
    }
  }

  async function syncServiceStatus() {
    if (isScanning) return;
    try {
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

  // Initial queries and heartbeat interval
  loadAdapterInfo();
  setInterval(syncServiceStatus, 5000);

  // ============================================================================
  // 4. Reactive UI State Machine (6 Clean Scan States)
  // ============================================================================
  function setUIState(state, payload = {}) {
    if (payload && (payload.service_state || payload.driver_status)) {
      updateServiceBadge(payload.service_state, payload.driver_status);
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
        if (resultChipState) resultChipState.textContent = "Starting Engine";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> <span class="btn-text">Starting...</span>';
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
        if (resultChipState) resultChipState.textContent = "Live Telemetry";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-wave-square fa-spin"></i> <span class="btn-text">Monitoring Live</span>';
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

        // Render Telemetry Flow Statistics
        if (telemetryGrid) {
          telemetryGrid.style.display = "grid";
          if (telemetryPkts) {
            const totalPkts = payload.packets_captured !== undefined ? payload.packets_captured : (payload.flow_summary?.packets_captured || 0);
            const winPkts = payload.window_packets !== undefined ? payload.window_packets : 0;
            telemetryPkts.textContent = winPkts > 0 ? `${totalPkts} (${winPkts}/win)` : `${totalPkts}`;
          }
          if (telemetryDuration) {
            const dur = payload.duration !== undefined ? payload.duration : (((payload.flow_summary?.flow_duration_us || 0) / 1000000));
            telemetryDuration.textContent = `${Number(dur).toFixed(1)} s`;
          }
          if (telemetryThroughput) {
            const kbps = payload.throughput_kbps !== undefined ? payload.throughput_kbps : (((payload.flow_summary?.flow_bytes_per_s || 0) / 1024));
            telemetryThroughput.textContent = `${Number(kbps).toFixed(1)} KB/s`;
          }
          if (telemetryProtocol) {
            telemetryProtocol.textContent = payload.protocol || "WinDivert";
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
        if (resultChipState) resultChipState.textContent = "Monitoring Stopped";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-play"></i> <span class="btn-text">Start Monitoring</span>';
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
        if (resultChipState) resultChipState.textContent = "Error";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-rotate-right"></i> <span class="btn-text">Start Monitoring</span>';
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
  async function startScan() {
    if (isScanning) return;

    activeScanId = null;
    console.log("[DDoS-Guard] Start Monitoring clicked. Initiating fresh continuous session...");

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
    if (telemetryProtocol) telemetryProtocol.textContent = "WinDivert";

    if (diagnosticAlert) diagnosticAlert.style.display = "none";

    setUIState("starting");
    scanStartTime = Date.now();

    try {
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ continuous: true, min_packets: 3 })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        console.error("[DDoS-Guard] /api/scan returned HTTP error:", res.status, errData);
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
      if (startData.status === "error" || startData.error_type === "SERVICE_START_FAILED" || startData.error_type === "SERVICE_NOT_INSTALLED") {
        console.error("[DDoS-Guard] Service error on startup:", startData);
        activeScanId = null;
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
  // 6. Threat Vectors Slider & Category Filtering
  // ============================================================================
  let visibleCards = [...allCards];
  let currentIndex = 0;

  function updateSliderCounter() {
    if (!sliderCurrentIndex || !sliderTotalCount) return;
    sliderTotalCount.textContent = visibleCards.length;
    sliderCurrentIndex.textContent = visibleCards.length > 0 ? (currentIndex + 1) : 0;
  }

  function scrollSliderToIndex(index) {
    if (!visibleCards.length || !slider) return;
    currentIndex = Math.max(0, Math.min(index, visibleCards.length - 1));
    const targetCard = visibleCards[currentIndex];
    if (targetCard) {
      targetCard.scrollIntoView({
        behavior: "smooth",
        block: "nearest",
        inline: "center"
      });
    }
    updateSliderCounter();
  }

  function filterCards(category) {
    visibleCards = [];
    allCards.forEach(card => {
      const cardCat = card.getAttribute("data-category");
      if (category === "all" || cardCat === category) {
        card.style.display = "flex";
        visibleCards.push(card);
      } else {
        card.style.display = "none";
      }
    });

    currentIndex = 0;
    updateSliderCounter();
    if (slider) slider.scrollTo({ left: 0, behavior: "smooth" });
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

  // Slider controls
  if (sliderNextBtn) {
    sliderNextBtn.addEventListener("click", () => {
      scrollSliderToIndex(currentIndex + 1);
    });
  }

  if (sliderPrevBtn) {
    sliderPrevBtn.addEventListener("click", () => {
      scrollSliderToIndex(currentIndex - 1);
    });
  }

  updateSliderCounter();

  // ============================================================================
  // 7. General Navigation & Interactive Features
  // ============================================================================
  // Mobile Hamburger Menu
  if (menuToggle && mainNav) {
    menuToggle.addEventListener("click", () => {
      const isOpen = mainNav.classList.toggle("mobile-open");
      menuToggle.setAttribute("aria-expanded", isOpen);
      menuToggle.innerHTML = isOpen ? '<i class="fas fa-times"></i>' : '<i class="fas fa-bars"></i>';
    });

    // Close menu when clicking navigation link
    mainNav.querySelectorAll("a").forEach(link => {
      link.addEventListener("click", () => {
        mainNav.classList.remove("mobile-open");
        menuToggle.setAttribute("aria-expanded", "false");
        menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
      });
    });
  }

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

  // Header Quick Check CTA
  if (headerQuickCheckBtn) {
    headerQuickCheckBtn.addEventListener("click", () => {
      const scanSection = document.getElementById("check-connection");
      if (scanSection) {
        scanSection.scrollIntoView({ behavior: "smooth" });
        if (checkBtn) checkBtn.focus();
      }
    });
  }

  // ScrollSpy for Active Navigation Links
  const navSections = document.querySelectorAll("section[id]");
  const navLinks = document.querySelectorAll(".main-nav .nav-link");

  function highlightNavOnScroll() {
    const scrollPos = window.scrollY + 120;
    navSections.forEach(section => {
      const top = section.offsetTop;
      const height = section.offsetHeight;
      const id = section.getAttribute("id");

      if (scrollPos >= top && scrollPos < top + height) {
        navLinks.forEach(link => {
          link.classList.remove("active");
          if (link.getAttribute("href") === `#${id}`) {
            link.classList.add("active");
          }
        });
      }
    });
  }

  window.addEventListener("scroll", highlightNavOnScroll, { passive: true });

  // ============================================================================
  // 8. Event Listeners for DDoS Live Scanning
  // ============================================================================
  if (checkBtn) {
    checkBtn.addEventListener("click", () => {
      startScan();
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener("click", () => {
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
    const stopBtn = document.getElementById("psStopBtn");
    const exportGroup = document.getElementById("psExportGroup");
    const exportJsonBtn = document.getElementById("psExportJsonBtn");
    const exportCsvBtn = document.getElementById("psExportCsvBtn");

    const stateBadge = document.getElementById("psStateBadge");
    const localIpBadge = document.getElementById("psLocalIpBadge");
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
          autoDetectedSubnet = data.suggested_subnet || "192.168.1.0/24";
          if (localIpBadge) {
            localIpBadge.innerHTML = `<i class="fas fa-circle-dot"></i> Local IP: ${data.local_ip || "127.0.0.1"}`;
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
        targetInput.value = autoDetectedSubnet || "192.168.1.0/24";
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
        showError("Target address is required.");
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
      if (stopBtn) stopBtn.style.display = "inline-flex";
      if (progressBox) progressBox.style.display = "block";
      if (progressBar) progressBar.style.width = "0%";
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

        if (kpiHosts) kpiHosts.textContent = data.active_hosts_count || 0;
        if (kpiScanned) kpiScanned.textContent = data.scanned_ports || 0;
        if (kpiOpen) kpiOpen.textContent = data.open_ports_count || 0;
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
          } else if (status === "stopped") {
            setBadge("stopped", "Stopped");
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
      if (stopBtn) stopBtn.style.display = "none";
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
      ports.forEach(p => {
        const stateClass = p.state === "open" ? "state-open" : (p.state === "filtered" ? "state-filtered" : "state-closed");
        const stateIcon = p.state === "open" ? "fa-circle-check" : (p.state === "filtered" ? "fa-circle-exclamation" : "fa-circle-xmark");
        const latencyText = p.latency_ms !== null ? `${p.latency_ms} ms` : "--";
        const bannerHtml = p.banner ? `<code class="ps-banner-code" title="${escapeHtml(p.banner)}">${escapeHtml(p.banner)}</code>` : '<span class="text-muted">--</span>';

        rows += `
          <tr>
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

      // Start / Stop
      if (startBtn) startBtn.addEventListener("click", startScan);
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
    }

    return {
      init,
      startScan,
      stopScan
    };
  })();

  // Initialize Port Scanner UI
  PortScannerUI.init();

  window.addEventListener("beforeunload", () => {
    if (isScanning) stopScan(true);
  });
});