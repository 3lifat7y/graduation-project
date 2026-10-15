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
        if (stateBadge) stateBadge.textContent = "Ready";
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Standby";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-search"></i> <span class="btn-text">Scan Network</span>';
        }
        if (stopBtn) stopBtn.style.display = "none";
        if (statusEl) {
          statusEl.textContent = payload.message || "System ready. Click 'Scan Network' to capture live traffic.";
          statusEl.style.color = "";
        }
        break;

      case "scanning":
        isScanning = true;
        if (stateBadge) stateBadge.textContent = "Scanning...";
        if (radarBox) radarBox.classList.add("active");
        if (resultChipState) resultChipState.textContent = "Sniffing Packets";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> <span class="btn-text">Sniffing Packets...</span>';
        }
        if (stopBtn) {
          stopBtn.style.display = "inline-flex";
          stopBtn.disabled = false;
        }

        if (statusEl) {
          statusEl.textContent = payload.message || "Capturing live packets across active network adapter...";
          statusEl.style.color = "";
        }
        if (diagnosticAlert) diagnosticAlert.style.display = "none";
        break;

      case "processing":
        if (stateBadge) stateBadge.textContent = "Processing Features";
        if (radarBox) radarBox.classList.add("active");
        if (resultChipState) resultChipState.textContent = "Evaluating 77 Features";

        if (checkBtn) {
          checkBtn.disabled = true;
          checkBtn.innerHTML = '<i class="fas fa-microchip fa-spin"></i> <span class="btn-text">Evaluating Model...</span>';
        }
        if (statusEl) {
          statusEl.textContent = payload.message || "Running 77-feature extraction through AI model...";
          statusEl.style.color = "";
        }
        break;

      case "prediction_available":
        isScanning = false;
        if (stateBadge) stateBadge.textContent = "Prediction Available";
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Scan Complete";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-rotate-right"></i> <span class="btn-text">Scan Again</span>';
        }
        if (stopBtn) stopBtn.style.display = "none";

        const isAttack = Boolean(payload.is_attack);
        const label = payload.label || (isAttack ? "DDoS Attack" : "Benign");
        const confNum = typeof payload.confidence === "number" ? payload.confidence : 0;
        const confStr = confNum > 0 ? `${confNum.toFixed(1)}%` : "--%";

        if (resultsConsole) {
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
        if (telemetryGrid && payload.flow_summary) {
          const fs = payload.flow_summary;
          telemetryGrid.style.display = "grid";

          if (telemetryPkts) {
            telemetryPkts.textContent = fs.packets_captured || payload.packets_captured || 0;
          }
          if (telemetryDuration) {
            const durMs = ((fs.flow_duration_us || 0) / 1000).toFixed(1);
            telemetryDuration.textContent = `${durMs} ms`;
          }
          if (telemetryThroughput) {
            const kbps = ((fs.flow_bytes_per_s || 0) / 1024).toFixed(1);
            telemetryThroughput.textContent = `${kbps} KB/s`;
          }
          if (telemetryProtocol) {
            const protoMap = { 6: "TCP (6)", 17: "UDP (17)", 1: "ICMP (1)" };
            telemetryProtocol.textContent = protoMap[fs.protocol] || `Proto ${fs.protocol || 6}`;
          }
        }
        break;

      case "insufficient_traffic":
        isScanning = false;
        if (stateBadge) stateBadge.textContent = "Insufficient Traffic";
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Notice";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-rotate-right"></i> <span class="btn-text">Retry Scan</span>';
        }
        if (stopBtn) stopBtn.style.display = "none";

        if (labelEl) {
          labelEl.textContent = "Quiet Network";
          labelEl.style.color = "var(--status-warning)";
        }
        if (rateEl) {
          rateEl.textContent = "Confidence: N/A";
          rateEl.style.color = "var(--text-muted)";
        }
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "Not enough packets intercepted during the capture window to form a valid flow.";
          statusEl.style.color = "var(--status-warning)";
        }

        if (telemetryGrid) telemetryGrid.style.display = "none";

        if (diagnosticAlert) {
          diagnosticAlert.style.display = "flex";
          if (diagnosticMsg) {
            diagnosticMsg.textContent = "The network adapter had minimal traffic during the scan. Generate traffic in your browser or run 'python send_traffic.py' and scan again.";
          }
        }
        break;

      case "uac_cancelled":
        isScanning = false;
        if (stateBadge) stateBadge.textContent = "Elevation Cancelled";
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Cancelled";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-search"></i> <span class="btn-text">Scan Network</span>';
        }
        if (stopBtn) stopBtn.style.display = "none";

        if (labelEl) {
          labelEl.textContent = "Elevation Cancelled";
          labelEl.style.color = "var(--status-warning)";
        }
        if (rateEl) rateEl.textContent = "Confidence: N/A";
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = "Administrator approval was cancelled. Click 'Scan Network' to approve the prompt or stream simulation packets.";
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
        if (stateBadge) stateBadge.textContent = "Scan Error";
        if (radarBox) radarBox.classList.remove("active");
        if (resultChipState) resultChipState.textContent = "Error";

        if (checkBtn) {
          checkBtn.disabled = false;
          checkBtn.innerHTML = '<i class="fas fa-rotate-right"></i> <span class="btn-text">Retry Scan</span>';
        }
        if (stopBtn) stopBtn.style.display = "none";

        if (labelEl) {
          labelEl.textContent = "Scan Error";
          labelEl.style.color = "var(--status-attack)";
        }
        if (rateEl) rateEl.textContent = "Confidence: N/A";
        if (confidenceBarFill) confidenceBarFill.style.width = "0%";

        if (statusEl) {
          statusEl.textContent = payload.message || "An error occurred during packet capture.";
          statusEl.style.color = "var(--status-attack)";
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
    console.log("[DDoS-Guard] Scan button clicked. Initiating fresh scan session...");

    // Reset previous outputs immediately
    if (resultsConsole) {
      resultsConsole.classList.remove("state-benign", "state-attack");
    }
    if (resultIcon) {
      resultIcon.className = "fas fa-satellite-dish result-icon fa-spin";
      resultIcon.style.color = "var(--accent-cyan)";
    }
    if (labelEl) {
      labelEl.textContent = "Sniffing Live Packets...";
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

    setUIState("scanning");
    scanStartTime = Date.now();

    try {
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ duration: 3.0, min_packets: 3 })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        console.error("[DDoS-Guard] /api/scan returned HTTP error:", res.status, errData);
        setUIState("error", errData);
        return;
      }

      const startData = await res.json().catch(() => ({}));
      activeScanId = startData.scan_id || null;
      console.log("[DDoS-Guard] Scan session registered:", activeScanId, startData);

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

      // Begin polling status every 300ms
      if (scanPollInterval) clearInterval(scanPollInterval);
      scanPollInterval = setInterval(pollScanStatus, 300);

      // Watchdog timeout (15 seconds)
      if (scanTimeoutTimer) clearTimeout(scanTimeoutTimer);
      scanTimeoutTimer = setTimeout(() => {
        if (isScanning) {
          stopScan(true);
          setUIState("error", { message: "Scan request timed out without receiving packets from kernel engine." });
        }
      }, 15000);

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
      if (status === "scanning") {
        const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
        const pkts = data.packets_captured !== undefined ? data.packets_captured : 0;
        const iface = data.interface?.name || "active adapter";
        if (statusEl) {
          statusEl.textContent = `Sniffing live packets on [${iface}] — ${pkts} pkts captured (${elapsed}s)...`;
        }
        if (telemetryPkts) {
          telemetryPkts.textContent = pkts;
        }
        if (telemetryDuration) {
          telemetryDuration.textContent = `${elapsed} s`;
        }
      } else if (status === "processing") {
        setUIState("processing", data);
      } else if (status === "prediction_available") {
        clearInterval(scanPollInterval);
        clearTimeout(scanTimeoutTimer);
        console.log(`[DDoS-Guard] Scan completed: ${data.label} (Confidence: ${data.confidence}%, Packets: ${data.packets_captured})`);
        setUIState("prediction_available", data);
      } else if (status === "insufficient_traffic") {
        clearInterval(scanPollInterval);
        clearTimeout(scanTimeoutTimer);
        console.warn("[DDoS-Guard] Scan completed: Insufficient traffic intercepted.");
        setUIState("insufficient_traffic", data);
      } else if (status === "error") {
        clearInterval(scanPollInterval);
        clearTimeout(scanTimeoutTimer);
        console.error("[DDoS-Guard] Scan failed with error:", data.error || data.message);
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

    try {
      await fetch(`${API_BASE_URL}/scan-stop`, { method: "POST" });
    } catch (err) {
      // Ignore stop network errors
    }

    if (!silent) {
      setUIState("ready", { message: "Scan cancelled by user." });
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
  // 8. Event Listeners for Scanning
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

  window.addEventListener("beforeunload", () => {
    if (isScanning) stopScan(true);
  });
});