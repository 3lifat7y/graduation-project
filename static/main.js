const cards = Array.from(document.querySelectorAll(".card"));
const container = document.querySelector(".card-container");
const nextBtn = document.querySelector(".next");
const prevBtn = document.querySelector(".prev");

let current = 0;
let cardWidth = 0;
let autoSlideInterval = null;
let isInteracting = false;

function recalcCardWidth() {
  if (!cards.length) return;
  const rect = cards[0].getBoundingClientRect();
  const style = getComputedStyle(cards[0]);
  const margin = parseFloat(style.marginLeft) + parseFloat(style.marginRight);
  cardWidth = rect.width + margin;
}

function showCard(index) {
  current = ((index % cards.length) + cards.length) % cards.length;
  container.style.transform = `translateX(-${current * cardWidth}px)`;
}

function startAutoSlide() {
  if (autoSlideInterval) return;
  autoSlideInterval = setInterval(() => {
    if (!isInteracting) showCard(current + 1);
  }, 3000);
}

function stopAutoSlide() {
  if (autoSlideInterval) {
    clearInterval(autoSlideInterval);
    autoSlideInterval = null;
  }
}

if (nextBtn) {
  nextBtn.addEventListener("click", () => {
    isInteracting = true;
    stopAutoSlide();
    showCard(current + 1);
    setTimeout(() => {
      isInteracting = false;
      startAutoSlide();
    }, 1000);
  });
}

if (prevBtn) {
  prevBtn.addEventListener("click", () => {
    isInteracting = true;
    stopAutoSlide();
    showCard(current - 1);
    setTimeout(() => {
      isInteracting = false;
      startAutoSlide();
    }, 1000);
  });
}

window.addEventListener("resize", () => {
  recalcCardWidth();
  showCard(current);
});

window.addEventListener("load", () => {
  recalcCardWidth();
  showCard(current);
  startAutoSlide();
});

let touchStartX = 0;
container?.addEventListener("touchstart", (e) => {
  touchStartX = e.touches[0].clientX;
  stopAutoSlide();
});
container?.addEventListener("touchend", (e) => {
  const diff = touchStartX - e.changedTouches[0].clientX;
  if (Math.abs(diff) > 50) showCard(current + (diff > 0 ? 1 : -1));
  startAutoSlide();
});

const API_BASE_URL = "/api"; 
let scanPollInterval = null;
let scanTimeoutTimer = null;
let isScanning = false;
let scanStartTime = 0;

// DOM Element References
const checkBtn = document.getElementById("checkBtn");
const stopBtn = document.getElementById("stopBtn");
const stateBadge = document.getElementById("stateBadge");
const statusEl = document.getElementById("connectionStatus");
const rateEl = document.getElementById("connectionRate");
const labelEl = document.getElementById("connectionStatusText");
const resultIcon = document.getElementById("resultIcon");

const telemetryGrid = document.getElementById("telemetryGrid");
const telemetryPkts = document.getElementById("telemetryPkts");
const telemetryDuration = document.getElementById("telemetryDuration");
const telemetryThroughput = document.getElementById("telemetryThroughput");
const telemetryProtocol = document.getElementById("telemetryProtocol");

const diagnosticAlert = document.getElementById("diagnosticAlert");
const diagnosticMsg = document.getElementById("diagnosticMsg");

const adapterChip = document.getElementById("adapterChip");
const adapterName = document.getElementById("adapterName");
const adapterIp = document.getElementById("adapterIp");
const driverStatusBadge = document.getElementById("driverStatusBadge");
const adapterIcon = document.getElementById("adapterIcon");


// ==============================================================================
// 1. Adapter Discovery & Initialization
// ==============================================================================
async function loadAdapterInfo() {
  try {
    const res = await fetch(`${API_BASE_URL}/adapter-info`);
    if (!res.ok) throw new Error("Failed to query adapter info");
    const data = await res.json();
    
    if (data.status === "success" && data.adapter) {
      const ad = data.adapter;
      const drv = data.driver_status || {};

      if (adapterName) adapterName.textContent = `${ad.name} (${ad.type})`;
      if (adapterIp) adapterIp.textContent = `IP: ${ad.primary_ip || "DHCP"}`;
      
      if (adapterIcon) {
        adapterIcon.className = (ad.type === "Ethernet") ? "fas fa-ethernet" : "fas fa-wifi";
      }

      if (driverStatusBadge) {
        if (drv.can_capture_live) {
          driverStatusBadge.textContent = "WinDivert: Ready";
          driverStatusBadge.className = "driver-badge driver-ready";
        } else {
          driverStatusBadge.textContent = "WinDivert (Admin needed)";
          driverStatusBadge.className = "driver-badge";
        }
      }
    }
  } catch (err) {
    console.warn("Could not load adapter info:", err);
    if (adapterName) adapterName.textContent = "Network Adapter: Ready";
  }
}

window.addEventListener("DOMContentLoaded", loadAdapterInfo);


// ==============================================================================
// 2. Scan State Management (6 States)
// ==============================================================================
function setUIState(state, payload = {}) {
  if (!stateBadge) return;

  // Reset badge class
  stateBadge.className = `status-indicator-badge state-${state}`;

  switch (state) {
    case "ready":
      isScanning = false;
      stateBadge.textContent = "Ready";
      checkBtn.disabled = false;
      checkBtn.innerHTML = '<i class="fas fa-search"></i> Scan Network';
      stopBtn.style.display = "none";
      if (statusEl) statusEl.textContent = payload.message || "System ready. Click 'Scan Network' to capture live traffic.";
      break;

    case "scanning":
      isScanning = true;
      stateBadge.textContent = "Scanning...";
      checkBtn.disabled = true;
      checkBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sniffing Packets...';
      stopBtn.style.display = "inline-flex";
      if (statusEl) statusEl.textContent = payload.message || "Capturing live packets across active network adapter...";
      if (diagnosticAlert) diagnosticAlert.style.display = "none";
      break;

    case "processing":
      stateBadge.textContent = "Processing Features";
      checkBtn.disabled = true;
      checkBtn.innerHTML = '<i class="fas fa-cogs fa-spin"></i> Analyzing...';
      if (statusEl) statusEl.textContent = payload.message || "Running 77-feature extraction through AI model...";
      break;

    case "prediction_available":
      isScanning = false;
      stateBadge.textContent = "Prediction Available";
      checkBtn.disabled = false;
      checkBtn.innerHTML = '<i class="fas fa-search"></i> Scan Again';
      stopBtn.style.display = "none";

      const isAttack = payload.is_attack;
      const label = payload.label || "Benign";
      const conf = payload.confidence ? `${payload.confidence.toFixed(1)}%` : "--%";

      if (labelEl) {
        labelEl.textContent = label;
        labelEl.style.color = isAttack ? "#dc3545" : "#28a745";
      }
      if (rateEl) {
        rateEl.textContent = `Confidence: ${conf}`;
        rateEl.style.color = isAttack ? "#dc3545" : "#28a745";
      }
      if (statusEl) {
        statusEl.textContent = isAttack ? "⚠️ Alert: DDoS Attack Traffic Detected!" : "✅ Traffic Status: Normal / Benign Flow";
        statusEl.style.color = isAttack ? "#dc3545" : "#28a745";
      }

      if (resultIcon) {
        resultIcon.className = isAttack ? "fas fa-shield-virus result-icon" : "fas fa-shield-alt result-icon";
        resultIcon.style.color = isAttack ? "#dc3545" : "#28a745";
      }

      // Display flow telemetry grid
      if (telemetryGrid && payload.flow_summary) {
        const fs = payload.flow_summary;
        telemetryGrid.style.display = "grid";
        if (telemetryPkts) telemetryPkts.textContent = fs.packets_captured || payload.packets_captured || 0;
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

      if (isAttack) {
        document.body.style.backgroundColor = "#ff002222";
        setTimeout(() => (document.body.style.backgroundColor = ""), 600);
      }
      break;

    case "insufficient_traffic":
      isScanning = false;
      stateBadge.textContent = "Insufficient Traffic";
      checkBtn.disabled = false;
      checkBtn.innerHTML = '<i class="fas fa-search"></i> Retry Scan';
      stopBtn.style.display = "none";

      if (labelEl) {
        labelEl.textContent = "Quiet Network";
        labelEl.style.color = "#ff9800";
      }
      if (rateEl) rateEl.textContent = "Confidence: N/A";
      if (statusEl) {
        statusEl.textContent = payload.message || "Not enough packets intercepted during the capture window to form a valid flow.";
        statusEl.style.color = "#ff9800";
      }
      if (telemetryGrid) telemetryGrid.style.display = "none";
      if (diagnosticAlert) {
        diagnosticAlert.style.display = "flex";
        if (diagnosticMsg) {
          diagnosticMsg.textContent = "Notice: The network adapter had minimal traffic during the scan. Generate traffic in your browser or run 'python send_traffic.py' and scan again.";
        }
      }
      break;

    case "error":
      isScanning = false;
      stateBadge.textContent = "Scan Error";
      checkBtn.disabled = false;
      checkBtn.innerHTML = '<i class="fas fa-search"></i> Retry Scan';
      stopBtn.style.display = "none";

      if (labelEl) {
        labelEl.textContent = "Error";
        labelEl.style.color = "#dc3545";
      }
      if (statusEl) {
        statusEl.textContent = payload.message || "An error occurred during packet capture.";
        statusEl.style.color = "#dc3545";
      }
      if (diagnosticAlert) {
        diagnosticAlert.style.display = "flex";
        if (diagnosticMsg) {
          diagnosticMsg.textContent = payload.error || payload.message || "Driver or permissions error. Run terminal as Administrator for WinDivert.";
        }
      }
      break;
  }
}


// ==============================================================================
// 3. Scan Execution & Polling Lifecycle
// ==============================================================================
async function startScan() {
  if (isScanning) return;

  // Clear previous outputs
  if (labelEl) labelEl.textContent = "Scanning...";
  if (rateEl) rateEl.textContent = "Confidence: --%";
  if (telemetryGrid) telemetryGrid.style.display = "none";
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
      setUIState("error", errData);
      return;
    }

    // Begin active status polling
    if (scanPollInterval) clearInterval(scanPollInterval);
    scanPollInterval = setInterval(pollScanStatus, 400);

    // Timeout watchdog (12 seconds)
    if (scanTimeoutTimer) clearTimeout(scanTimeoutTimer);
    scanTimeoutTimer = setTimeout(() => {
      if (isScanning) {
        stopScan(true);
        setUIState("error", { message: "Scan request timed out without receiving packets." });
      }
    }, 12000);

  } catch (err) {
    setUIState("error", { message: `Cannot connect to API server: ${err.message}. Make sure 'python api.py' is running.` });
  }
}

async function pollScanStatus() {
  try {
    const res = await fetch(`${API_BASE_URL}/scan-status`);
    if (!res.ok) return;
    const data = await res.json();

    const status = data.status;
    if (status === "scanning") {
      const elapsed = ((Date.now() - scanStartTime) / 1000).toFixed(1);
      if (statusEl) statusEl.textContent = `Sniffing live packets on ${data.interface?.name || "adapter"} (${elapsed}s elapsed)...`;
    } else if (status === "processing") {
      setUIState("processing", data);
    } else if (status === "prediction_available") {
      clearInterval(scanPollInterval);
      clearTimeout(scanTimeoutTimer);
      setUIState("prediction_available", data);
    } else if (status === "insufficient_traffic") {
      clearInterval(scanPollInterval);
      clearTimeout(scanTimeoutTimer);
      setUIState("insufficient_traffic", data);
    } else if (status === "error") {
      clearInterval(scanPollInterval);
      clearTimeout(scanTimeoutTimer);
      setUIState("error", data);
    }
  } catch (err) {
    console.warn("Polling error:", err);
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

  try {
    await fetch(`${API_BASE_URL}/scan-stop`, { method: "POST" });
  } catch (err) {
    // Ignore network errors on stop
  }

  if (!silent) {
    setUIState("ready", { message: "Scan cancelled by user." });
  }
}

// Event Listeners
checkBtn?.addEventListener("click", () => {
  startScan();
});

stopBtn?.addEventListener("click", () => {
  stopScan();
});

window.addEventListener("beforeunload", () => {
  if (isScanning) stopScan(true);
});