/**
 * SCOUT System Architecture Interactive Mind Map Controller
 * Curved SVG connector topology, pan & zoom engine, verified metadata inspector
 */

(function () {
  "use strict";

  const MINDMAP_DATA = {
    "branch-core": {
      badge: "Engine Core · Unified Platform",
      title: "SCOUT Core Architecture",
      desc: "Autonomous cyber operations platform uniting passive traffic telemetry, 77-feature extraction, multi-class ML inference, subnet reconnaissance, and active port auditing into a unified defensive engine.",
      meta: [
        { label: "Engine", val: "SCOUT v2.5" },
        { label: "Architecture", val: "Client-Server / SCM Service" },
        { label: "Core Model", val: "XGBoost Champion" },
        { label: "Target OS", val: "Windows 10/11 x64" }
      ],
      action: { text: "Explore Architecture", url: "#overview" }
    },
    "branch-monitoring": {
      badge: "Branch: Live Monitoring",
      title: "Live Traffic Telemetry",
      desc: "Continuous packet sniffer and bidirectional flow analyzer executing non-intrusive network telemetry with real-time ML classification.",
      meta: [
        { label: "Sniffer", val: "Npcap / Scapy NDIS 6" },
        { label: "Pipeline", val: "77 Statistical Features" },
        { label: "Latency", val: "< 10ms per Flow" },
        { label: "Service", val: "DDoSGuardSnifferService" }
      ],
      action: { text: "Launch Live Monitoring", url: "/?view=monitoring" }
    },
    "packet-capture": {
      badge: "Telemetry Engine",
      title: "Passive Packet Sniffing",
      desc: "Low-overhead packet capture capturing raw ethernet and IP frames on physical adapters with BPF filtering 'not (tcp port 5000 or tcp port 50505)'.",
      meta: [
        { label: "Driver", val: "Npcap OEM / WinPcap" },
        { label: "Filter", val: "BPF Filter Optimized" },
        { label: "Elevation", val: "Scoped UAC Execution" }
      ],
      action: { text: "Configure Monitoring", url: "/?view=monitoring" }
    },
    "feature-extraction": {
      badge: "Flow Engineering",
      title: "77 Bidirectional Features",
      desc: "Stateful flow aggregator computing forward and backward packet lengths, inter-arrival times (IAT), flow duration, flag distributions, and window sizes matching CIC-IDS2017 schema.",
      meta: [
        { label: "Dimensions", val: "77 Float64 Features" },
        { label: "Computation", val: "Bidirectional Flow IAT" },
        { label: "Standard", val: "CIC-IDS2017 Format" }
      ],
      action: { text: "View Feature Pipeline", url: "/?view=monitoring" }
    },
    "xgboost-classifier": {
      badge: "Machine Learning",
      title: "XGBoost Champion Classifier",
      desc: "Trained and validated gradient boosted tree model evaluating flow vectors across 15 classes (14 hostile attacks and benign traffic) with 99.86% overall recall.",
      meta: [
        { label: "Algorithm", val: "XGBoost GBDT" },
        { label: "Classes", val: "15 Distinct Labels" },
        { label: "Recall", val: "99.86% Validated" }
      ],
      action: { text: "Inspect Model Signatures", url: "/#threat-intelligence" }
    },
    "verdict": {
      badge: "Inference Output",
      title: "Real-Time Threat Verdict",
      desc: "Generates multi-class prediction label, attack severity level (Critical, High, Medium, Safe), and calibrated confidence probability percentage per evaluated flow.",
      meta: [
        { label: "Output", val: "Label + Confidence %" },
        { label: "Severity", val: "4-Level Threat Scale" },
        { label: "Dispatch", val: "Instant WebSocket Push" }
      ],
      action: { text: "Launch Telemetry View", url: "/?view=monitoring" }
    },
    "branch-portscan": {
      badge: "Branch: Port Scanner",
      title: "Port Security Auditing",
      desc: "Fast asynchronous TCP service enumeration engine discovering active listening daemons, exposed ports, and service banners.",
      meta: [
        { label: "Modes", val: "Localhost, Single, Subnet" },
        { label: "Presets", val: "Top 20, 100, 1000, Custom" },
        { label: "Export", val: "Structured JSON / CSV" }
      ],
      action: { text: "Launch Port Scanner", url: "/?view=port-scanner" }
    },
    "localhost": {
      badge: "Loopback Audit",
      title: "127.0.0.1 Localhost Scan",
      desc: "Instant loopback interface security verification inspecting locally bound services, database daemons, and administrative ports.",
      meta: [
        { label: "Target", val: "127.0.0.1 (Loopback)" },
        { label: "Timeout", val: "100ms Optimized" }
      ],
      action: { text: "Scan Localhost", url: "/?view=port-scanner" }
    },
    "single-target": {
      badge: "Targeted Audit",
      title: "Single IP Address Scan",
      desc: "Point-to-point TCP connect scans examining defined port boundaries for specific internal hosts, servers, or perimeter firewalls.",
      meta: [
        { label: "Input", val: "IPv4 Host / Domain" },
        { label: "Sockets", val: "Multi-threaded Workers" }
      ],
      action: { text: "Configure Target Scan", url: "/?view=port-scanner" }
    },
    "subnet-scan": {
      badge: "Horizontal Recon",
      title: "Subnet CIDR Range Sweep",
      desc: "Horizontal port scanning sweeping across entire subnet address spaces (e.g. 192.168.1.0/24) to locate rogue services and exposed endpoints.",
      meta: [
        { label: "Range", val: "CIDR /24 Subnets" },
        { label: "Concurrency", val: "Thread Pool Throttled" }
      ],
      action: { text: "Run Subnet Audit", url: "/?view=port-scanner" }
    },
    "export": {
      badge: "Reporting",
      title: "Audit Report Export",
      desc: "Structured export facility saving comprehensive scan outcomes, port banners, service names, and response latencies in JSON or CSV files.",
      meta: [
        { label: "Formats", val: "JSON, CSV" },
        { label: "Structure", val: "Host, Port, State, Service" }
      ],
      action: { text: "Open Port Scanner", url: "/?view=port-scanner" }
    },
    "branch-attacks": {
      badge: "Branch: Threat Signatures",
      title: "14 Attack Classes & Benign",
      desc: "Comprehensive attack classification system validated on 64,000+ benchmark network flow records across four operational threat domains.",
      meta: [
        { label: "Trained Classes", val: "15 Classes" },
        { label: "Domain", val: "CIC-IDS2017 Dataset" },
        { label: "Coverage", val: "DoS, Web, Brute, Recon" }
      ],
      action: { text: "View Attack Signatures", url: "/#threat-intelligence" }
    },
    "dos": {
      badge: "Attack Category",
      title: "Denial of Service (DoS/DDoS) · 5",
      desc: "Volumetric flooding and low-and-slow exhaustion attacks: DDoS, DoS Hulk, DoS GoldenEye, DoS Slowloris, and DoS Slowhttptest.",
      meta: [
        { label: "Signatures", val: "5 Attack Vectors" },
        { label: "Recall Rate", val: "99.8% Average" }
      ],
      action: { text: "View DoS Signatures", url: "/#threat-intelligence" }
    },
    "web-attacks": {
      badge: "Attack Category",
      title: "Web Application Attacks · 3",
      desc: "Injections and privilege escalations targeting web applications: SQL Injection, Cross-Site Scripting (XSS), and Web Brute Force.",
      meta: [
        { label: "Signatures", val: "SQLi, XSS, Brute Force" },
        { label: "Precision", val: "99.2% Validated" }
      ],
      action: { text: "View Web Signatures", url: "/#threat-intelligence" }
    },
    "brute-force": {
      badge: "Attack Category",
      title: "Brute Force & Exploits · 3",
      desc: "Credential harvesting and SSL memory over-read vulnerabilities: SSH-Patator, FTP-Patator, and OpenSSL Heartbleed (CVE-2014-0160).",
      meta: [
        { label: "Protocols", val: "SSH (22), FTP (21), TLS (443)" },
        { label: "Heartbleed", val: "100.0% Recall" }
      ],
      action: { text: "View Exploit Signatures", url: "/#threat-intelligence" }
    },
    "recon-infil": {
      badge: "Attack Category",
      title: "Recon & Infiltration · 3",
      desc: "Surveillance and lateral network penetration attacks: PortScan sweeps, Ares C2 Botnet communications, and Subnet Infiltration.",
      meta: [
        { label: "Vectors", val: "PortScan, Bot, Infiltration" },
        { label: "Lateral Movement", val: "100.0% Detection" }
      ],
      action: { text: "View Recon Signatures", url: "/#threat-intelligence" }
    },
    "branch-discovery": {
      badge: "Branch: Network Discovery",
      title: "Subnet Asset Reconnaissance",
      desc: "Autonomous local subnet scanner discovering active network devices, resolving IEEE MAC vendor fingerprints, and tracking device availability.",
      meta: [
        { label: "Probes", val: "ARP Table + ICMP Sweeps" },
        { label: "Vendors", val: "IEEE OUI Registry" },
        { label: "Views", val: "Device Cards & Data Table" }
      ],
      action: { text: "Open Network Discovery", url: "/network-discovery" }
    },
    "arp-icmp": {
      badge: "Discovery Mechanism",
      title: "ARP + ICMP Subnet Sweep",
      desc: "Non-intrusive dual-mode network mapping gathering local kernel ARP neighbors and dispatching asynchronous ICMP echo probes.",
      meta: [
        { label: "Stealth", val: "Non-intrusive Sweep" },
        { label: "Protocols", val: "ARP + ICMP Echo" }
      ],
      action: { text: "Launch Discovery Scan", url: "/network-discovery" }
    },
    "mac-vendor": {
      badge: "Hardware Fingerprinting",
      title: "MAC & OUI Vendor Fingerprint",
      desc: "Translates 24-bit MAC address prefixes into verified hardware manufacturers (Intel, Apple, Cisco, TP-Link, Samsung, Raspberry Pi).",
      meta: [
        { label: "Lookup", val: "IEEE OUI Database" },
        { label: "Resolution", val: "Instant Local Match" }
      ],
      action: { text: "Inspect Discovered Vendors", url: "/network-discovery" }
    },
    "device-types": {
      badge: "Asset Categorization",
      title: "Device Role Classification",
      desc: "Heuristic classification identifying device types (Routers/Gateways, Servers, Desktops/Laptops, Smartphones, and Embedded IoT).",
      meta: [
        { label: "Categories", val: "Gateway, PC, Mobile, IoT" },
        { label: "Badging", val: "Role-specific Color Badges" }
      ],
      action: { text: "View Device Roles", url: "/network-discovery" }
    },
    "inventory-views": {
      badge: "UI Management",
      title: "Cards & Data Table Views",
      desc: "Interactive dual-view asset management interface offering rich visual device cards with telemetry pills and a searchable tabular data view.",
      meta: [
        { label: "Views", val: "Grid Cards + Tabular View" },
        { label: "Actions", val: "Quick Port Scan Handoff" }
      ],
      action: { text: "Explore Inventory", url: "/network-discovery" }
    }
  };

  // Branch Connector Mapping Definitions
  const CONNECTIONS = [
    // Center to Left Major Branches
    { from: "branch-core", to: "branch-monitoring", branch: "teal", dir: "left" },
    { from: "branch-core", to: "branch-portscan", branch: "amber", dir: "left" },

    // Center to Right Major Branches
    { from: "branch-core", to: "branch-attacks", branch: "coral", dir: "right" },
    { from: "branch-core", to: "branch-discovery", branch: "blue", dir: "right" },

    // Live Monitoring (Teal) to Children
    { from: "branch-monitoring", to: "packet-capture", branch: "teal", dir: "left", group: "monitoring" },
    { from: "branch-monitoring", to: "feature-extraction", branch: "teal", dir: "left", group: "monitoring" },
    { from: "branch-monitoring", to: "xgboost-classifier", branch: "teal", dir: "left", group: "monitoring" },
    { from: "branch-monitoring", to: "verdict", branch: "teal", dir: "left", group: "monitoring" },

    // Port Scanner (Amber) to Children
    { from: "branch-portscan", to: "localhost", branch: "amber", dir: "left", group: "portscan" },
    { from: "branch-portscan", to: "single-target", branch: "amber", dir: "left", group: "portscan" },
    { from: "branch-portscan", to: "subnet-scan", branch: "amber", dir: "left", group: "portscan" },
    { from: "branch-portscan", to: "export", branch: "amber", dir: "left", group: "portscan" },

    // Attack Classes (Coral) to Children
    { from: "branch-attacks", to: "dos", branch: "coral", dir: "right", group: "attacks" },
    { from: "branch-attacks", to: "web-attacks", branch: "coral", dir: "right", group: "attacks" },
    { from: "branch-attacks", to: "brute-force", branch: "coral", dir: "right", group: "attacks" },
    { from: "branch-attacks", to: "recon-infil", branch: "coral", dir: "right", group: "attacks" },

    // Network Discovery (Blue) to Children
    { from: "branch-discovery", to: "arp-icmp", branch: "blue", dir: "right", group: "discovery" },
    { from: "branch-discovery", to: "mac-vendor", branch: "blue", dir: "right", group: "discovery" },
    { from: "branch-discovery", to: "device-types", branch: "blue", dir: "right", group: "discovery" },
    { from: "branch-discovery", to: "inventory-views", branch: "blue", dir: "right", group: "discovery" }
  ];

  function initMindMap() {
    const wrapper = document.getElementById("mindmapWrapper");
    if (!wrapper) return;

    const viewport = document.getElementById("mindmapViewport");
    const canvas = document.getElementById("mindmapCanvas");
    const svg = document.getElementById("mindmapSvg");

    const drawer = document.getElementById("mindmapDetailsDrawer");
    const drawerBadge = document.getElementById("mmDrawerBadge");
    const drawerTitle = document.getElementById("mmDrawerTitle");
    const drawerDesc = document.getElementById("mmDrawerDesc");
    const drawerMeta = document.getElementById("mmDrawerMeta");
    const drawerActionBtn = document.getElementById("mmDrawerActionBtn");
    const drawerCloseBtn = document.getElementById("mmDrawerCloseBtn");

    const zoomInBtn = document.getElementById("mmZoomInBtn");
    const zoomOutBtn = document.getElementById("mmZoomOutBtn");
    const fitBtn = document.getElementById("mmFitBtn");
    const resetBtn = document.getElementById("mmResetBtn");
    const toggleAllBranchesBtn = document.getElementById("mmToggleAllBranchesBtn");

    let activeNodeId = "branch-core";
    let isAllCollapsed = false;

    // Stable 1:1 Viewport (No scale or drag transforms)
    function applyTransform() {
      if (!canvas) return;
      canvas.style.transform = "none";
    }

    function setZoom() {
      applyTransform();
    }

    function fitToScreen() {
      applyTransform();
      renderSvgConnectors();
    }

    function resetView() {
      applyTransform();
      renderSvgConnectors();
    }

    // Draw Dynamic SVG Bezier Connector Paths (Responsive 1:1 Coordinate Mapping)
    function renderSvgConnectors() {
      if (!svg || !canvas) return;

      // On narrow mobile devices (<768px), connectors are handled via clean CSS tree layout
      if (window.innerWidth < 768) {
        svg.innerHTML = "";
        svg.style.display = "none";
        return;
      }
      svg.style.display = "block";

      const canvasRect = canvas.getBoundingClientRect();
      if (canvasRect.width === 0 || canvasRect.height === 0) return;

      // SVG matches exact rendered dimensions of the canvas
      svg.setAttribute("viewBox", `0 0 ${canvasRect.width} ${canvasRect.height}`);
      svg.setAttribute("width", canvasRect.width);
      svg.setAttribute("height", canvasRect.height);
      svg.innerHTML = "";

      CONNECTIONS.forEach(conn => {
        const fromEl = document.querySelector(`.mm-node[data-id="${conn.from}"]`);
        const toEl = document.querySelector(`.mm-node[data-id="${conn.to}"]`);
        if (!fromEl || !toEl) return;

        // Check if group is collapsed
        if (conn.group) {
          const groupEl = document.getElementById(`mmGroup${conn.group.charAt(0).toUpperCase() + conn.group.slice(1)}Children`);
          if (groupEl && groupEl.classList.contains("is-collapsed")) {
            return;
          }
        }

        const fromRect = fromEl.getBoundingClientRect();
        const toRect = toEl.getBoundingClientRect();

        // Exact pixel coordinates relative to the responsive canvas coordinate space
        let x0, y0, x1, y1;

        if (conn.dir === "left") {
          // From right element's left anchor to left element's right anchor
          x0 = fromRect.left - canvasRect.left;
          y0 = fromRect.top + fromRect.height / 2 - canvasRect.top;
          x1 = toRect.right - canvasRect.left;
          y1 = toRect.top + toRect.height / 2 - canvasRect.top;
        } else {
          // From left element's right anchor to right element's left anchor
          x0 = fromRect.right - canvasRect.left;
          y0 = fromRect.top + fromRect.height / 2 - canvasRect.top;
          x1 = toRect.left - canvasRect.left;
          y1 = toRect.top + toRect.height / 2 - canvasRect.top;
        }

        const dx = Math.abs(x1 - x0);
        const curveOffset = Math.max(16, Math.min(64, dx * 0.48));

        let d;
        if (conn.dir === "left") {
          d = `M ${x0} ${y0} C ${x0 - curveOffset} ${y0}, ${x1 + curveOffset} ${y1}, ${x1} ${y1}`;
        } else {
          d = `M ${x0} ${y0} C ${x0 + curveOffset} ${y0}, ${x1 - curveOffset} ${y1}, ${x1} ${y1}`;
        }

        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", d);
        path.setAttribute("class", `mm-connector-path mm-connector-${conn.branch}`);
        path.setAttribute("data-from", conn.from);
        path.setAttribute("data-to", conn.to);
        path.setAttribute("data-branch", conn.branch);

        // Highlight if active node is part of this path
        if (activeNodeId === conn.from || activeNodeId === conn.to) {
          path.classList.add("active");
        }

        svg.appendChild(path);
      });
    }

    // Select and inspect node details
    function selectNode(id) {
      activeNodeId = id;

      document.querySelectorAll(".mm-node").forEach(n => {
        n.classList.toggle("selected", n.getAttribute("data-id") === id);
      });

      // Update path active classes
      document.querySelectorAll(".mm-connector-path").forEach(p => {
        const from = p.getAttribute("data-from");
        const to = p.getAttribute("data-to");
        p.classList.toggle("active", from === id || to === id);
      });

      const data = MINDMAP_DATA[id] || MINDMAP_DATA["branch-core"];
      if (drawer && data) {
        if (drawerBadge) drawerBadge.textContent = data.badge;
        if (drawerTitle) drawerTitle.textContent = data.title;
        if (drawerDesc) drawerDesc.textContent = data.desc;

        if (drawerMeta) {
          drawerMeta.innerHTML = "";
          (data.meta || []).forEach(m => {
            const pill = document.createElement("span");
            pill.className = "mm-meta-pill";
            pill.innerHTML = `<strong>${m.label}:</strong> ${m.val}`;
            drawerMeta.appendChild(pill);
          });
        }

        if (drawerActionBtn && data.action) {
          drawerActionBtn.textContent = "";
          const icon = document.createElement("i");
          icon.className = "fas fa-arrow-up-right-from-square";
          drawerActionBtn.appendChild(icon);
          drawerActionBtn.appendChild(document.createTextNode(" " + data.action.text));
          drawerActionBtn.href = data.action.url;
        }

        drawer.style.display = "flex";
      }
    }

    // Toggle Branch Collapse/Expand
    function toggleBranch(branchName) {
      const groupEl = document.getElementById(`mmGroup${branchName.charAt(0).toUpperCase() + branchName.slice(1)}Children`);
      const btn = document.querySelector(`.mm-branch-toggle[data-branch="${branchName}"]`);
      if (!groupEl) return;

      const isNowCollapsed = !groupEl.classList.contains("is-collapsed");
      groupEl.classList.toggle("is-collapsed", isNowCollapsed);
      if (btn) btn.classList.toggle("collapsed", isNowCollapsed);

      renderSvgConnectors();
    }

    // Toggle All Branches
    function toggleAllBranches() {
      isAllCollapsed = !isAllCollapsed;
      ["monitoring", "portscan", "attacks", "discovery"].forEach(b => {
        const groupEl = document.getElementById(`mmGroup${b.charAt(0).toUpperCase() + b.slice(1)}Children`);
        const btn = document.querySelector(`.mm-branch-toggle[data-branch="${b}"]`);
        if (groupEl) groupEl.classList.toggle("is-collapsed", isAllCollapsed);
        if (btn) btn.classList.toggle("collapsed", isAllCollapsed);
      });
      renderSvgConnectors();
    }

    // Event Bindings
    // 1. Node Click / Enter key
    document.querySelectorAll(".mm-node").forEach(node => {
      const id = node.getAttribute("data-id");

      node.addEventListener("click", (e) => {
        if (e.target.closest(".mm-branch-toggle")) return;
        selectNode(id);
      });

      node.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          selectNode(id);
        }
      });

      node.addEventListener("mouseenter", () => {
        document.querySelectorAll(`.mm-connector-path[data-from="${id}"], .mm-connector-path[data-to="${id}"]`).forEach(p => {
          p.classList.add("active");
        });
      });

      node.addEventListener("mouseleave", () => {
        document.querySelectorAll(`.mm-connector-path[data-from="${id}"], .mm-connector-path[data-to="${id}"]`).forEach(p => {
          if (activeNodeId !== id && activeNodeId !== p.getAttribute("data-from") && activeNodeId !== p.getAttribute("data-to")) {
            p.classList.remove("active");
          }
        });
      });
    });

    // 2. Branch Collapse Buttons
    document.querySelectorAll(".mm-branch-toggle").forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const branch = btn.getAttribute("data-branch");
        toggleBranch(branch);
      });
    });

    // 3. Toolbar Controls
    if (zoomInBtn) zoomInBtn.addEventListener("click", () => {});
    if (zoomOutBtn) zoomOutBtn.addEventListener("click", () => {});
    if (fitBtn) fitBtn.addEventListener("click", fitToScreen);
    if (resetBtn) resetBtn.addEventListener("click", resetView);
    if (toggleAllBranchesBtn) toggleAllBranchesBtn.addEventListener("click", toggleAllBranches);

    if (drawerCloseBtn) {
      drawerCloseBtn.addEventListener("click", () => {
        if (drawer) drawer.style.display = "none";
      });
    }

    // 5. Initial Sizing and Rendering
    fitToScreen();
    selectNode("branch-core");
    setTimeout(renderSvgConnectors, 50);
    setTimeout(renderSvgConnectors, 250);

    // Recompute connectors on window resize or theme switch
    window.addEventListener("resize", () => {
      fitToScreen();
      renderSvgConnectors();
    });

    const themeToggleBtn = document.getElementById("themeToggleBtn");
    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        setTimeout(renderSvgConnectors, 50);
      });
    }

    // Observe Mind Map container resize
    if ("ResizeObserver" in window) {
      const ro = new ResizeObserver(() => {
        renderSvgConnectors();
      });
      ro.observe(canvas);
      ro.observe(viewport);
    }
  }

  // Auto-initialize when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initMindMap);
  } else {
    initMindMap();
  }

  window.initMindMap = initMindMap;
})();
