# 🛡️ DDoS-Guard: AI-Powered Real-Time Intrusion & DDoS Detection System

An enterprise-grade, real-time intrusion and DDoS detection system powered by Machine Learning and deep network flow telemetry.

DDoS-Guard intercepts and extracts 77 bidirectional network flow features in real-time, classifies network traffic across 15 attack classes using a champion XGBoost model (99.86% detection rate), and visualizes security threats in a responsive real-time web dashboard.

---

## 🌟 Key Features

- **Real-Time Traffic Inspection:**
  - Non-intrusive kernel packet capture via WinDivert in monitor-only mode (`Flag.SNIFF`).
  - Seamless auto-discovery of physical and wireless network adapters (Wi-Fi & Ethernet).
  - High-performance 77-feature flow extraction engine matching the CIC-IDS2017 benchmark.

- **Champion AI Model:**
  - **Algorithm:** Tuned Multi-Class XGBoost Classifier.
  - **Attack Detection Rate (Recall):** 99.86%
  - **Binary Accuracy:** 99.85% | **Binary Precision:** 99.34% | **AUC-ROC:** 1.0000
  - **15 Traffic Classes:** Benign, DDoS, Bot, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, Heartbleed, Infiltration, PortScan, SSH-Patator, Web Attack (Brute Force, SQL Injection, XSS).

- **Secure Architecture:**
  - Decoupled Windows Sniffer Service running in background with kernel privileges.
  - Hardened local IPC interface (`127.0.0.1:50505`) with constant-time HMAC token authentication.
  - Self-healing IPC client with automatic secret synchronization and retry resilience.

- **Interactive Dashboard & Simulation:**
  - Dark-mode responsive web interface with live attack classification, flow metrics, and alert triggers.
  - Built-in traffic simulator (`send_traffic.py`) for streaming live benign and attack flows without requiring root privileges.

---

## 🚀 Quick Start

### 1. Prerequisites
- Windows 10/11 (64-bit)
- Python 3.10+ installed

### 2. Installation
```powershell
# Clone the repository
git clone https://github.com/3lifat7y/graduation-project.git
cd graduation-project

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Launching the System

#### Option A: Quick Launch (Interactive Web UI + Simulation)
Double-click `run_ddos_guard.bat` or run:
```powershell
python api.py
```
Open your browser at: **`http://127.0.0.1:5000`**

To simulate attack traffic in real-time:
```powershell
python send_traffic.py
# Or double-click simulate_attack.bat
```

#### Option B: Dedicated Windows Service (Real Physical Packet Sniffing)
Open PowerShell as **Administrator**:
```powershell
# Install Windows Service
powershell -ExecutionPolicy Bypass -File .\service_manager.ps1 Install

# Start Windows Service
powershell -ExecutionPolicy Bypass -File .\service_manager.ps1 Start

# Check Status
powershell -ExecutionPolicy Bypass -File .\service_manager.ps1 Status
```

---

## 📁 Project Structure

```text
Grad project/
├── api.py                          # Flask REST API & Web Dashboard application entry point
├── modules/                        # Independent feature packages
│   ├── common/                     # Shared services (network interface detection)
│   │   ├── __init__.py
│   │   └── network_detector.py
│   ├── monitoring/                 # Live network monitoring & capture engine
│   │   ├── __init__.py
│   │   ├── capture_engine.py       # 77-feature extraction engine (WinDivert/Rolling window)
│   │   ├── ipc_client.py           # Authenticated local IPC client
│   │   ├── service.py              # Windows Sniffer Service implementation
│   │   └── service_helper.py       # Non-privileged SCM query & UAC elevation helper
│   ├── port_scanner/               # Independent Port & Network Scanner module
│   │   ├── __init__.py
│   │   └── scanner.py              # Pure-Python async socket port scanner
│   └── network_discovery/          # Independent Local Network Discovery module
│       ├── __init__.py
│       └── discovery.py            # Multi-method LAN host discovery (ARP/ICMP/NetBIOS)
├── ml_engine/                      # Machine learning training & feature preparation
│   ├── __init__.py
│   ├── train.py                    # Champion XGBoost training & evaluation pipeline
│   └── read_features.py            # Feature extractor & JSON dataset generator
├── scripts/                        # Operational scripts & management tools
│   ├── __init__.py
│   ├── send_traffic.py             # Realistic attack and benign traffic flow simulator
│   └── service_manager.ps1         # Windows Service lifecycle manager (Install/Start/Stop)
├── tests/                          # Unified test suites (Unit & Integration)
│   ├── __init__.py
│   ├── test_scan_flow.py
│   ├── test_service_architecture.py
│   ├── test_port_scanner.py
│   ├── test_network_discovery.py
│   ├── test_continuous_monitoring.py
│   ├── test_ipc_auth.py
│   └── test_service_manager_syntax.py
├── final_output_new_dataset/       # Active champion model, scaler, configs & evaluation reports
│   ├── models/                     # Serialized XGBoost model (best_model.joblib) & scaler
│   ├── configs/                    # Exact 77 feature schema & label mappings
│   ├── reports/                    # Classification reports, confusion matrices, audit logs
│   └── datasets/                   # Isolated test set
├── static/                         # Web UI stylesheets, JavaScript, and assets
├── templates/                      # HTML5 dashboard templates
├── run_ddos_guard.bat              # One-click Windows launcher for Web UI
├── simulate_attack.bat             # One-click Windows launcher for attack simulator
├── service_manager.ps1             # Root Windows Service launcher
└── requirements.txt                # Python dependencies
```

---

## 🧪 Testing

Run the comprehensive test suite across all modules:
```powershell
python -m unittest discover tests -v
```

Or run individual test suites:
```powershell
python -m unittest tests/test_service_architecture.py
python -m unittest tests/test_scan_flow.py
python -m unittest tests/test_port_scanner.py
python -m unittest tests/test_network_discovery.py
python -m unittest tests/test_continuous_monitoring.py
python -m unittest tests/test_service_manager_syntax.py
```

---

## 📜 License
This project is developed as an academic Graduation Project.
