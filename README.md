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
├── api.py                      # Flask REST API & Web Dashboard backend
├── ddos_guard_service.py       # Windows Sniffer Service & Secure Local IPC capture engine
├── service_helper.py           # Unprivileged SCM query helper & scoped UAC elevation manager
├── ipc_client.py               # Resilient local IPC client with auto-reconnect & token auth
├── feature_extraction2.py      # Real-time 77 network flow feature extractor
├── network_detector.py         # Network interface discovery & driver validation
├── Train.py                    # Complete AI model training pipeline & benchmark suite
├── send_traffic.py             # Realistic attack and benign traffic flow simulator
├── read_features.py            # Feature extractor & JSON dataset generator
├── service_manager.ps1         # Windows Service lifecycle manager (Install/Start/Stop)
├── test_service_architecture.py # Non-privileged service architecture & pipeline verification suite
├── run_ddos_guard.bat          # One-click Windows launcher for Web UI
├── simulate_attack.bat         # One-click Windows launcher for attack simulator
├── requirements.txt            # Python dependencies
├── final_output_new_dataset/   # Active champion model, scaler, configs & evaluation reports
│   ├── models/                 # Serialized XGBoost model (best_model.joblib) & scaler
│   ├── configs/                # Exact 77 feature schema & label mappings
│   ├── reports/                # Classification reports, confusion matrices, audit logs
│   └── datasets/               # Isolated test set
├── static/                     # Web UI stylesheets, JavaScript, and assets
└── templates/                  # HTML5 dashboard templates
```

---

## 🧪 Testing

Run the verification test suites:
```powershell
# Non-privileged Service Architecture & Pipeline Verification (7 automated tests)
python test_service_architecture.py

# IPC Authentication and security test suite (requires service running)
python test_ipc_auth.py

# End-to-end Flask integration test (requires service running)
python test_flask_ipc_live.py
```

---

## 📜 License
This project is developed as an academic Graduation Project.
