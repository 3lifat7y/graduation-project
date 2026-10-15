from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import pickle
import json
import os
import sys
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import numpy as np
import pandas as pd
import joblib

import datetime
import secrets

from network_detector import auto_detect_primary_interface, check_capture_drivers
from feature_extraction2 import FlowStatsCollector, capture_window_windivert, OFFICIAL_77_FEATURES
from ipc_client import DDoSGuardIPCClient
from service_helper import get_service_status, request_service_start, is_service_online, is_authenticated_service_online

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

ipc_client = DDoSGuardIPCClient()


def log_diag(category: str, message: str, **kwargs):
    """Timestamped diagnostic console logging for real-time traceability."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    extra = " | " + " ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
    print(f"[{ts}] [{category.upper()}] {message}{extra}", flush=True)


@app.before_request
def log_request_start():
    request._start_time = time.time()
    if request.path.startswith("/api"):
        log_diag("HTTP_REQ", f"--> {request.method} {request.path} from {request.remote_addr}")


@app.after_request
def log_request_end(response):
    if request.path.startswith("/api"):
        duration_ms = (time.time() - getattr(request, "_start_time", time.time())) * 1000
        log_diag("HTTP_RES", f"<-- {request.method} {request.path} {response.status_code} ({duration_ms:.1f}ms)")
    return response


BASE_DIR = Path(__file__).resolve().parent
NEW_DATASET_DIR = BASE_DIR / "final_output_new_dataset"
V2_DIR = BASE_DIR / "final_output_optimized_v2"
TOP3_DIR = BASE_DIR / "final_output_top3"
OPTIMIZED_DIR = BASE_DIR / "final_output_optimized"
LEGACY_DIR = BASE_DIR / "final output"

FEATURE_EXTRACTION_SCRIPT = str(BASE_DIR / "feature_extraction2.py")
TRAFFIC_JSON_PATH = str(BASE_DIR / "extracted_features.json")

CLASS_LABELS = {
    0: "Benign", 1: "Bot", 2: "DDoS", 3: "DoS GoldenEye",
    4: "DoS Hulk", 5: "DoS Slowhttptest", 6: "DoS slowloris",
    7: "FTP-Patator", 8: "Heartbleed", 9: "Infiltration",
    10: "PortScan", 11: "SSH-Patator", 12: "Web Attack - Brute Force",
    13: "Web Attack - SQL Injection", 14: "Web Attack - XSS"
}

BENIGN_IDX = 0
model = None
scaler = None
FEATURE_COLUMNS = None
capture_process = None
is_monitoring = False
last_mtime_read = 0.5
last_result = {"label": None, "is_attack": False, "confidence": 0.0, "timestamp": None, "consec_normal": 0}
STALE_THRESHOLD = 1.0 
NORMAL_CONFIRM_COUNT = 1  
NORMAL_CONFIRM_TIME = 1.0  

# Mapping of equivalent flow feature aliases across datasets & live capture
FEATURE_ALIASES = {
    "Avg Packet Size": ["Average Packet Size", "Avg Packet Size"],
    "Fwd Packets Length Total": ["Total Length of Fwd Packets", "Fwd Packets Length Total"],
    "Bwd Packets Length Total": ["Total Length of Bwd Packets", "Bwd Packets Length Total"],
    "Packet Length Min": ["Min Packet Length", "Packet Length Min"],
    "Packet Length Max": ["Max Packet Length", "Packet Length Max"],
    "Init Fwd Win Bytes": ["Init_Win_bytes_forward", "Init Fwd Win Bytes"],
    "Init Bwd Win Bytes": ["Init_Win_bytes_backward", "Init Bwd Win Bytes"],
    "Fwd Act Data Packets": ["act_data_pkt_fwd", "Fwd Act Data Packets"],
    "Fwd Seg Size Min": ["min_seg_size_forward", "Fwd Seg Size Min"]
}

# Thread-safe scan session management
scan_session_lock = threading.Lock()
current_scan_session = {
    "status": "ready",  # ready, scanning, processing, prediction_available, insufficient_traffic, error
    "scan_id": None,
    "started_at": None,
    "duration": 3.0,
    "min_packets": 3,
    "packets_captured": 0,
    "interface": None,
    "driver_status": None,
    "prediction": None,
    "label": None,
    "is_attack": False,
    "confidence": 0.0,
    "flow_summary": {},
    "error": None,
    "message": "Ready to scan network traffic."
}

# Live packet collector for current session
live_collector = FlowStatsCollector()
last_injected_flow = None


def load_model_and_scaler():
    global model, scaler, CLASS_LABELS, FEATURE_COLUMNS, BENIGN_IDX
    if model is not None and scaler is not None:
        return
    
    # Priority 1: Check for NEW DATASET trained champion model
    new_model = NEW_DATASET_DIR / "models" / "best_model.joblib"
    new_scaler = NEW_DATASET_DIR / "models" / "scaler.joblib"
    new_labels = NEW_DATASET_DIR / "configs" / "label_mapping.json"
    new_features = NEW_DATASET_DIR / "configs" / "feature_columns.json"

    # Priority 2: Check for V2 trained champion model
    v2_model = V2_DIR / "models" / "best_model.joblib"
    v2_scaler = V2_DIR / "models" / "scaler.joblib"
    v2_labels = V2_DIR / "configs" / "label_mapping.json"
    v2_features = V2_DIR / "configs" / "feature_columns.json"

    # Priority 3: Check for top3 trained model
    top3_model = TOP3_DIR / "models" / "best_model.joblib"
    top3_scaler = TOP3_DIR / "models" / "scaler.joblib"
    top3_labels = TOP3_DIR / "configs" / "label_mapping.json"
    top3_features = TOP3_DIR / "configs" / "feature_columns.json"

    # Priority 4: Check for optimized model
    opt_model = OPTIMIZED_DIR / "models" / "best_model.joblib"
    opt_scaler = OPTIMIZED_DIR / "models" / "scaler.joblib"
    opt_labels = OPTIMIZED_DIR / "configs" / "label_mapping.json"
    opt_features = OPTIMIZED_DIR / "configs" / "feature_columns.json"
    
    if new_model.exists() and new_scaler.exists():
        print(f"✨ Loading NEW DATASET CHAMPION model from: {new_model}")
        model = joblib.load(new_model)
        scaler = joblib.load(new_scaler)
        if new_labels.exists():
            with open(new_labels, 'r', encoding='utf-8') as f:
                raw_labels = json.load(f)
                CLASS_LABELS = {int(k): str(v) for k, v in raw_labels.items()}
        if new_features.exists():
            with open(new_features, 'r', encoding='utf-8') as f:
                FEATURE_COLUMNS = json.load(f)
    elif v2_model.exists() and v2_scaler.exists():
        print(f"✨ Loading V2 CHAMPION model from: {v2_model}")
        model = joblib.load(v2_model)
        scaler = joblib.load(v2_scaler)
        if v2_labels.exists():
            with open(v2_labels, 'r', encoding='utf-8') as f:
                raw_labels = json.load(f)
                CLASS_LABELS = {int(k): str(v) for k, v in raw_labels.items()}
        if v2_features.exists():
            with open(v2_features, 'r', encoding='utf-8') as f:
                FEATURE_COLUMNS = json.load(f)
    elif top3_model.exists() and top3_scaler.exists():
        print(f"✨ Loading TOP3 model from: {top3_model}")
        model = joblib.load(top3_model)
        scaler = joblib.load(top3_scaler)
        if top3_labels.exists():
            with open(top3_labels, 'r', encoding='utf-8') as f:
                raw_labels = json.load(f)
                CLASS_LABELS = {int(k): str(v) for k, v in raw_labels.items()}
        if top3_features.exists():
            with open(top3_features, 'r', encoding='utf-8') as f:
                FEATURE_COLUMNS = json.load(f)
    elif opt_model.exists() and opt_scaler.exists():
        print(f"✨ Loading OPTIMIZED model from: {opt_model}")
        model = joblib.load(opt_model)
        scaler = joblib.load(opt_scaler)
        if opt_labels.exists():
            with open(opt_labels, 'r', encoding='utf-8') as f:
                raw_labels = json.load(f)
                CLASS_LABELS = {int(k): str(v) for k, v in raw_labels.items()}
        if opt_features.exists():
            with open(opt_features, 'r', encoding='utf-8') as f:
                FEATURE_COLUMNS = json.load(f)
    else:
        # Priority 5: Fallback to existing legacy model in 'final output'
        legacy_model = LEGACY_DIR / "model_01-12.pht"
        legacy_scaler = LEGACY_DIR / "scaler.pkl"
        legacy_labels = LEGACY_DIR / "label_mapping_01-12.json"
        
        print(f"📦 Loading LEGACY model from: {legacy_model}")
        try:
            model = joblib.load(legacy_model)
        except Exception:
            with open(legacy_model, 'rb') as f:
                model = pickle.load(f)
                
        try:
            scaler = joblib.load(legacy_scaler)
        except Exception:
            with open(legacy_scaler, 'rb') as f:
                scaler = pickle.load(f)
                
        if legacy_labels.exists():
            try:
                with open(legacy_labels, 'r', encoding='utf-8') as f:
                    raw_labels = json.load(f)
                    CLASS_LABELS = {int(k): str(v) for k, v in raw_labels.items()}
            except Exception:
                pass
                
        FEATURE_COLUMNS = getattr(scaler, 'feature_names_in_', None)

    # Detect benign index
    benign_candidates = [k for k, v in CLASS_LABELS.items() if str(v).lower() in ["benign", "normal", "safe"]]
    BENIGN_IDX = benign_candidates[0] if benign_candidates else 0
        
    num_feats = getattr(model, 'n_features_in_', len(FEATURE_COLUMNS) if FEATURE_COLUMNS is not None else 0)
    print(f"✅ Model loaded successfully → {num_feats} features, {len(CLASS_LABELS)} classes (Benign index: {BENIGN_IDX})")
    print(f"✅ Scaler loaded → {type(scaler).__name__}")

# Initialize model and scaler on module import
load_model_and_scaler()


def prepare_features(data_dict: Dict[str, Any]) -> np.ndarray:
    """
    Prepares input features with exact column name matching and alias resolution,
    converting to float64 to preserve precision for large flow durations.
    """
    global FEATURE_COLUMNS
    expected = getattr(model, 'n_features_in_', len(FEATURE_COLUMNS) if FEATURE_COLUMNS else 77)
    
    # Unwrap nested features dictionary if present
    if "features" in data_dict and isinstance(data_dict["features"], dict):
        data_dict = data_dict["features"]

    # Clean incoming dictionary keys of whitespace
    cleaned_dict = {k.strip(): v for k, v in data_dict.items()}
    
    features = []
    if FEATURE_COLUMNS is not None and len(FEATURE_COLUMNS) == expected:
        for col_name in FEATURE_COLUMNS:
            col_clean = col_name.strip()
            val = None
            if col_clean in cleaned_dict:
                val = cleaned_dict[col_clean]
            elif col_name in cleaned_dict:
                val = cleaned_dict[col_name]
            else:
                # Check alias mapping
                aliases = FEATURE_ALIASES.get(col_clean, [])
                for alt in aliases:
                    if alt in cleaned_dict:
                        val = cleaned_dict[alt]
                        break
            if val is None:
                val = 0.0
            try:
                val = float(val)
                if np.isnan(val) or np.isinf(val):
                    val = 0.0
            except (ValueError, TypeError):
                val = 0.0
            features.append(val)
    else:
        values = list(data_dict.values())
        for i in range(expected):
            if i < len(values):
                try:
                    val = float(values[i])
                    if np.isnan(val) or np.isinf(val):
                        val = 0.0
                    features.append(val)
                except (ValueError, TypeError):
                    features.append(0.0)
            else:
                features.append(0.0)

    X = np.array([features], dtype=np.float64)

    if scaler is not None:
        feature_names = getattr(scaler, 'feature_names_in_', None)
        if feature_names is not None and len(feature_names) == X.shape[1]:
            X = pd.DataFrame(X, columns=feature_names)
        X = scaler.transform(X)
        
    return X


def run_scan_worker(scan_id: str, adapter_info: Dict[str, Any], driver_info: Dict[str, Any], duration: float, min_packets: int):
    """Background worker that conducts the windowed packet capture and model prediction."""
    global current_scan_session, is_monitoring, live_collector, last_result
    start_t = time.time()
    can_capture_physical = driver_info.get("can_capture_live", False)
    extracted_feats = None

    log_diag("SCAN_WORKER", f"Worker started for scan {scan_id} (duration={duration}s, min_packets={min_packets})",
             adapter=adapter_info.get("name"), adapter_type=adapter_info.get("type"))

    # Check if dedicated Windows Sniffer Service is actively running via IPC
    service_active = ipc_client.is_service_running()

    if service_active:
        # Delegate live packet capture to Windows Service (running with kernel privileges in monitor mode)
        log_diag("IPC_CMD", f"Sending START_SCAN to Windows Service (duration={duration}s, scan_id={scan_id})")
        svc_start = ipc_client.start_scan(duration=duration, min_packets=min_packets, scan_id=scan_id)
        if svc_start.get("status") == "error":
            err_msg = svc_start.get("message") or "Failed to start capture window on service."
            log_diag("IPC_ERROR", f"Service start_scan error: {err_msg}", scan_id=scan_id)
            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    current_scan_session.update({
                        "status": "error",
                        "error": err_msg,
                        "message": f"Service capture failed to start: {err_msg}"
                    })
                    is_monitoring = False
            return

        # Poll service for capture window completion
        poll_timeout = duration + 3.5
        poll_start = time.time()
        last_log_t = 0.0

        while time.time() - poll_start < poll_timeout:
            with scan_session_lock:
                if current_scan_session.get("scan_id") != scan_id or current_scan_session.get("status") != "scanning":
                    log_diag("SCAN_CANCEL", f"Scan {scan_id} was cancelled by user.", scan_id=scan_id)
                    ipc_client.stop_scan()
                    return  # Cancelled

            svc_status = ipc_client.get_scan_status(scan_id)
            resp_scan_id = svc_status.get("scan_id")

            # CRITICAL: Verify response belongs to THIS scan session to prevent stale result reuse
            if resp_scan_id != scan_id:
                time.sleep(0.1)
                continue

            curr_st = svc_status.get("status")

            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    pkts = svc_status.get("packets_captured")
                    if pkts is not None:
                        current_scan_session["packets_captured"] = pkts

            now = time.time()
            if now - last_log_t >= 0.8:
                log_diag("CAPTURE_PROGRESS", f"Scan {scan_id}: {svc_status.get('packets_captured', 0)} pkts ({now - start_t:.1f}s)", scan_id=scan_id)
                last_log_t = now

            if curr_st == "captured":
                extracted_feats = svc_status.get("features")
                pkts_seen = svc_status.get("packets_captured", 0)
                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        current_scan_session["packets_captured"] = pkts_seen
                        current_scan_session["is_live_capture"] = True
                log_diag("CAPTURE_COMPLETE", f"Scan {scan_id} successfully captured {pkts_seen} packets via WinDivert kernel engine.", scan_id=scan_id)
                break
            elif curr_st == "insufficient_traffic":
                total_seen = svc_status.get("packets_captured", 0)
                dur = svc_status.get("duration", round(time.time() - start_t, 2))
                log_diag("INSUFFICIENT_TRAFFIC", f"Scan {scan_id}: Only {total_seen} pkts in {dur}s (min: {min_packets})", scan_id=scan_id)
                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        current_scan_session.update({
                            "status": "insufficient_traffic",
                            "packets_captured": total_seen,
                            "min_required": min_packets,
                            "duration": dur,
                            "message": f"Network was quiet: only {total_seen} packet(s) intercepted in {dur}s."
                        })
                        is_monitoring = False
                return
            elif curr_st in ["error", "service_unavailable", "timeout"]:
                err_msg = svc_status.get("message") or "Communication with packet sniffer service lost."
                log_diag("SERVICE_ERROR", f"Scan {scan_id} failed: {err_msg}", scan_id=scan_id)
                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        current_scan_session.update({
                            "status": "error",
                            "error": err_msg,
                            "error_type": svc_status.get("error_type", "ServiceError"),
                            "message": f"Service capture error: {err_msg}"
                        })
                        is_monitoring = False
                return
            time.sleep(0.1)

    elif can_capture_physical:
        # Local process has Administrator privilege: Run WinDivert directly
        log_diag("PHYSICAL_CAPTURE", f"Running direct WinDivert capture on interface {adapter_info.get('name')}", scan_id=scan_id)
        status, extracted_feats = capture_window_windivert(
            interface_name=adapter_info.get("name"),
            duration=duration,
            min_packets=min_packets
        )
        if status.get("status") == "error":
            err_msg = status.get("message")
            log_diag("CAPTURE_ERROR", f"Direct capture error: {err_msg}", scan_id=scan_id)
            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    current_scan_session.update({
                        "status": "error",
                        "error": err_msg,
                        "error_type": status.get("error_type"),
                        "message": f"Packet capture failed: {err_msg}"
                    })
                    is_monitoring = False
            return
        elif status.get("status") == "insufficient_traffic":
            total_seen = status.get("packets_captured", 0)
            log_diag("INSUFFICIENT_TRAFFIC", f"Direct capture quiet: {total_seen} pkts", scan_id=scan_id)
            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    current_scan_session.update({
                        "status": "insufficient_traffic",
                        "packets_captured": total_seen,
                        "min_required": min_packets,
                        "duration": round(time.time() - start_t, 2),
                        "message": f"Network was quiet: only {total_seen} packet(s) intercepted in {round(time.time() - start_t, 2)}s."
                    })
                    is_monitoring = False
            return
    else:
        # Service offline & Local process non-elevated: Fail clearly with ZERO fake or synthetic fallbacks
        err_msg = (
            "DDoS-Guard Windows Sniffer Service is offline or unreachable. "
            "Kernel packet capture requires the service to be started. "
            "Please click 'Scan Network' to trigger elevation, or start the service via service_manager.ps1."
        )
        log_diag("SERVICE_OFFLINE", f"Scan {scan_id} failed: Service is offline and local process is non-elevated.", scan_id=scan_id)
        with scan_session_lock:
            if current_scan_session.get("scan_id") == scan_id:
                current_scan_session.update({
                    "status": "error",
                    "error_type": "ServiceOffline",
                    "error": err_msg,
                    "message": err_msg
                })
                is_monitoring = False
        return

    # Guard against missing extracted features (e.g. timeout without capture)
    if extracted_feats is None:
        err_msg = f"Packet capture window timed out ({poll_timeout:.1f}s) without receiving flow data."
        log_diag("CAPTURE_TIMEOUT", err_msg, scan_id=scan_id)
        with scan_session_lock:
            if current_scan_session.get("scan_id") == scan_id:
                current_scan_session.update({
                    "status": "error",
                    "error_type": "CaptureTimeout",
                    "error": err_msg,
                    "message": err_msg
                })
                is_monitoring = False
        return

    with scan_session_lock:
        if current_scan_session.get("scan_id") != scan_id:
            return  # Cancelled
        current_scan_session["status"] = "processing"
        current_scan_session["message"] = "Processing extracted flow features through AI model..."

    # Preprocess & Predict
    try:
        inf_start = time.time()
        X = prepare_features(extracted_feats)
        prediction = int(model.predict(X)[0])
        label = CLASS_LABELS.get(prediction, "Unknown")
        is_attack = bool(prediction != BENIGN_IDX and str(label).lower() not in ["benign", "normal", "safe"])
        confidence = 100.0
        if hasattr(model, 'predict_proba'):
            try:
                proba = model.predict_proba(X)[0]
                confidence = round(float(proba[prediction]) * 100, 2)
            except Exception:
                pass

        inf_duration_ms = (time.time() - inf_start) * 1000

        flow_summary = {
            "packets_captured": int(extracted_feats.get("Total Fwd Packets", 0) + extracted_feats.get("Total Backward Packets", 0)),
            "flow_duration_us": float(extracted_feats.get("Flow Duration", 0)),
            "flow_bytes_per_s": round(float(extracted_feats.get("Flow Bytes/s", 0)), 2),
            "flow_packets_per_s": round(float(extracted_feats.get("Flow Packets/s", 0)), 2),
            "protocol": int(extracted_feats.get("Protocol", 6)),
            "avg_packet_size": round(float(extracted_feats.get("Avg Packet Size", 0)), 2)
        }

        # Save to extracted_features.json for record
        payload = {**extracted_feats, **flow_summary, "prediction": prediction, "label": label, "is_attack": is_attack}
        tmp_f = Path(TRAFFIC_JSON_PATH + ".tmp")
        try:
            with open(tmp_f, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            tmp_f.replace(TRAFFIC_JSON_PATH)
        except Exception:
            pass

        with scan_session_lock:
            if current_scan_session.get("scan_id") == scan_id:
                total_pkts = max(current_scan_session.get("packets_captured", 0), flow_summary["packets_captured"])
                current_scan_session.update({
                    "status": "prediction_available",
                    "prediction": prediction,
                    "label": label,
                    "is_attack": is_attack,
                    "confidence": confidence,
                    "flow_summary": flow_summary,
                    "packets_captured": total_pkts,
                    "message": "DDoS Attack Detected!" if is_attack else "Normal Traffic - Safe",
                    "timestamp": time.strftime("%H:%M:%S")
                })
                last_result = {
                    "label": label,
                    "is_attack": is_attack,
                    "confidence": confidence,
                    "timestamp": time.strftime("%H:%M:%S")
                }
                is_monitoring = False

        log_diag("INFERENCE_COMPLETE",
                 f"Scan {scan_id} prediction -> Label: '{label}' (is_attack={is_attack}), "
                 f"Confidence: {confidence}%, Packets: {total_pkts}, Inference Latency: {inf_duration_ms:.1f}ms",
                 scan_id=scan_id)
    except Exception as e:
        log_diag("INFERENCE_ERROR", f"Model inference exception on scan {scan_id}: {e}", scan_id=scan_id)
        with scan_session_lock:
            if current_scan_session.get("scan_id") == scan_id:
                current_scan_session.update({
                    "status": "error",
                    "error": str(e),
                    "message": f"Model inference error: {e}"
                })
                is_monitoring = False


# ==============================================================================
# HTTP Routes
# ==============================================================================
@app.route('/')
def home():
    return render_template('ddos.html')


@app.route('/api/adapter-info', methods=['GET'])
def get_adapter_info():
    """Returns the auto-detected primary network adapter, capture driver, and Windows Service readiness."""
    try:
        adapter, driver_status = auto_detect_primary_interface()
        svc_probe = ipc_client.ping()
        service_online = bool(svc_probe.get("pong", False))
        svc_state = get_service_status()

        driver_status["service_online"] = service_online
        driver_status["service_info"] = svc_probe
        driver_status["service_state"] = svc_state

        if service_online:
            driver_status["can_capture_live"] = True
            driver_status["active_engine"] = "WinDivert (Windows Service)"
            driver_status["remediation_guide"] = "DDoS-Guard Windows Service is active and ready."
        elif svc_state.get("installed") and svc_state.get("status") == "STOPPED":
            driver_status["can_capture_live"] = False
            driver_status["active_engine"] = "None"
            driver_status["remediation_guide"] = "DDoS-Guard Service is installed but stopped. Starting a scan will request permission to start it."
        elif not svc_state.get("installed"):
            driver_status["can_capture_live"] = False
            driver_status["active_engine"] = "None"
            driver_status["remediation_guide"] = "DDoS-Guard Service is not installed. Run 'service_manager.ps1 Install' as Administrator."
        return jsonify({
            "status": "success",
            "adapter": adapter,
            "driver_status": driver_status,
            "service_state": svc_state
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route('/api/service-status', methods=['GET'])
def get_service_status_route():
    """Returns unprivileged Windows Service state and IPC probe status."""
    try:
        st = get_service_status(include_ipc=True)
        return jsonify({"status": "success", "service": st}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/service-start', methods=['POST'])
def start_service_route():
    """Requests scoped UAC elevation to start the DDoSGuardSnifferService."""
    try:
        res = request_service_start(timeout=6.0)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/scan', methods=['GET', 'POST'])
def start_scan():
    """Initiates a discrete live network traffic scan session."""
    global current_scan_session, is_monitoring, live_collector, last_injected_flow
    with scan_session_lock:
        if current_scan_session["status"] == "scanning":
            log_diag("SCAN_REJECT", "Scan request rejected: a scan is already in progress.",
                     scan_id=current_scan_session.get("scan_id"))
            return jsonify({
                "status": "already_scanning",
                "message": "A network scan is already in progress.",
                "scan_id": current_scan_session["scan_id"]
            }), 200

        duration = 3.0
        min_packets = 3
        if request.is_json and request.get_json():
            req_data = request.get_json(silent=True) or {}
            duration = float(req_data.get("duration", 3.0))
            min_packets = int(req_data.get("min_packets", 3))

        log_diag("SCAN_START_REQUEST", f"New scan requested: duration={duration}s, min_packets={min_packets}")

        # Wipe previous scan predictions, packet counts, and errors immediately
        current_scan_session.update({
            "prediction": None,
            "label": None,
            "confidence": 0.0,
            "packets_captured": 0,
            "flow_summary": {},
            "error": None
        })

        # 1. Query actual Windows SCM state before starting
        svc_state = get_service_status(include_ipc=True)
        log_diag("SCM_STATE", f"Status: {svc_state.get('status')} | Installed: {svc_state.get('installed')} | PID: {svc_state.get('pid')} | IPC: {svc_state.get('ipc_online')}")

        if not svc_state.get("installed"):
            not_inst_msg = (
                "DDoS-Guard Windows Sniffer Service is not installed. "
                "Run 'powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 Install' as Administrator."
            )
            log_diag("SERVICE_NOT_INSTALLED", not_inst_msg)
            current_scan_session.update({
                "status": "error",
                "error_type": "SERVICE_NOT_INSTALLED",
                "error": not_inst_msg,
                "message": not_inst_msg,
                "service_state": svc_state
            })
            return jsonify(current_scan_session), 200

        # Check if service is currently in START_PENDING (wait briefly for transition)
        if svc_state.get("status") == "START_PENDING":
            log_diag("SCM_STATE", "Service is currently START_PENDING. Waiting up to 4s for startup to complete...")
            pending_wait_start = time.time()
            while time.time() - pending_wait_start < 4.0:
                time.sleep(0.4)
                svc_state = get_service_status(include_ipc=True)
                if svc_state.get("running") and svc_state.get("ipc_online"):
                    break

        # If service is stopped, request scoped administrator elevation through standard Windows UAC prompt
        if not svc_state.get("ipc_online") and (svc_state.get("status") in ["STOPPED", "STOP_PENDING"] or not svc_state.get("running")):
            log_diag("UAC_ELEVATION", "Service is STOPPED. Requesting scoped Administrator elevation via Windows UAC dialog...")
            uac_res = request_service_start(timeout=10.0)
            status_code = uac_res.get("status")

            if status_code == "uac_cancelled":
                cancel_msg = uac_res.get("message", "Administrator approval was cancelled by the user.")
                log_diag("UAC_CANCELLED", f"User declined UAC prompt (Win32 Error 1223): {cancel_msg}")
                current_scan_session.update({
                    "status": "uac_cancelled",
                    "error_type": "UAC_CANCELLED",
                    "error": cancel_msg,
                    "message": cancel_msg,
                    "prediction": None,
                    "label": None,
                    "service_state": get_service_status(include_ipc=True)
                })
                return jsonify(current_scan_session), 200

            elif status_code == "start_failed":
                fail_msg = uac_res.get("message", "Elevated service startup failed.")
                log_diag("UAC_FAILED", f"Service start failure: {fail_msg}")
                current_scan_session.update({
                    "status": "error",
                    "error_type": "SERVICE_START_FAILED",
                    "error": fail_msg,
                    "message": fail_msg,
                    "prediction": None,
                    "label": None,
                    "log_tail": uac_res.get("log_tail", []),
                    "service_state": get_service_status(include_ipc=True)
                })
                return jsonify(current_scan_session), 200

            log_diag("UAC_APPROVED", "User approved UAC prompt; Windows Service confirmed RUNNING and authenticated IPC online.")
            svc_state = get_service_status(include_ipc=True)
        else:
            log_diag("SCM_STATE", f"Service is already RUNNING (PID: {svc_state.get('pid')}, IPC: {svc_state.get('ipc_online')}). Bypassing UAC elevation prompt.")

        # 2. Strict Authenticated IPC Health Verification before dispatching scan
        auth_ok, auth_detail = ipc_client.verify_authenticated_health()
        if not auth_ok:
            log_diag("IPC_AUTH_ERROR", f"Authenticated IPC health check failed: {auth_detail}")
            current_scan_session.update({
                "status": "error",
                "error_type": "IPC_AUTH_FAILED",
                "error": auth_detail,
                "message": f"Service is running but authenticated IPC health check failed: {auth_detail}",
                "prediction": None,
                "label": None,
                "service_state": svc_state
            })
            return jsonify(current_scan_session), 200

        try:
            adapter_info, driver_info = auto_detect_primary_interface()
        except Exception as e:
            log_diag("ADAPTER_ERROR", f"Adapter discovery error: {e}")
            current_scan_session.update({
                "status": "error",
                "error": str(e),
                "message": "Failed to discover active network adapter."
            })
            return jsonify(current_scan_session), 500

        # Generate unique scan ID with random entropy to prevent any collision or stale state
        scan_id = f"scan_{int(time.time() * 1000)}_{secrets.token_hex(3)}"
        live_collector.reset()
        last_injected_flow = None

        current_scan_session.update({
            "status": "scanning",
            "scan_id": scan_id,
            "started_at": time.time(),
            "duration": duration,
            "min_packets": min_packets,
            "packets_captured": 0,
            "interface": adapter_info,
            "driver_status": driver_info,
            "service_state": svc_state,
            "is_live_capture": bool(svc_state.get("running") and svc_state.get("ipc_online")),
            "prediction": None,
            "label": None,
            "is_attack": False,
            "confidence": 0.0,
            "flow_summary": {},
            "error": None,
            "message": f"Scanning live traffic on [{adapter_info['name']}] ({adapter_info['type']})..."
        })
        is_monitoring = True

        log_diag("SCAN_INITIALIZED", f"Scan {scan_id} successfully initiated on [{adapter_info['name']}]", scan_id=scan_id)

        threading.Thread(
            target=run_scan_worker,
            args=(scan_id, adapter_info, driver_info, duration, min_packets),
            daemon=True
        ).start()

        return jsonify(current_scan_session), 200


@app.route('/api/scan-status', methods=['GET'])
def get_scan_status():
    """Polls the active scan session state with synchronized service state."""
    with scan_session_lock:
        resp = dict(current_scan_session)
    resp["service_state"] = get_service_status(include_ipc=True)
    return jsonify(resp), 200


@app.route('/api/scan-stop', methods=['GET', 'POST'])
def stop_scan():
    """Cancels/aborts the active scan session."""
    global current_scan_session, is_monitoring
    try:
        if ipc_client.is_service_running():
            ipc_client.stop_scan()
    except Exception:
        pass
    with scan_session_lock:
        current_scan_session.update({
            "status": "ready",
            "message": "Scan cancelled by user."
        })
        is_monitoring = False
    return jsonify({"status": "stopped", "message": "Scan cancelled."}), 200



@app.route('/api/start')
def start_monitoring():
    """Backward compatibility alias for /api/scan."""
    return start_scan()


@app.route('/api/stop')
def stop_monitoring():
    """Backward compatibility alias for /api/scan-stop."""
    return stop_scan()


@app.route('/api/receive-packet', methods=['POST'])
def receive_packet():
    """Receives and buffers simulated attack packets from send_traffic.py."""
    global live_collector, last_injected_flow
    try:
        packet = request.get_json(force=True)
        if not packet or not isinstance(packet, dict):
            return jsonify({"error": "Invalid or empty packet"}), 400

        # Check if packet is already an extracted 77-feature flow dictionary (e.g. from send_traffic.py)
        if "Flow Duration" in packet or "Total Fwd Packets" in packet or "Protocol" in packet:
            last_injected_flow = packet
            live_collector.all_packet_sizes.append(int(packet.get("Fwd Packet Length Mean", 120)))
            live_collector.all_packet_times.append(time.time())

        # Also feed to live_collector
        live_collector.add_packet(packet)

        # Atomic write to extracted_features.json
        tmp_path = TRAFFIC_JSON_PATH + '.tmp'
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(packet, f)
            os.replace(tmp_path, TRAFFIC_JSON_PATH)
        except Exception:
            pass

        return jsonify({"status": "received", "buffered_packets": live_collector.packet_count}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/predict')
def predict_traffic():
    """
    Returns prediction result in both legacy and modern formats
    for seamless frontend compatibility.
    """
    with scan_session_lock:
        session = dict(current_scan_session)

    status = session.get("status", "ready")
    if status == "ready":
        return jsonify({
            "status": "waiting",
            "label": "Ready to Scan",
            "confidence": 0,
            "message": "Click 'Scan Network' to begin"
        })
    elif status == "scanning":
        return jsonify({
            "status": "collecting",
            "label": "Scanning Traffic...",
            "confidence": 0,
            "message": session.get("message")
        })
    elif status == "processing":
        return jsonify({
            "status": "processing",
            "label": "Analyzing Features...",
            "confidence": 0,
            "message": "Running flow features through AI model..."
        })
    elif status == "insufficient_traffic":
        return jsonify({
            "status": "insufficient_traffic",
            "label": "Insufficient Traffic",
            "confidence": 0,
            "message": session.get("message"),
            "packets_captured": session.get("packets_captured", 0)
        })
    elif status == "error":
        return jsonify({
            "status": "error",
            "label": "Scan Error",
            "confidence": 0,
            "error_type": session.get("error_type"),
            "message": session.get("message", "An error occurred during scan.")
        })
    elif status == "prediction_available":
        return jsonify({
            "status": "success",
            "prediction": session.get("prediction"),
            "label": session.get("label"),
            "is_attack": session.get("is_attack", False),
            "confidence": session.get("confidence", 0.0),
            "flow_summary": session.get("flow_summary", {}),
            "message": session.get("message"),
            "timestamp": session.get("timestamp")
        })
    else:
        return jsonify({
            "status": "waiting",
            "label": "Ready",
            "confidence": 0
        })


@app.route('/api/predict-direct', methods=['POST'])
def predict_direct():
    """Direct inference endpoint for automated testing."""
    try:
        data = request.get_json(force=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid input JSON"}), 400
        X = prepare_features(data)
        prediction = int(model.predict(X)[0])
        label = CLASS_LABELS.get(prediction, "Unknown")
        is_attack = bool(prediction != BENIGN_IDX and str(label).lower() not in ["normal", "benign", "safe"])
        confidence = 100.0
        if hasattr(model, 'predict_proba'):
            try:
                proba = model.predict_proba(X)[0]
                confidence = round(float(proba[prediction]) * 100, 2)
            except Exception:
                pass
        return jsonify({
            "status": "success",
            "prediction": prediction,
            "label": label,
            "is_attack": is_attack,
            "confidence": confidence
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================================
# Isolated Port & Network Scanner Endpoints
# Architecture: Independent async manager, zero interference with DDoS core.
# ==============================================================================
from port_scanner import port_scanner_manager
from network_detector import get_active_routable_ip


@app.route('/api/port-scan/network-info', methods=['GET'])
def get_port_scan_network_info():
    """Returns local host IP and suggested /24 subnet for network scanning."""
    try:
        local_ip = get_active_routable_ip() or "127.0.0.1"
        suggested_subnet = "192.168.1.0/24"
        if local_ip and not local_ip.startswith("127."):
            parts = local_ip.split(".")
            if len(parts) == 4:
                suggested_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return jsonify({
            "status": "success",
            "local_ip": local_ip,
            "suggested_subnet": suggested_subnet
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/port-scan/start', methods=['POST'])
def start_port_scan():
    """Initiates an isolated port scan session."""
    try:
        data = request.get_json(silent=True) or {}
        scan_type = data.get("scan_type", "localhost")
        target = data.get("target", "127.0.0.1")
        ports_mode = data.get("ports_mode", "top20")
        custom_ports = data.get("custom_ports")
        timeout = float(data.get("timeout", 0.5))
        concurrency = int(data.get("concurrency", 150))

        res = port_scanner_manager.start_scan(
            scan_type=scan_type,
            target=target,
            ports_mode=ports_mode,
            custom_ports=custom_ports,
            timeout=timeout,
            concurrency=concurrency
        )
        return jsonify(res), 200
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/port-scan/status', methods=['GET'])
def get_port_scan_status():
    """Polls real-time progress and accumulated results of the port scan."""
    try:
        status = port_scanner_manager.get_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/port-scan/stop', methods=['POST'])
def stop_port_scan():
    """Cooperatively cancels the active port scan session immediately."""
    try:
        res = port_scanner_manager.stop_scan()
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def check_port_availability(port: int = 5000):
    """Detects and alerts if port is already bound."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex(('127.0.0.1', port)) == 0:
            print(f"\n⚠️ [PORT WARNING] Port {port} is already in use by another process!")
            print(f"   Please stop any existing background api.py process before starting a new instance.\n", flush=True)


if __name__ == '__main__':
    print("=" * 90)
    print("           AI-POWERED REAL-TIME DDoS DETECTION SYSTEM")
    print("                    ULTIMATE FINAL VERSION - 2025")
    print("=" * 90)
    load_model_and_scaler()
    check_port_availability(5000)
    print("Server is running on:")
    print("   → http://127.0.0.1:5000")
    print("\nFeatures:")
    print("   • Automatic Network Adapter Auto-Discovery (Wi-Fi & Ethernet)")
    print("   • Live flow capture & 77-feature extraction engine")
    print("   • Multi-Class Intrusion Detection (15 categories)")
    print("   • Simulated attack streaming with send_traffic.py")
    print("   • 6-State Reactive Lifecycle")
    print("=" * 90)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)