from flask import Flask, jsonify, render_template, request, send_from_directory, redirect
from flask_cors import CORS
import pickle
import json
import os
import sys
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import numpy as np
import pandas as pd
import joblib
import traceback

import datetime
import secrets

from modules.common.network_detector import (
    auto_detect_primary_interface, check_capture_drivers,
    get_windows_network_adapters, get_active_routable_ip,
    auto_detect_interface_with_rationale
)
from modules.monitoring.capture_engine import (
    FlowStatsCollector, RollingFlowStatsCollector, capture_window_scapy,
    capture_window_windivert, OFFICIAL_77_FEATURES, validate_flow_features,
    resolve_scapy_interface, parse_scapy_packet
)
from modules.monitoring.ipc_client import DDoSGuardIPCClient
from modules.monitoring.service import CaptureWorker
from modules.monitoring.service_helper import get_service_status, request_service_start, request_service_restart, is_service_online, is_authenticated_service_online
from modules.auth.db import init_db
from modules.auth.routes import auth_bp
from modules.subscriptions.routes_admin import sub_admin_bp
from modules.subscriptions.routes_user import sub_user_bp
from modules.auth.security import SECRET_KEY
from modules.auth.decorators import login_required, roles_required, admin_required
from modules.subscriptions.decorators import subscription_required

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
app.register_blueprint(auth_bp)
app.register_blueprint(sub_admin_bp)
app.register_blueprint(sub_user_bp)

try:
    init_db()
except Exception as _db_err:
    print(f"⚠️ [DB INIT WARNING] Could not initialize database: {_db_err}")

ipc_client = DDoSGuardIPCClient()
standalone_worker = CaptureWorker()


def log_diag(category: str, message: str, **kwargs):
    """Timestamped diagnostic console logging for real-time traceability."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    extra = " | " + " ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
    print(f"[{ts}] [{category.upper()}] {message}{extra}", flush=True)


def is_authorized_client(client_ip: Optional[str]) -> bool:
    """Restricts API access to loopback and authorized private test subnets (RFC 1918)."""
    if not client_ip:
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(client_ip)
        return ip.is_loopback or ip.is_private
    except Exception:
        return True  # Fallback to allow if format unrecognized in unit test mocks


@app.before_request
def log_request_start():
    request._start_time = time.time()
    if request.path.startswith("/api"):
        if not is_authorized_client(request.remote_addr):
            log_diag("AUTH_REJECT", f"Blocked unauthorized API access attempt from public IP {request.remote_addr}")
            return jsonify({
                "status": "error",
                "message": "Access restricted: Development API is restricted to authorized local and private test networks."
            }), 403
        log_diag("HTTP_REQ", f"--> {request.method} {request.path} from {request.remote_addr}")


@app.after_request
def log_request_end(response):
    if request.path.startswith("/api"):
        duration_ms = (time.time() - getattr(request, "_start_time", time.time())) * 1000
        log_diag("HTTP_RES", f"<-- {request.method} {request.path} {response.status_code} ({duration_ms:.1f}ms)")
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    elif request.args.get("view") in ("admin", "dashboard", "monitoring", "port-scanner", "plans", "admin-users", "admin-plans", "admin-subs", "admin-audit", "admin-profile") or request.path in ("/admin", "/dashboard"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


BASE_DIR = Path(__file__).resolve().parent
NEW_DATASET_DIR = BASE_DIR / "final_output_new_dataset"
V2_DIR = BASE_DIR / "final_output_optimized_v2"
TOP3_DIR = BASE_DIR / "final_output_top3"
OPTIMIZED_DIR = BASE_DIR / "final_output_optimized"
LEGACY_DIR = BASE_DIR / "final output"

FEATURE_EXTRACTION_SCRIPT = str(BASE_DIR / "modules" / "monitoring" / "capture_engine.py")
TRAFFIC_JSON_PATH = str(BASE_DIR / "extracted_features.json")

CLASS_LABELS = {
    0: "Benign", 1: "Bot", 2: "DDoS", 3: "DoS GoldenEye",
    4: "DoS Hulk", 5: "DoS Slowhttptest", 6: "DoS slowloris",
    7: "FTP-Patator", 8: "Heartbleed", 9: "Infiltration",
    10: "PortScan", 11: "SSH-Patator", 12: "Web Attack - Brute Force",
    13: "Web Attack - SQL Injection", 14: "Web Attack - XSS"
}

BENIGN_IDX: Optional[int] = 0
BENIGN_LABEL: Optional[str] = "Benign"
CONFIG_ERROR: Optional[str] = None

detected_attacks_lock = threading.Lock()
detected_attacks_history: List[Dict[str, Any]] = []
MAX_ATTACK_HISTORY = 300

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
    "status": "ready",  # ready, starting, monitoring, scanning, processing, prediction_available, no_traffic, insufficient_traffic, stopped, error
    "scan_id": None,
    "continuous": True,
    "started_at": None,
    "duration": 0.0,
    "min_packets": 3,
    "packets_captured": 0,
    "window_packets": 0,
    "throughput_kbps": 0.0,
    "protocol": "--",
    "interface": None,
    "driver_status": None,
    "prediction": None,
    "label": None,
    "is_attack": False,
    "confidence": 0.0,
    "flow_summary": {},
    "current_flow": {},
    "live_packets": [],
    "detected_attacks_count": 0,
    "error": None,
    "message": "Ready to monitor network traffic."
}

# Live packet collector for current session
live_collector = RollingFlowStatsCollector(window_seconds=2.0)
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

def resolve_benign_configuration(labels_dict=None):
    """
    Dynamically identifies the benign label and index from a label mapping dict.
    Returns (benign_idx, benign_label, config_error).
    """
    target = labels_dict if labels_dict is not None else CLASS_LABELS
    benign_candidates = []
    for k, v in target.items():
        clean_v = str(v).strip().lower()
        if clean_v in ["benign", "normal", "safe", "whitelist", "legitimate"]:
            benign_candidates.append((int(k), str(v).strip()))

    if benign_candidates:
        return benign_candidates[0][0], benign_candidates[0][1], None
    else:
        err = "Model Configuration Error: Unable to locate verified benign/normal baseline traffic label in model label mapping."
        return None, None, err


# Initialize model and scaler on module import
load_model_and_scaler()

# Detect benign index and label dynamically from verified model configuration
BENIGN_IDX, BENIGN_LABEL, CONFIG_ERROR = resolve_benign_configuration(CLASS_LABELS)

num_feats = getattr(model, 'n_features_in_', len(FEATURE_COLUMNS) if FEATURE_COLUMNS is not None else 0)
model_name = type(model).__name__ if model is not None else "None"
scaler_name = type(scaler).__name__ if scaler is not None else "None"
print(f"✅ Model loaded successfully → {num_feats} features, {len(CLASS_LABELS)} classes (Benign index: {BENIGN_IDX}, Label: '{BENIGN_LABEL}')")
print(f"✅ Scaler loaded → {scaler_name}")


def is_benign_label(label: Any) -> bool:
    """Case-insensitive and whitespace-trimmed check against verified model benign label."""
    if BENIGN_LABEL is None or label is None:
        return False
    return str(label).strip().lower() == str(BENIGN_LABEL).strip().lower()


def is_benign_index(pred_idx: Any) -> bool:
    """Checks if numeric prediction index matches identified benign index."""
    if BENIGN_IDX is None or pred_idx is None:
        return False
    try:
        return int(pred_idx) == int(BENIGN_IDX)
    except (ValueError, TypeError):
        return False


def get_supported_attack_labels() -> List[str]:
    """Dynamically returns all verified attack labels from model configuration (excluding benign)."""
    return [str(v).strip() for k, v in CLASS_LABELS.items() if not is_benign_label(v)]


def record_detected_attack(
    label: Optional[str] = None,
    confidence: float = 0.0,
    scan_id: Optional[str] = None,
    prediction: Optional[int] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Any = None,
    flow_id: Optional[str] = None,
    flow_summary: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
    flow_meta: Optional[Dict[str, Any]] = None,
    **kwargs
) -> Optional[Dict[str, Any]]:
    """
    Registers a detected attack event with strict benign exclusion,
    full dynamic multi-class support, and intelligent flow-level deduplication.
    Supports direct arguments or flow_meta dictionary.
    """
    if flow_meta:
        src_ip = src_ip or flow_meta.get("src_ip")
        dst_ip = dst_ip or flow_meta.get("dst_ip")
        src_port = src_port if src_port is not None else flow_meta.get("src_port")
        dst_port = dst_port if dst_port is not None else flow_meta.get("dst_port")
        protocol = protocol or flow_meta.get("protocol")
        flow_id = flow_id or flow_meta.get("flow_id")
        flow_summary = flow_summary or flow_meta.get("flow_summary")
        if not label and "label" in flow_meta:
            label = flow_meta["label"]
        if confidence == 0.0 and "confidence" in flow_meta:
            try:
                confidence = float(flow_meta["confidence"])
            except (ValueError, TypeError):
                confidence = 0.0
        if prediction is None and "prediction" in flow_meta:
            prediction = flow_meta["prediction"]

    if CONFIG_ERROR is not None:
        log_diag("ATTACK_RECORD_BLOCKED", f"Blocked attack recording due to model config error: {CONFIG_ERROR}")
        return None

    if not label or not str(label).strip():
        return None

    clean_label = str(label).strip()

    # Strict Exclusion Gate: Benign label MUST NEVER be added to Detected Attacks
    if is_benign_label(clean_label) or is_benign_index(prediction):
        return None

    if prediction is None:
        for k, v in CLASS_LABELS.items():
            if str(v).strip().lower() == clean_label.lower():
                prediction = int(k)
                break
        if prediction is None:
            prediction = 1

    flow_summary = flow_summary or {}
    now_ts = timestamp or time.strftime("%H:%M:%S")
    now_epoch = time.time()
    proto_str = str(protocol) if protocol is not None else "TCP"

    s_ip = src_ip or flow_summary.get("src_ip") or "0.0.0.0"
    d_ip = dst_ip or flow_summary.get("dst_ip") or "0.0.0.0"
    s_port = int(src_port if src_port is not None else flow_summary.get("src_port", 0))
    d_port = int(dst_port if dst_port is not None else flow_summary.get("dst_port", 0))
    resolved_flow_id = flow_id or f"{s_ip}:{s_port} <-> {d_ip}:{d_port} ({proto_str})"
    current_sid = scan_id or current_scan_session.get("scan_id") or "session_default"

    with detected_attacks_lock:
        # Check for existing detection of this exact flow in the current scan session
        for existing in reversed(detected_attacks_history):
            if existing.get("scan_id") == current_sid and existing.get("flow_id") == resolved_flow_id:
                if str(existing.get("label")).strip().lower() == clean_label.lower():
                    # Same flow, same attack: update latest stats and timestamp in-place without duplicating card
                    existing["last_seen_time"] = now_ts
                    existing["last_seen_epoch"] = now_epoch
                    existing["confidence"] = confidence
                    existing["flow_summary"] = flow_summary
                    existing["occurrence_count"] = existing.get("occurrence_count", 1) + 1
                    return existing
                else:
                    # Same flow, but attack label changed during lifecycle! Documented transition: record new event with reference
                    log_diag("FLOW_LABEL_TRANSITION", f"Flow {resolved_flow_id} changed from '{existing.get('label')}' to '{clean_label}'")
                    break

        det_id = f"det_{current_sid}_{int(now_epoch * 1000)}_{secrets.token_hex(3)}"
        attack_record = {
            "detection_id": det_id,
            "scan_id": current_sid,
            "timestamp": now_ts,
            "created_epoch": now_epoch,
            "last_seen_time": now_ts,
            "last_seen_epoch": now_epoch,
            "label": clean_label,
            "prediction": prediction,
            "confidence": float(confidence),
            "src_ip": s_ip,
            "dst_ip": d_ip,
            "src_port": s_port,
            "dst_port": d_port,
            "protocol": proto_str,
            "flow_id": resolved_flow_id,
            "flow_summary": flow_summary,
            "occurrence_count": 1,
            "is_attack": True
        }

        detected_attacks_history.append(attack_record)
        if len(detected_attacks_history) > MAX_ATTACK_HISTORY:
            detected_attacks_history.pop(0)

        log_diag("ATTACK_PINNED", f"Pinned threat [{det_id}]: {clean_label} ({confidence}%) on {resolved_flow_id}")
        return attack_record


def evaluate_flow_prediction(
    extracted_feats: Dict[str, Any],
    scan_id: str,
    total_pkts: int,
    win_pkts: int,
    throughput: float,
    proto_str: str,
    elapsed: float,
    last_pkt: Any,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    flow_id: Optional[str] = None,
    live_packets: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    global CONFIG_ERROR
    if CONFIG_ERROR is not None:
        return {
            "status": "error",
            "error_type": "ConfigError",
            "error": CONFIG_ERROR,
            "message": f"Configuration Error: {CONFIG_ERROR}"
        }

    X = prepare_features(extracted_feats)
    prediction = int(model.predict(X)[0])
    label = CLASS_LABELS.get(prediction, "Unknown")
    is_attack = not is_benign_label(label)
    confidence = 100.0
    if hasattr(model, 'predict_proba'):
        try:
            proba = model.predict_proba(X)[0]
            confidence = round(float(proba[prediction]) * 100, 2)
        except Exception:
            pass

    s_ip = src_ip or "0.0.0.0"
    d_ip = dst_ip or "0.0.0.0"
    s_port = int(src_port or 0)
    d_port = int(dst_port or 0)
    resolved_flow_id = flow_id or f"{s_ip}:{s_port} <-> {d_ip}:{d_port} ({proto_str})"

    flow_summary = {
        "packets_captured": total_pkts,
        "window_packets": win_pkts,
        "flow_duration_us": float(extracted_feats.get("Flow Duration", 0)),
        "flow_bytes_per_s": round(float(extracted_feats.get("Flow Bytes/s", 0)), 2),
        "flow_packets_per_s": round(float(extracted_feats.get("Flow Packets/s", 0)), 2),
        "protocol": proto_str,
        "avg_packet_size": round(float(extracted_feats.get("Avg Packet Size", 0)), 2),
        "src_ip": s_ip,
        "dst_ip": d_ip,
        "src_port": s_port,
        "dst_port": d_port,
        "flow_id": resolved_flow_id
    }

    if is_attack:
        record_detected_attack(
            scan_id=scan_id,
            label=label,
            prediction=prediction,
            confidence=confidence,
            src_ip=s_ip,
            dst_ip=d_ip,
            src_port=s_port,
            dst_port=d_port,
            protocol=proto_str,
            flow_id=resolved_flow_id,
            flow_summary=flow_summary
        )

    msg = f"⚠️ Security Alert: Malicious {label} Traffic Signature Detected!" if is_attack else "✅ Security Status: Normal / Benign Traffic Flow Verified"

    with detected_attacks_lock:
        attack_count = len(detected_attacks_history)

    return {
        "status": "monitoring",
        "prediction": prediction,
        "label": label,
        "is_attack": is_attack,
        "confidence": confidence,
        "packets_captured": total_pkts,
        "window_packets": win_pkts,
        "throughput_kbps": throughput,
        "protocol": proto_str,
        "flow_summary": flow_summary,
        "current_flow": flow_summary,
        "live_packets": live_packets or [],
        "detected_attacks_count": attack_count,
        "duration": elapsed,
        "last_packet_time": last_pkt,
        "message": msg,
        "timestamp": time.strftime("%H:%M:%S")
    }


def prepare_features(data_dict: Dict[str, Any]) -> np.ndarray:
    """
    Prepares input features with exact column name matching and alias resolution,
    converting to float64 to preserve precision for large flow durations.
    Validates features strictly before transformation to prevent zero-default poisoning.
    """
    global FEATURE_COLUMNS
    expected = getattr(model, 'n_features_in_', len(FEATURE_COLUMNS) if FEATURE_COLUMNS else 77)
    
    # Unwrap nested features dictionary if present
    if "features" in data_dict and isinstance(data_dict["features"], dict):
        data_dict = data_dict["features"]

    # Strict Validation Gate: Reject empty, invalid, or zero-filled vectors
    is_valid, reason = validate_flow_features(data_dict, min_packets=1)
    if not is_valid:
        raise ValueError(f"Feature validation failed: {reason}")

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


def run_scan_worker(scan_id: str, adapter_info: Dict[str, Any], driver_info: Dict[str, Any], duration: float, min_packets: int, continuous: bool = True):
    """Background worker that conducts continuous or windowed packet capture and model prediction."""
    global current_scan_session, is_monitoring, live_collector, last_result
    start_t = time.time()
    can_capture_physical = driver_info.get("can_capture_live", False)
    extracted_feats = None

    log_diag("SCAN_WORKER", f"Worker started for scan {scan_id} (duration={duration}s, min_packets={min_packets}, continuous={continuous})",
             adapter=adapter_info.get("name"), adapter_type=adapter_info.get("type"))

    # Check if dedicated Windows Sniffer Service is actively running via IPC
    service_active = ipc_client.is_service_running()

    if service_active:
        # Delegate live packet capture to Windows Service (running with kernel privileges in monitor mode)
        adapter_name = adapter_info.get("name", "Active Adapter")
        adapter_index = adapter_info.get("index")
        adapter_status = adapter_info.get("status", "Unknown")
        primary_ip = adapter_info.get("primary_ip")
        is_conn = adapter_info.get("is_connected", False)
        log_diag(
            "SCAN_START_DETAILS",
            f"scan_id={scan_id} | adapter={adapter_name} | idx={adapter_index} | "
            f"status={adapter_status} | ip={primary_ip} | connected={is_conn} | duration={duration}s | continuous={continuous}"
        )
        filter_str = "not (tcp port 5000 or tcp port 50505)"
        log_diag("IPC_CMD", f"Sending START_SCAN to Windows Service on [{adapter_name}] (idx={adapter_index}, filter='{filter_str}', duration={duration}s, continuous={continuous}, scan_id={scan_id})")
        svc_start = ipc_client.start_scan(
            duration=duration,
            min_packets=min_packets,
            scan_id=scan_id,
            interface_name=adapter_name,
            interface_index=adapter_index,
            filter_str=filter_str,
            continuous=continuous,
            guid=adapter_info.get("guid") or adapter_info.get("scapy_guid"),
            network_name=adapter_info.get("network_name")
        )
        if svc_start.get("status") == "error":
            err_msg = svc_start.get("message") or "Failed to start capture window on service."
            log_diag("IPC_ERROR", f"Service start_scan error: {err_msg}", scan_id=scan_id)
            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    current_scan_session.update({
                        "status": "error",
                        "label": "Capture Error",
                        "confidence": 0.0,
                        "error": err_msg,
                        "message": f"Service capture failed to start: {err_msg}"
                    })
                    is_monitoring = False
            return

        if continuous:
            last_log_t = 0.0
            while is_monitoring:
                with scan_session_lock:
                    if current_scan_session.get("scan_id") != scan_id or current_scan_session.get("status") in ["stopped", "ready"]:
                        log_diag("MONITORING_STOP", f"Monitoring {scan_id} stopped.", scan_id=scan_id)
                        ipc_client.stop_scan()
                        return

                svc_status = ipc_client.get_scan_status(scan_id)
                if not svc_status or svc_status.get("status") in ["error", "service_unavailable", "timeout"]:
                    err_msg = svc_status.get("message") if svc_status else "Communication with service lost."
                    log_diag("SERVICE_ERROR", f"Monitoring {scan_id} error: {err_msg}", scan_id=scan_id)
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "error",
                                "label": "Capture Error",
                                "confidence": 0.0,
                                "error": err_msg,
                                "message": f"Service capture error: {err_msg}"
                            })
                            is_monitoring = False
                    return

                curr_st = svc_status.get("status")
                total_pkts = svc_status.get("packets_captured", 0)
                win_pkts = svc_status.get("window_packets", 0)
                throughput = svc_status.get("throughput_kbps", 0.0)
                proto_num = svc_status.get("protocol", 6)
                last_pkt = svc_status.get("last_packet_time")
                elapsed = round(time.time() - start_t, 1)

                proto_map = {6: "TCP (6)", 17: "UDP (17)", 1: "ICMP (1)"}
                proto_str = proto_map.get(int(proto_num), f"Proto {proto_num}")

                now = time.time()
                if now - last_log_t >= 1.5:
                    log_diag("MONITORING_PROGRESS", f"Session {scan_id}: {total_pkts} total pkts, {win_pkts} in window ({throughput} KB/s, {elapsed}s)", scan_id=scan_id)
                    last_log_t = now

                if curr_st == "monitoring" and svc_status.get("features"):
                    try:
                        eval_res = evaluate_flow_prediction(
                            extracted_feats=svc_status.get("features"),
                            scan_id=scan_id,
                            total_pkts=total_pkts,
                            win_pkts=win_pkts,
                            throughput=throughput,
                            proto_str=proto_str,
                            elapsed=elapsed,
                            last_pkt=last_pkt,
                            src_ip=svc_status.get("src_ip"),
                            dst_ip=svc_status.get("dst_ip"),
                            src_port=svc_status.get("src_port"),
                            dst_port=svc_status.get("dst_port"),
                            flow_id=svc_status.get("flow_id"),
                            live_packets=svc_status.get("live_packets", [])
                        )
                        with scan_session_lock:
                            if current_scan_session.get("scan_id") == scan_id:
                                current_scan_session.update(eval_res)
                    except Exception as inf_err:
                        log_diag("INFERENCE_ERROR", f"Model inference exception: {inf_err}", scan_id=scan_id)

                elif curr_st == "no_traffic":
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "no_traffic",
                                "label": "No Traffic Detected",
                                "is_attack": False,
                                "prediction": None,
                                "confidence": 0.0,
                                "packets_captured": total_pkts,
                                "window_packets": 0,
                                "throughput_kbps": 0.0,
                                "protocol": "--",
                                "duration": elapsed,
                                "message": f"No traffic detected on [{adapter_name}]. 0 packets intercepted in active window."
                            })

                elif curr_st == "insufficient_traffic":
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "insufficient_traffic",
                                "label": "Insufficient Data",
                                "is_attack": False,
                                "prediction": None,
                                "confidence": 0.0,
                                "packets_captured": total_pkts,
                                "window_packets": win_pkts,
                                "throughput_kbps": throughput,
                                "protocol": proto_str,
                                "duration": elapsed,
                                "message": f"Network quiet: only {win_pkts} packet(s) in active window (min required: {min_packets})."
                            })

                time.sleep(0.25)
            return

        # Discrete window mode continues below for continuous=False:
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
                    if svc_status.get("last_packet_time"):
                        current_scan_session["last_packet_time"] = svc_status["last_packet_time"]

            now = time.time()
            if now - last_log_t >= 0.8:
                log_diag("CAPTURE_PROGRESS", f"Scan {scan_id}: {svc_status.get('packets_captured', 0)} pkts ({now - start_t:.1f}s)", scan_id=scan_id)
                last_log_t = now

            if curr_st == "captured":
                res_iface = svc_status.get("interface_name")
                if not res_iface or (adapter_name and res_iface != adapter_name):
                    err_msg = (
                        f"Capture result rejected: reported interface '{res_iface}' does not match "
                        f"target [{adapter_name}]. Blocked unisolated/outdated traffic leakage."
                    )
                    log_diag("INTERFACE_MISMATCH", err_msg, scan_id=scan_id)
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "error",
                                "label": "Capture Error",
                                "confidence": 0.0,
                                "error_type": "InterfaceMismatch",
                                "error": err_msg,
                                "message": err_msg
                            })
                            is_monitoring = False
                    return

                extracted_feats = svc_status.get("features")
                pkts_seen = svc_status.get("packets_captured", 0)
                last_pkt_ts = svc_status.get("last_packet_time")
                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        current_scan_session["packets_captured"] = pkts_seen
                        current_scan_session["last_packet_time"] = last_pkt_ts
                        current_scan_session["is_live_capture"] = True
                log_diag(
                    "CAPTURE_COMPLETE",
                    f"Scan {scan_id} successfully captured {pkts_seen} packets on [{adapter_name}] (last_pkt_time: {last_pkt_ts}).",
                    scan_id=scan_id
                )
                break
            elif curr_st == "no_traffic":
                dur = svc_status.get("duration", round(time.time() - start_t, 2))
                log_diag("NO_TRAFFIC", f"Scan {scan_id}: No traffic detected on [{adapter_name}] in {dur}s", scan_id=scan_id)
                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        current_scan_session.update({
                            "status": "no_traffic",
                            "label": "No Traffic Detected",
                            "is_attack": False,
                            "prediction": None,
                            "confidence": 0.0,
                            "packets_captured": 0,
                            "min_required": min_packets,
                            "duration": dur,
                            "last_packet_time": None,
                            "message": f"No traffic detected on [{adapter_name}]. 0 packets intercepted."
                        })
                        is_monitoring = False
                return
            elif curr_st == "insufficient_traffic":
                total_seen = svc_status.get("packets_captured", 0)
                dur = svc_status.get("duration", round(time.time() - start_t, 2))
                last_pkt_ts = svc_status.get("last_packet_time")
                log_diag("INSUFFICIENT_TRAFFIC", f"Scan {scan_id}: Only {total_seen} pkts in {dur}s (min: {min_packets})", scan_id=scan_id)
                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        current_scan_session.update({
                            "status": "insufficient_traffic",
                            "label": "Insufficient Data",
                            "is_attack": False,
                            "prediction": None,
                            "confidence": 0.0,
                            "packets_captured": total_seen,
                            "min_required": min_packets,
                            "duration": dur,
                            "last_packet_time": last_pkt_ts,
                            "message": f"Network was quiet: only {total_seen} packet(s) intercepted in {dur}s (min: {min_packets}). Insufficient data."
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
                            "label": "Capture Error",
                            "confidence": 0.0,
                            "error": err_msg,
                            "error_type": svc_status.get("error_type", "ServiceError"),
                            "message": f"Service capture error: {err_msg}"
                        })
                        is_monitoring = False
                return
            time.sleep(0.1)

    elif can_capture_physical:
        # Local process: Run Scapy capture directly on resolved physical adapter
        adapter_name = adapter_info.get("name", "Active Adapter")
        adapter_index = adapter_info.get("index")
        adapter_guid = adapter_info.get("guid") or adapter_info.get("scapy_guid")
        adapter_netname = adapter_info.get("network_name")
        target_iface = resolve_scapy_interface(
            adapter_name,
            adapter_index,
            guid=adapter_guid,
            network_name=adapter_netname
        )
        if not target_iface:
            err_msg = (
                f"Interface resolution failed for adapter='{adapter_name}' (idx={adapter_index}, guid={adapter_guid}). "
                f"No matching Scapy/Npcap network adapter found. Aborting capture to prevent silent default interface substitution."
            )
            log_diag("INTERFACE_NOT_FOUND", err_msg, scan_id=scan_id)
            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    current_scan_session.update({
                        "status": "error",
                        "label": "Capture Error",
                        "confidence": 0.0,
                        "error": err_msg,
                        "error_type": "InterfaceNotFound",
                        "message": err_msg
                    })
                    is_monitoring = False
            return

        iface_display = getattr(target_iface, "name", str(target_iface))
        iface_desc = getattr(target_iface, "description", "")
        log_diag("PHYSICAL_CAPTURE", f"Running direct Scapy capture on [{iface_display}] ({iface_desc}, idx={adapter_index})", scan_id=scan_id)

        filter_str = "not (tcp port 5000 or tcp port 50505)"
        log_diag("STANDALONE_START", f"Starting in-process CaptureWorker on [{iface_display}] (idx={adapter_index}, filter='{filter_str}', duration={duration}s, continuous={continuous}, scan_id={scan_id})")
        start_res = standalone_worker.start_window(
            scan_id=scan_id,
            duration=duration,
            min_packets=min_packets,
            filter_str=filter_str,
            interface_name=adapter_name,
            interface_index=adapter_index,
            continuous=continuous,
            guid=adapter_guid,
            network_name=adapter_netname
        )
        if start_res.get("status") == "error":
            err_msg = start_res.get("message") or "Failed to start direct capture worker."
            err_type = start_res.get("error_type", "CaptureError")
            log_diag("CAPTURE_ERROR", err_msg, scan_id=scan_id)
            with scan_session_lock:
                if current_scan_session.get("scan_id") == scan_id:
                    current_scan_session.update({
                        "status": "error",
                        "label": "Capture Error",
                        "confidence": 0.0,
                        "error": err_msg,
                        "error_type": err_type,
                        "message": err_msg
                    })
                    is_monitoring = False
            return

        if continuous:
            last_log_t = 0.0
            while is_monitoring:
                with scan_session_lock:
                    if current_scan_session.get("scan_id") != scan_id or current_scan_session.get("status") in ["stopped", "ready"]:
                        log_diag("MONITORING_STOP", f"Direct monitoring {scan_id} stopped.", scan_id=scan_id)
                        standalone_worker.stop_window()
                        return

                worker_status = standalone_worker.get_status(scan_id)
                if not worker_status or worker_status.get("status") == "error":
                    err_msg = worker_status.get("message") if worker_status else "Direct capture error."
                    err_type = worker_status.get("error_type", "DriverPermissionError") if worker_status else "DriverPermissionError"
                    log_diag("CAPTURE_ERROR", f"Monitoring {scan_id} error: {err_msg}", scan_id=scan_id)
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "error",
                                "label": "Capture Error",
                                "confidence": 0.0,
                                "error": err_msg,
                                "error_type": err_type,
                                "message": err_msg
                            })
                            is_monitoring = False
                    return

                curr_st = worker_status.get("status")
                total_pkts = worker_status.get("packets_captured", 0)
                win_pkts = worker_status.get("window_packets", 0)
                throughput = worker_status.get("throughput_kbps", 0.0)
                proto_num = worker_status.get("protocol", 6)
                last_pkt = worker_status.get("last_packet_time")
                elapsed = round(time.time() - start_t, 1)

                proto_map = {6: "TCP (6)", 17: "UDP (17)", 1: "ICMP (1)"}
                proto_str = proto_map.get(int(proto_num), f"Proto {proto_num}")

                now = time.time()
                if now - last_log_t >= 1.5:
                    log_diag("MONITORING_PROGRESS", f"Direct session {scan_id}: {total_pkts} total pkts, {win_pkts} in window ({throughput} KB/s, {elapsed}s)", scan_id=scan_id)
                    last_log_t = now

                if curr_st == "monitoring" and worker_status.get("features"):
                    try:
                        eval_res = evaluate_flow_prediction(
                            extracted_feats=worker_status.get("features"),
                            scan_id=scan_id,
                            total_pkts=total_pkts,
                            win_pkts=win_pkts,
                            throughput=throughput,
                            proto_str=proto_str,
                            elapsed=elapsed,
                            last_pkt=last_pkt,
                            src_ip=worker_status.get("src_ip"),
                            dst_ip=worker_status.get("dst_ip"),
                            src_port=worker_status.get("src_port"),
                            dst_port=worker_status.get("dst_port"),
                            flow_id=worker_status.get("flow_id"),
                            live_packets=worker_status.get("live_packets", [])
                        )
                        with scan_session_lock:
                            if current_scan_session.get("scan_id") == scan_id:
                                current_scan_session.update(eval_res)
                    except Exception as inf_err:
                        log_diag("INFERENCE_ERROR", f"Model inference exception: {inf_err}", scan_id=scan_id)

                elif curr_st == "no_traffic":
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "no_traffic",
                                "label": "No Traffic Detected",
                                "is_attack": False,
                                "prediction": None,
                                "confidence": 0.0,
                                "packets_captured": total_pkts,
                                "window_packets": 0,
                                "throughput_kbps": 0.0,
                                "protocol": "--",
                                "duration": elapsed,
                                "message": f"No traffic detected on [{adapter_name}]. 0 packets intercepted in active window."
                            })

                elif curr_st == "insufficient_traffic":
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "insufficient_traffic",
                                "label": "Insufficient Data",
                                "is_attack": False,
                                "prediction": None,
                                "confidence": 0.0,
                                "packets_captured": total_pkts,
                                "window_packets": win_pkts,
                                "throughput_kbps": throughput,
                                "protocol": proto_str,
                                "duration": elapsed,
                                "message": f"Network quiet: only {win_pkts} packet(s) in active window (min required: {min_packets})."
                            })

                time.sleep(0.25)
            standalone_worker.stop_window()
            return
        else:
            poll_timeout = duration + 3.5
            poll_start = time.time()
            last_log_t = 0.0

            while time.time() - poll_start < poll_timeout:
                with scan_session_lock:
                    if current_scan_session.get("scan_id") != scan_id or current_scan_session.get("status") != "scanning":
                        log_diag("SCAN_CANCEL", f"Direct scan {scan_id} was cancelled by user.", scan_id=scan_id)
                        standalone_worker.stop_window()
                        return

                worker_status = standalone_worker.get_status(scan_id)
                curr_st = worker_status.get("status")

                with scan_session_lock:
                    if current_scan_session.get("scan_id") == scan_id:
                        pkts = worker_status.get("packets_captured")
                        if pkts is not None:
                            current_scan_session["packets_captured"] = pkts
                        if worker_status.get("last_packet_time"):
                            current_scan_session["last_packet_time"] = worker_status["last_packet_time"]

                now = time.time()
                if now - last_log_t >= 0.8:
                    log_diag("CAPTURE_PROGRESS", f"Direct scan {scan_id}: {worker_status.get('packets_captured', 0)} pkts ({now - start_t:.1f}s)", scan_id=scan_id)
                    last_log_t = now

                if curr_st == "captured":
                    extracted_feats = worker_status.get("features", {})
                    last_pkt_ts = worker_status.get("last_packet_time")
                    total_seen = worker_status.get("packets_captured", 0)
                    dur = worker_status.get("duration", round(time.time() - start_t, 2))
                    log_diag("CAPTURE_COMPLETE", f"Direct scan {scan_id} successfully captured {total_seen} packets on [{adapter_name}] (last_pkt_time: {last_pkt_ts}).", scan_id=scan_id)

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
                        inf_dur = round((time.time() - inf_start) * 1000, 1)
                        log_diag("INFERENCE_COMPLETE", f"Direct scan {scan_id} prediction -> Label: '{label}' (is_attack={is_attack}), Confidence: {confidence}%, Packets: {total_seen}, Inference Latency: {inf_dur}ms", scan_id=scan_id)

                        flow_summary = {
                            "packets_captured": total_seen,
                            "flow_duration_us": float(extracted_feats.get("Flow Duration", 0)),
                            "flow_bytes_per_s": round(float(extracted_feats.get("Flow Bytes/s", 0)), 2),
                            "flow_packets_per_s": round(float(extracted_feats.get("Flow Packets/s", 0)), 2),
                            "protocol": int(extracted_feats.get("Protocol", 6)),
                            "avg_packet_size": round(float(extracted_feats.get("Avg Packet Size", 0)), 2)
                        }

                        with scan_session_lock:
                            if current_scan_session.get("scan_id") == scan_id:
                                current_scan_session.update({
                                    "status": "prediction_available",
                                    "prediction": prediction,
                                    "label": label,
                                    "is_attack": is_attack,
                                    "confidence": confidence,
                                    "packets_captured": total_seen,
                                    "duration": dur,
                                    "last_packet_time": last_pkt_ts,
                                    "flow_summary": flow_summary,
                                    "message": f"Analysis complete: {label} ({confidence}%) over {total_seen} packets."
                                })
                                is_monitoring = False
                        return
                    except Exception as e:
                        err_msg = str(e)
                        log_diag("INFERENCE_ERROR", f"Model inference exception on direct scan {scan_id}: {err_msg}", scan_id=scan_id)
                        with scan_session_lock:
                            if current_scan_session.get("scan_id") == scan_id:
                                current_scan_session.update({
                                    "status": "error",
                                    "label": "Model Inference Error",
                                    "confidence": 0.0,
                                    "error": err_msg,
                                    "message": f"Inference error: {err_msg}"
                                })
                                is_monitoring = False
                        return

                elif curr_st == "no_traffic":
                    dur = worker_status.get("duration", round(time.time() - start_t, 2))
                    log_diag("NO_TRAFFIC", f"Direct capture quiet: 0 pkts on [{adapter_name}]", scan_id=scan_id)
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "no_traffic",
                                "label": "No Traffic Detected",
                                "is_attack": False,
                                "prediction": None,
                                "confidence": 0.0,
                                "packets_captured": 0,
                                "min_required": min_packets,
                                "duration": dur,
                                "last_packet_time": None,
                                "message": f"No traffic detected on [{adapter_name}]. 0 packets intercepted."
                            })
                            is_monitoring = False
                    return

                elif curr_st == "insufficient_traffic":
                    total_seen = worker_status.get("packets_captured", 0)
                    dur = worker_status.get("duration", round(time.time() - start_t, 2))
                    last_pkt_ts = worker_status.get("last_packet_time")
                    log_diag("INSUFFICIENT_TRAFFIC", f"Direct capture quiet: {total_seen} pkts", scan_id=scan_id)
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "insufficient_traffic",
                                "label": "Insufficient Data",
                                "is_attack": False,
                                "prediction": None,
                                "confidence": 0.0,
                                "packets_captured": total_seen,
                                "min_required": min_packets,
                                "duration": dur,
                                "last_packet_time": last_pkt_ts,
                                "message": f"Network was quiet: only {total_seen} packet(s) intercepted in {dur}s (min: {min_packets}). Insufficient data."
                            })
                            is_monitoring = False
                    return

                elif curr_st in ["error", "service_unavailable", "timeout"]:
                    err_msg = worker_status.get("message") or "Direct capture error."
                    log_diag("CAPTURE_ERROR", f"Scan {scan_id} failed: {err_msg}", scan_id=scan_id)
                    with scan_session_lock:
                        if current_scan_session.get("scan_id") == scan_id:
                            current_scan_session.update({
                                "status": "error",
                                "label": "Capture Error",
                                "confidence": 0.0,
                                "error": err_msg,
                                "error_type": worker_status.get("error_type", "CaptureError"),
                                "message": f"Direct capture error: {err_msg}"
                            })
                            is_monitoring = False
                    return

                time.sleep(0.1)
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
                    "label": "Capture Error",
                    "confidence": 0.0,
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
                    "label": "Capture Error",
                    "confidence": 0.0,
                    "error_type": "CaptureTimeout",
                    "error": err_msg,
                    "message": err_msg
                })
                is_monitoring = False
        return

    # Strict Validation Gate before Model Inference
    is_valid, val_reason = validate_flow_features(extracted_feats, min_packets=min_packets)
    if not is_valid:
        err_msg = f"Flow feature validation failed: {val_reason}"
        log_diag("FEATURE_INVALID", err_msg, scan_id=scan_id)
        with scan_session_lock:
            if current_scan_session.get("scan_id") == scan_id:
                current_scan_session.update({
                    "status": "error",
                    "label": "Capture Error",
                    "confidence": 0.0,
                    "error_type": "InvalidFlowFeatures",
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
    """
    Public entry point for anonymous visitors.
    If client has an active session and no explicit view parameter is requested,
    automatically route them to their designated authenticated landing destination.
    """
    view_param = request.args.get("view")
    public_param = request.args.get("public")
    if not view_param and not public_param:
        from modules.auth.routes import get_current_user_from_request
        from modules.subscriptions.services import determine_user_landing_view
        user, _ = get_current_user_from_request()
        if user and user.is_active:
            _, redirect_url = determine_user_landing_view(user)
            return redirect(redirect_url)

    return render_template('ddos.html')


@app.route('/dashboard')
@login_required
def user_dashboard_page():
    """Direct URL access to the authenticated user dashboard."""
    user = request.current_user
    if user.role == "Admin":
        return redirect("/?view=admin")
    from modules.subscriptions.services import determine_user_landing_view
    _, redirect_url = determine_user_landing_view(user)
    return redirect(redirect_url)


@app.route('/admin')
@admin_required
def admin_dashboard_page():
    """Direct URL access to the administrative management console."""
    return redirect("/?view=admin")


@app.route('/plans')
def plans_page():
    """Direct URL access to the subscription plans catalog."""
    return redirect("/?view=plans")


@app.route('/login')
def login_page():
    """Standalone Login Page for SCOUT Platform."""
    return render_template('login.html')


@app.route('/register')
def register_page():
    """Standalone Create Account / Registration Page for SCOUT Platform."""
    return render_template('register.html')


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static', 'images'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/api/adapter-info', methods=['GET'])
def get_adapter_info():
    """Returns the auto-detected primary network adapter, capture driver, Windows Service readiness, available adapters, and candidate rationale."""
    try:
        available_adapters = get_windows_network_adapters()
        detect_result = auto_detect_interface_with_rationale(adapters=available_adapters)
        adapter = detect_result["adapter"]
        driver_status = detect_result["driver_status"]
        selection_rationale = detect_result.get("selection_rationale", "")
        candidates = detect_result.get("candidates", [])

        svc_probe = ipc_client.ping()
        service_online = bool(svc_probe.get("pong", False))
        svc_state = get_service_status()

        driver_status["service_online"] = service_online
        driver_status["service_info"] = svc_probe
        driver_status["service_state"] = svc_state

        if service_online:
            driver_status["can_capture_live"] = True
            driver_status["active_engine"] = "Npcap + Scapy (Windows Service)"
            driver_status["remediation_guide"] = "DDoS-Guard Windows Service is active and ready."
        elif svc_state.get("installed") and svc_state.get("status") == "STOPPED":
            if driver_status.get("scapy_ready") or driver_status.get("npcap_installed"):
                driver_status["can_capture_live"] = True
                driver_status["active_engine"] = "Npcap + Scapy (Standalone / Direct)"
                driver_status["remediation_guide"] = "DDoS-Guard Service is stopped. Direct standalone packet capture is ready, or start service for elevated capture."
            else:
                driver_status["can_capture_live"] = False
                driver_status["active_engine"] = "None"
                driver_status["remediation_guide"] = "DDoS-Guard Service is installed but stopped. Starting a scan will request permission to start it."
        elif not svc_state.get("installed"):
            if driver_status.get("scapy_ready") or driver_status.get("npcap_installed"):
                driver_status["can_capture_live"] = True
                driver_status["active_engine"] = "Npcap + Scapy (Standalone / Direct)"
                driver_status["remediation_guide"] = "Windows Service not installed. Ready for direct standalone packet capture via Npcap."
            else:
                driver_status["can_capture_live"] = False
                driver_status["active_engine"] = "None"
                driver_status["remediation_guide"] = "DDoS-Guard Service is not installed. Run 'service_manager.ps1 Install' as Administrator."

        return jsonify({
            "status": "success",
            "adapter": adapter,
            "auto_selected": adapter,
            "selection_rationale": selection_rationale,
            "candidates": candidates,
            "driver_status": driver_status,
            "service_state": svc_state,
            "available_adapters": available_adapters
        }), 200
    except Exception as e:
        log_diag("ADAPTER_INFO_WARN", f"Auto-detection rationale raised: {e}")
        available = []
        try:
            available = get_windows_network_adapters()
        except Exception:
            pass
        driver_status = check_capture_drivers()
        return jsonify({
            "status": "warning" if available else "error",
            "message": str(e),
            "selection_rationale": str(e),
            "adapter": None,
            "auto_selected": None,
            "candidates": [],
            "driver_status": driver_status,
            "service_state": get_service_status(),
            "available_adapters": available
        }), 200 if available else 500


@app.route('/api/health', methods=['GET'])
def get_health_status():
    """Lightweight connectivity health check endpoint for remote test clients and local monitoring."""
    try:
        adapter, driver_status = auto_detect_primary_interface()
        return jsonify({
            "status": "ok",
            "service": "SocNet DDoS-Guard",
            "monitoring": is_monitoring,
            "primary_adapter": {
                "name": adapter.get("name"),
                "type": adapter.get("type"),
                "ip": adapter.get("primary_ip"),
                "status": adapter.get("status"),
                "index": adapter.get("index"),
                "network_name": adapter.get("network_name")
            },
            "can_capture_live": driver_status.get("can_capture_live", False),
            "traffic_test_port": getattr(app, "traffic_test_port", 8080),
            "timestamp": time.time()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "service": "SocNet DDoS-Guard",
            "error": str(e),
            "monitoring": is_monitoring,
            "traffic_test_port": getattr(app, "traffic_test_port", 8080),
            "timestamp": time.time()
        }), 200


@app.route('/api/service-status', methods=['GET'])
def get_service_status_route():
    """Returns unprivileged Windows Service state and IPC probe status."""
    try:
        st = get_service_status(include_ipc=True)
        return jsonify({"status": "success", "service": st}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/service-start', methods=['POST'])
@admin_required
def start_service_route():
    """Requests scoped UAC elevation to start the DDoSGuardSnifferService."""
    try:
        res = request_service_start(timeout=6.0)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/scan', methods=['GET', 'POST'])
@subscription_required(feature="can_live_monitoring")
def start_scan():
    """Initiates a continuous or discrete live network traffic monitoring session."""
    global current_scan_session, is_monitoring, live_collector, last_injected_flow
    with scan_session_lock:
        duration = 3.0
        min_packets = 3
        continuous = True
        req_adapter_name = None
        req_adapter_idx = None
        req_adapter_guid = None
        req_adapter_netname = None
        force_restart = False

        if request.is_json and request.get_json():
            req_data = request.get_json(silent=True) or {}
            duration = float(req_data.get("duration", 3.0))
            min_packets = int(req_data.get("min_packets", 3))
            if "continuous" in req_data:
                continuous = bool(req_data["continuous"])
            req_adapter_name = req_data.get("interface_name") or req_data.get("adapter") or req_data.get("interface")
            req_adapter_idx = req_data.get("interface_index")
            req_adapter_guid = req_data.get("guid") or req_data.get("scapy_guid")
            req_adapter_netname = req_data.get("network_name")
            force_restart = bool(req_data.get("force_restart", False) or req_data.get("restart", False))
        elif request.args:
            if "continuous" in request.args:
                continuous = request.args.get("continuous", "true").lower() in ("true", "1")
            if "duration" in request.args:
                duration = float(request.args.get("duration", 3.0))
            if "min_packets" in request.args:
                min_packets = int(request.args.get("min_packets", 3))
            req_adapter_name = request.args.get("interface_name") or request.args.get("adapter") or request.args.get("interface")
            req_adapter_idx = request.args.get("interface_index")
            req_adapter_guid = request.args.get("guid") or request.args.get("scapy_guid")
            req_adapter_netname = request.args.get("network_name")
            force_restart = request.args.get("force_restart", "false").lower() in ("true", "1") or request.args.get("restart", "false").lower() in ("true", "1")

        ACTIVE_CAPTURE_STATES = ["scanning", "starting", "monitoring", "prediction_available", "no_traffic", "insufficient_traffic"]
        if is_monitoring or current_scan_session.get("status") in ACTIVE_CAPTURE_STATES:
            if force_restart:
                log_diag("SCAN_RESTART", "Force restart requested: stopping active capture before starting new session on requested adapter.",
                         scan_id=current_scan_session.get("scan_id"))
                try:
                    if ipc_client.is_service_running():
                        ipc_client.stop_scan()
                except Exception:
                    pass
                try:
                    standalone_worker.stop_window()
                except Exception:
                    pass
                is_monitoring = False
                current_scan_session["status"] = "stopped"
            else:
                log_diag("SCAN_RECONNECT", "Scan request reconnected: a monitoring session is already in progress.",
                         scan_id=current_scan_session.get("scan_id"))
                resp = dict(current_scan_session)
                resp["status"] = "already_scanning"
                resp["is_active"] = True
                resp["message"] = "Reconnected to existing active network monitoring session."
                return jsonify(resp), 200

        log_diag("SCAN_START_REQUEST", f"New scan/monitoring requested: adapter={req_adapter_name} (idx={req_adapter_idx}, guid={req_adapter_guid}, net={req_adapter_netname}), continuous={continuous}, duration={duration}s, min_packets={min_packets}, force_restart={force_restart}")

        # Wipe previous scan predictions, packet counts, and errors immediately
        current_scan_session.update({
            "prediction": None,
            "label": None,
            "confidence": 0.0,
            "packets_captured": 0,
            "window_packets": 0,
            "throughput_kbps": 0.0,
            "protocol": "--",
            "flow_summary": {},
            "current_flow": {},
            "live_packets": [],
            "error": None
        })

        # Resolve requested network adapter or auto-detect primary
        try:
            is_auto_mode = (not req_adapter_name or str(req_adapter_name).strip().lower() in ["auto", "default", "none"]) and (req_adapter_idx is None) and (not req_adapter_guid) and (not req_adapter_netname)

            if not is_auto_mode:
                adapters = get_windows_network_adapters()
                matched_ad = None

                # 1. Match by exact GUID if provided
                if req_adapter_guid:
                    for ad in adapters:
                        if str(ad.get("guid", "")).strip().lower() == str(req_adapter_guid).strip().lower():
                            matched_ad = dict(ad)
                            break

                # 2. Match by exact interface index if provided
                if not matched_ad and req_adapter_idx is not None:
                    for ad in adapters:
                        if int(ad.get("index", -1)) == int(req_adapter_idx):
                            matched_ad = dict(ad)
                            break

                # 3. Match by exact name or network_name (case-insensitive)
                if not matched_ad and req_adapter_name:
                    clean_req = str(req_adapter_name).strip().lower()
                    for ad in adapters:
                        if str(ad.get("name", "")).strip().lower() == clean_req:
                            matched_ad = dict(ad)
                            break
                        if str(ad.get("network_name", "")).strip().lower() == clean_req:
                            matched_ad = dict(ad)
                            break

                # 3b. Match by explicit network_name if provided
                if not matched_ad and req_adapter_netname:
                    clean_net = str(req_adapter_netname).strip().lower()
                    for ad in adapters:
                        if str(ad.get("network_name", "")).strip().lower() == clean_net:
                            matched_ad = dict(ad)
                            break

                # 4. Match by exact description (strictly equal, no loose substring)
                if not matched_ad and req_adapter_name:
                    clean_req = str(req_adapter_name).strip().lower()
                    for ad in adapters:
                        if str(ad.get("description", "")).strip().lower() == clean_req:
                            matched_ad = dict(ad)
                            break

                if matched_ad:
                    if matched_ad.get("status") in ["Disconnected", "Disabled"]:
                        err_msg = (
                            f"Selected network adapter '{matched_ad.get('name')}' is {matched_ad.get('status')}. "
                            f"Live packet capture cannot start on a disconnected or disabled interface. "
                            f"Please connect the network cable, enable the adapter, or select an operational interface."
                        )
                        log_diag("ADAPTER_OFFLINE", err_msg)
                        current_scan_session.update({
                            "status": "error",
                            "label": "Capture Error",
                            "confidence": 0.0,
                            "error_type": "ADAPTER_OFFLINE",
                            "error": err_msg,
                            "message": err_msg
                        })
                        return jsonify(current_scan_session), 200

                    adapter_info = matched_ad
                    valid_ips = [ip for ip in adapter_info.get("ips", []) if ip and not ip.startswith("169.254.") and not ip.startswith("127.")]
                    adapter_info["primary_ip"] = valid_ips[0] if valid_ips else (adapter_info.get("ips", [None])[0] if adapter_info.get("ips") else None)
                    adapter_info["is_connected"] = bool(adapter_info.get("primary_ip") and adapter_info.get("status") == "Up")
                    driver_info = check_capture_drivers()
                    adapter_info["driver_status"] = driver_info
                else:
                    scapy_dev = resolve_scapy_interface(req_adapter_name, req_adapter_idx, guid=req_adapter_guid, network_name=req_adapter_netname)
                    if scapy_dev:
                        scapy_name = getattr(scapy_dev, "name", req_adapter_name)
                        scapy_desc = getattr(scapy_dev, "description", "")
                        scapy_idx = getattr(scapy_dev, "index", req_adapter_idx)
                        scapy_ip = getattr(scapy_dev, "ip", None)
                        scapy_netname = getattr(scapy_dev, "network_name", None)
                        scapy_guid = getattr(scapy_dev, "guid", req_adapter_guid)
                        is_wifi = any(k in str(scapy_name).lower() or k in str(scapy_desc).lower() for k in ["wi-fi", "wireless", "802.11"])
                        adapter_info = {
                            "name": scapy_name,
                            "description": scapy_desc,
                            "index": scapy_idx,
                            "status": "Up",
                            "type": "Wi-Fi" if is_wifi else "Ethernet",
                            "ips": [scapy_ip] if scapy_ip else [],
                            "primary_ip": scapy_ip,
                            "is_connected": bool(scapy_ip),
                            "is_virtual": False,
                            "network_name": scapy_netname,
                            "guid": scapy_guid
                        }
                        driver_info = check_capture_drivers()
                        adapter_info["driver_status"] = driver_info
                    else:
                        err_msg = (
                            f"Requested network adapter '{req_adapter_name}' (idx={req_adapter_idx}, guid={req_adapter_guid}) "
                            f"could not be resolved. Aborting capture to prevent silent interface substitution."
                        )
                        log_diag("ADAPTER_NOT_FOUND", err_msg)
                        current_scan_session.update({
                            "status": "error",
                            "label": "Capture Error",
                            "confidence": 0.0,
                            "error_type": "InterfaceNotFound",
                            "error": err_msg,
                            "message": err_msg
                        })
                        return jsonify(current_scan_session), 200
            else:
                adapter_info, driver_info = auto_detect_primary_interface()

            # Ensure Scapy Npcap device identifier is linked
            if not adapter_info.get("network_name"):
                scapy_dev = resolve_scapy_interface(
                    adapter_info.get("name"),
                    adapter_info.get("index"),
                    guid=adapter_info.get("guid") or adapter_info.get("scapy_guid")
                )
                if scapy_dev:
                    adapter_info["network_name"] = getattr(scapy_dev, "network_name", None)
                    adapter_info["scapy_guid"] = getattr(scapy_dev, "guid", None)

            adapter_name = adapter_info.get("name", "Unknown")
            adapter_idx = adapter_info.get("index")
            adapter_status = adapter_info.get("status", "Unknown")
            primary_ip = adapter_info.get("primary_ip")
            is_conn = adapter_info.get("is_connected", False)

            if not is_conn:
                log_diag(
                    "ADAPTER_UNCONNECTED",
                    f"Adapter [{adapter_name}] (idx={adapter_idx}) is {adapter_status} but has no routable IPv4 connection. Zero physical traffic expected."
                )
        except Exception as e:
            err_msg = str(e)
            log_diag("ADAPTER_ERROR", f"Adapter discovery error: {err_msg}")
            current_scan_session.update({
                "status": "error",
                "label": "Capture Error",
                "confidence": 0.0,
                "error_type": "ADAPTER_OFFLINE",
                "error": err_msg,
                "message": f"Network adapter error: {err_msg}"
            })
            return jsonify(current_scan_session), 200

        try:
            # 1. Query actual Windows SCM state before starting
            svc_state = get_service_status(include_ipc=True)
            log_diag("SCM_STATE", f"Status: {svc_state.get('status')} | Installed: {svc_state.get('installed')} | PID: {svc_state.get('pid')} | IPC: {svc_state.get('ipc_online')}")

            if not svc_state.get("installed"):
                if not driver_info.get("can_capture_live"):
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
                else:
                    log_diag("STANDALONE_CAPTURE", f"Windows Service not installed. Running direct Scapy capture on [{adapter_name}] (idx={adapter_idx}).")
            else:
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

                # Check if the running service is outdated (e.g. started before isolation patches)
                v_info = ipc_client.get_service_version_info()
                if v_info.get("online") and not v_info.get("is_updated"):
                    log_diag(
                        "SERVICE_OUTDATED",
                        f"Sniffer service (PID: {v_info.get('pid')}) is running outdated build '{v_info.get('version')}'. "
                        f"Requesting elevated service restart to load network isolation..."
                    )
                    restart_res = request_service_restart(timeout=10.0)
                    if restart_res.get("status") == "started":
                        log_diag("SERVICE_RESTARTED", "Windows Service successfully restarted and updated build verified.")
                        svc_state = get_service_status(include_ipc=True)
                    elif restart_res.get("status") == "uac_cancelled":
                        cancel_msg = "Administrator approval was cancelled. An elevated restart of the Windows Service is required to load network isolation fixes."
                        log_diag("UAC_CANCELLED", cancel_msg)
                        current_scan_session.update({
                            "status": "uac_cancelled",
                            "label": "Capture Error",
                            "confidence": 0.0,
                            "error_type": "UAC_CANCELLED",
                            "error": cancel_msg,
                            "message": cancel_msg,
                            "prediction": None,
                            "label": None,
                            "service_state": get_service_status(include_ipc=True)
                        })
                        return jsonify(current_scan_session), 200
                    else:
                        outdated_msg = (
                            f"DDoS-Guard Windows Service is running an outdated in-memory build (PID: {v_info.get('pid')}, version: {v_info.get('version')}). "
                            f"An elevated service restart is required to load loopback and network isolation fixes. "
                            f"Please run 'powershell -ExecutionPolicy Bypass -File .\\service_manager.ps1 Restart' as Administrator."
                        )
                        log_diag("SERVICE_OUTDATED_ERROR", outdated_msg)
                        current_scan_session.update({
                            "status": "error",
                            "label": "Capture Error",
                            "confidence": 0.0,
                            "error_type": "OUTDATED_SERVICE",
                            "error": outdated_msg,
                            "message": outdated_msg,
                            "prediction": None,
                            "label": None,
                            "service_state": svc_state
                        })
                        return jsonify(current_scan_session), 200

                # 2. Strict Authenticated IPC Health Verification before dispatching scan
                auth_ok, auth_detail = ipc_client.verify_authenticated_health(require_updated_version=True)
                if not auth_ok:
                    log_diag("IPC_AUTH_ERROR", f"Authenticated IPC health check failed: {auth_detail}")
                    current_scan_session.update({
                        "status": "error",
                        "label": "Capture Error",
                        "confidence": 0.0,
                        "error_type": "IPC_AUTH_FAILED",
                        "error": auth_detail,
                        "message": f"Service is running but authenticated IPC health check failed: {auth_detail}",
                        "prediction": None,
                        "label": None,
                        "service_state": svc_state
                    })
                    return jsonify(current_scan_session), 200

            # Generate unique scan ID with random entropy to prevent any collision or stale state
            scan_id = f"scan_{int(time.time() * 1000)}_{secrets.token_hex(3)}"
            live_collector.reset()
            last_injected_flow = None

            current_scan_session.update({
                "status": "scanning",
                "scan_id": scan_id,
                "continuous": continuous,
                "started_at": time.time(),
                "duration": duration,
                "min_packets": min_packets,
                "packets_captured": 0,
                "window_packets": 0,
                "throughput_kbps": 0.0,
                "protocol": "--",
                "interface": adapter_info,
                "driver_status": driver_info,
                "service_state": svc_state,
                "is_live_capture": bool(svc_state.get("running") and svc_state.get("ipc_online")) or bool(driver_info.get("can_capture_live")),
                "prediction": None,
                "label": None,
                "is_attack": False,
                "confidence": 0.0,
                "flow_summary": {},
                "error": None,
                "message": f"Starting live monitoring on [{adapter_info['name']}] ({adapter_info['type']})..." if continuous else f"Scanning live traffic on [{adapter_info['name']}] ({adapter_info['type']})..."
            })
            is_monitoring = True

            log_diag("SCAN_INITIALIZED", f"Scan {scan_id} successfully initiated on [{adapter_info['name']}] (continuous={continuous})", scan_id=scan_id)

            threading.Thread(
                target=run_scan_worker,
                args=(scan_id, adapter_info, driver_info, duration, min_packets, continuous),
                daemon=True
            ).start()

            return jsonify(current_scan_session), 200
        except Exception as e:
            err_msg = str(e)
            log_diag("SCAN_START_EXCEPTION", f"Scan startup exception: {err_msg}")
            is_monitoring = False
            current_scan_session.update({
                "status": "error",
                "label": "Capture Error",
                "confidence": 0.0,
                "error_type": "INITIALIZATION_FAILED",
                "error": err_msg,
                "message": f"Scan initialization failed: {err_msg}"
            })
            return jsonify(current_scan_session), 200


@app.route('/api/scan-status', methods=['GET'])
def get_scan_status():
    """Polls the active scan session state with synchronized service state and detected attacks."""
    ACTIVE_CAPTURE_STATES = {"scanning", "starting", "monitoring", "prediction_available", "no_traffic", "insufficient_traffic"}
    with scan_session_lock:
        resp = dict(current_scan_session)
        resp["is_active"] = bool(is_monitoring and resp.get("status") in ACTIVE_CAPTURE_STATES)
        resp["is_capturing"] = resp["is_active"]
    with detected_attacks_lock:
        resp["detected_attacks"] = list(detected_attacks_history)
        resp["detected_attacks_count"] = len(detected_attacks_history)
    resp["benign_label"] = BENIGN_LABEL
    resp["config_error"] = CONFIG_ERROR
    resp["supported_attack_labels"] = get_supported_attack_labels()
    resp["service_state"] = get_service_status(include_ipc=True)
    return jsonify(resp), 200


def get_detected_attacks_history() -> List[Dict[str, Any]]:
    """Returns a copy of all recorded detected attacks."""
    with detected_attacks_lock:
        return [dict(x) for x in detected_attacks_history]


def clear_detected_attacks_history():
    """Clears detected attacks history cleanly without affecting capture or model."""
    with detected_attacks_lock:
        detected_attacks_history.clear()
    with scan_session_lock:
        current_scan_session["detected_attacks_count"] = 0


@app.route('/api/detected-attacks', methods=['GET'])
def get_detected_attacks():
    """Returns all pinned attack detection events."""
    attacks = get_detected_attacks_history()
    return jsonify({
        "status": "success",
        "detected_attacks": attacks,
        "count": len(attacks),
        "benign_label": BENIGN_LABEL,
        "config_error": CONFIG_ERROR
    }), 200


@app.route('/api/detected-attacks/clear', methods=['POST'])
@admin_required
def clear_detected_attacks():
    """
    Clears the displayed detected attacks history cleanly.
    Does NOT stop capture, does NOT modify model or scaler, and does not alter scan session.
    """
    clear_detected_attacks_history()
    log_diag("ATTACK_HISTORY_CLEARED", "Detected attacks history cleared by user request.")
    return jsonify({
        "status": "success",
        "message": "Detected attacks history cleared successfully.",
        "count": 0
    }), 200


@app.route('/api/scan-rescan', methods=['GET', 'POST'])
@subscription_required(feature="can_live_monitoring")
def rescan_active_session():
    """
    Performs a non-intrusive health inspection of the active monitoring session.
    Verifies:
      1. Currently selected adapter presence, connection state, and current IPv4.
      2. Capture worker process/thread health (service or standalone).
      3. Real packet receipt and recent packet arrival without restarting capture.
    Does NOT stop or restart the capture worker.
    Does NOT create duplicate workers or duplicate packet handlers.
    Does NOT silently switch adapters.
    """
    with scan_session_lock:
        session = dict(current_scan_session)
        active = is_monitoring and session.get("status") in [
            "scanning", "monitoring", "no_traffic", "insufficient_traffic", "prediction_available"
        ]
        scan_id = session.get("scan_id")
        adapter_info = session.get("interface") or {}
        initial_pkts = session.get("packets_captured", 0)
        initial_win = session.get("window_packets", 0)
        last_pkt_time = session.get("last_packet_time")

    if not active or not scan_id:
        return jsonify({
            "status": "inactive",
            "health_state": "inactive",
            "scan_id": None,
            "message": "No active monitoring session found. Click 'Start Monitoring' to begin.",
            "adapter": None,
            "worker": None,
            "packets_observed": False,
            "recovery_action": None
        }), 200

    target_name = adapter_info.get("name") or "Active Adapter"
    target_guid = adapter_info.get("guid") or adapter_info.get("scapy_guid")
    target_idx = adapter_info.get("index")

    # 1. Real-time OS Adapter Verification
    adapters = get_windows_network_adapters()
    matched_adapter = None
    if target_guid:
        for ad in adapters:
            if str(ad.get("guid", "")).strip().lower() == str(target_guid).strip().lower():
                matched_adapter = ad
                break
    if not matched_adapter and target_idx is not None:
        for ad in adapters:
            if int(ad.get("index", -1)) == int(target_idx):
                matched_adapter = ad
                break
    if not matched_adapter and target_name:
        clean_name = str(target_name).strip().lower()
        for ad in adapters:
            if str(ad.get("name", "")).strip().lower() == clean_name:
                matched_adapter = ad
                break

    if not matched_adapter:
        adapter_available = False
        adapter_status = "Disconnected / Removed"
        current_ip = None
        is_connected = False
    else:
        adapter_status = matched_adapter.get("status", "Unknown")
        current_ip = matched_adapter.get("primary_ip")
        is_connected = matched_adapter.get("is_connected", False)
        is_disabled = (adapter_status in ["Disabled", "Disconnected"]) or not is_connected
        adapter_available = not is_disabled

    # 2. Capture Worker Health Check
    service_running = ipc_client.is_service_running()
    worker_alive = False
    worker_mode = "standalone"
    worker_err = None
    live_pkts = initial_pkts
    live_win = initial_win

    if service_running:
        worker_mode = "service"
        try:
            svc_st = ipc_client.get_scan_status(scan_id)
            if svc_st and svc_st.get("status") not in ["error", "service_unavailable"]:
                worker_alive = True
                live_pkts = svc_st.get("packets_captured", initial_pkts)
                live_win = svc_st.get("window_packets", initial_win)
                if svc_st.get("last_packet_time"):
                    last_pkt_time = svc_st["last_packet_time"]
            else:
                worker_err = svc_st.get("message") if svc_st else "Service unreachable"
        except Exception as e:
            worker_err = str(e)
    else:
        worker_mode = "standalone"
        worker_alive = standalone_worker.is_running()
        try:
            w_st = standalone_worker.get_status(scan_id)
            if w_st and w_st.get("status") not in ["error"]:
                worker_alive = True
                live_pkts = w_st.get("packets_captured", initial_pkts)
                live_win = w_st.get("window_packets", initial_win)
                if w_st.get("last_packet_time"):
                    last_pkt_time = w_st["last_packet_time"]
            else:
                worker_err = w_st.get("message") if w_st else "Capture worker stopped"
        except Exception as e:
            worker_err = str(e)

    # 3. Sample Packet Receipt over a brief observation interval (350ms)
    time.sleep(0.35)
    with scan_session_lock:
        sampled_pkts = current_scan_session.get("packets_captured", live_pkts)
        sampled_win = current_scan_session.get("window_packets", live_win)
        sampled_last_time = current_scan_session.get("last_packet_time") or last_pkt_time

    packets_delta = max(0, sampled_pkts - initial_pkts)
    now = time.time()
    has_recent_packet = (sampled_last_time is not None and (now - sampled_last_time < 5.0)) or (packets_delta > 0)
    packets_arrived = bool(sampled_pkts > 0 and (has_recent_packet or sampled_win > 0 or packets_delta > 0))

    # 4. Map to 4 Distinct Verification States
    if not adapter_available:
        health_state = "adapter_unavailable"
        message = (
            f"Selected interface '{target_name}' is unavailable ({adapter_status}). "
            f"Packet capture cannot intercept packets on an offline or disconnected adapter."
        )
        recovery_action = "reconnect_adapter"
    elif not worker_alive or worker_err:
        health_state = "worker_failed"
        message = (
            f"Packet capture worker failure: {worker_err or 'Capture worker is not actively running.'}"
        )
        recovery_action = "restart_monitoring"
    elif packets_arrived:
        health_state = "healthy_active"
        delta_str = f" (+{packets_delta} in check)" if packets_delta > 0 else ""
        message = (
            f"Capture is running on [{target_name}] ({current_ip or 'No IPv4'}) and "
            f"packets are actively being received ({sampled_pkts} total captured{delta_str})."
        )
        recovery_action = None
    else:
        health_state = "healthy_quiet"
        message = (
            f"Capture is running on [{target_name}] ({current_ip or 'No IPv4'}), but "
            f"zero packets were observed in the check window ({sampled_pkts} total captured). "
            f"Generate traffic to test detection."
        )
        recovery_action = None

    return jsonify({
        "status": "success",
        "health_state": health_state,
        "scan_id": scan_id,
        "adapter": {
            "name": target_name,
            "type": adapter_info.get("type", "Network"),
            "primary_ip": current_ip or "None",
            "status": adapter_status,
            "is_connected": is_connected,
            "available": adapter_available
        },
        "worker": {
            "alive": worker_alive,
            "mode": worker_mode,
            "packets_captured": sampled_pkts,
            "window_packets": sampled_win,
            "packets_delta": packets_delta,
            "last_packet_time": sampled_last_time,
            "error": worker_err
        },
        "packets_observed": packets_arrived,
        "message": message,
        "recovery_action": recovery_action,
        "timestamp": time.strftime("%H:%M:%S")
    }), 200


@app.route('/api/scan-stop', methods=['GET', 'POST'])
@login_required
def stop_scan():
    """Stops the active monitoring session cleanly and releases resources."""
    global current_scan_session, is_monitoring
    try:
        if ipc_client.is_service_running():
            ipc_client.stop_scan()
    except Exception:
        pass
    try:
        standalone_worker.stop_window()
    except Exception:
        pass
    with scan_session_lock:
        total_seen = current_scan_session.get("packets_captured", 0)
        current_scan_session.update({
            "status": "stopped",
            "label": "Stopped",
            "confidence": 0.0,
            "is_attack": False,
            "prediction": None,
            "message": f"Monitoring stopped by user ({total_seen} total packets captured).",
            "window_packets": 0,
            "throughput_kbps": 0.0
        })
        is_monitoring = False
    return jsonify({"status": "stopped", "message": "Monitoring stopped."}), 200



@app.route('/api/start')
@subscription_required(feature="can_live_monitoring")
def start_monitoring():
    """Backward compatibility alias for /api/scan."""
    return start_scan()


@app.route('/api/stop')
@login_required
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
    elif status == "no_traffic":
        return jsonify({
            "status": "no_traffic",
            "label": "No Traffic Detected",
            "confidence": 0,
            "message": session.get("message", "No traffic detected on network adapter."),
            "packets_captured": 0
        })
    elif status == "insufficient_traffic":
        return jsonify({
            "status": "insufficient_traffic",
            "label": "Insufficient Data",
            "confidence": 0,
            "message": session.get("message"),
            "packets_captured": session.get("packets_captured", 0)
        })
    elif status == "error":
        return jsonify({
            "status": "error",
            "label": "Capture Error",
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
# Dedicated Dataset Replay Inference Endpoints
# Architecture: Isolated Layer-7 feature evaluation, zero interference with live
# Scapy/Npcap packet capture, zero side effects on current_scan_session.
# ==============================================================================
replay_stats_lock = threading.Lock()
replay_session_stats = {
    "total_replayed": 0,
    "last_prediction": None,
    "last_predicted_label": None,
    "last_ground_truth": None,
    "last_match": None,
    "last_confidence": 0.0,
    "last_latency_ms": 0.0,
    "last_timestamp": None,
    "matches": 0,
    "mismatches": 0
}


@app.route('/api/replay-feature', methods=['POST'])
def replay_feature():
    """
    Dedicated endpoint for dataset feature replay and inference verification.
    Expects JSON structure:
      {
        "features": { ... 77 flow features ... },
        "ground_truth": "DDoS"
      }
    Validates features, executes model inference via prepare_features() and best_model.joblib,
    compares prediction with ground truth, and returns structured feedback without
    altering live monitoring session state or live_collector.
    """
    global model, CLASS_LABELS, BENIGN_IDX, replay_session_stats
    inf_start = time.time()
    try:
        data = request.get_json(force=True, silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "error": "Invalid input JSON. Expected a JSON object with 'features' and optional 'ground_truth'."
            }), 400

        # Extract features dictionary
        if "features" in data and isinstance(data["features"], dict):
            features_dict = data["features"]
        else:
            # Also support features passed directly at top-level alongside ground_truth
            features_dict = {
                k: v for k, v in data.items()
                if k not in ("ground_truth", "groundTruth", "Label", "label", "features")
            }

        if not features_dict or not isinstance(features_dict, dict):
            return jsonify({
                "status": "error",
                "error": "Missing or empty 'features' dictionary. Exactly 77 flow features required."
            }), 400

        # Extract ground truth label separately
        raw_truth = data.get("ground_truth")
        if raw_truth is None:
            raw_truth = data.get("groundTruth")
        if raw_truth is None:
            raw_truth = data.get("Label")
        if raw_truth is None:
            raw_truth = data.get("label")
        ground_truth = str(raw_truth).strip() if raw_truth is not None else "Unknown"

        # Prepare and validate features (strict 77-feature validation and scaling)
        try:
            X = prepare_features(features_dict)
        except ValueError as ve:
            return jsonify({
                "status": "error",
                "error": f"Feature validation or transformation error: {ve}"
            }), 400
        except Exception as fe:
            return jsonify({
                "status": "error",
                "error": f"Feature preprocessing exception: {fe}"
            }), 400

        if model is None:
            return jsonify({
                "status": "error",
                "error": "Model is not loaded on server."
            }), 500

        # Run inference
        prediction = int(model.predict(X)[0])
        predicted_label = CLASS_LABELS.get(prediction, "Unknown")
        is_attack = bool(prediction != BENIGN_IDX and str(predicted_label).lower() not in ["normal", "benign", "safe"])

        confidence = 100.0
        if hasattr(model, 'predict_proba'):
            try:
                proba = model.predict_proba(X)[0]
                confidence = round(float(proba[prediction]) * 100, 2)
            except Exception:
                pass

        # Compare ground truth with predicted label (normalized case & whitespace)
        norm_pred = str(predicted_label).strip().lower().replace("_", " ").replace("-", " ")
        norm_truth = str(ground_truth).strip().lower().replace("_", " ").replace("-", " ")
        match = bool(norm_pred == norm_truth)

        latency_ms = round((time.time() - inf_start) * 1000, 2)

        # Update dedicated replay session statistics (thread-safe, completely isolated from live monitoring)
        with replay_stats_lock:
            replay_session_stats["total_replayed"] += 1
            replay_session_stats["last_prediction"] = prediction
            replay_session_stats["last_predicted_label"] = predicted_label
            replay_session_stats["last_ground_truth"] = ground_truth
            replay_session_stats["last_match"] = match
            replay_session_stats["last_confidence"] = confidence
            replay_session_stats["last_latency_ms"] = latency_ms
            replay_session_stats["last_timestamp"] = time.strftime("%H:%M:%S")
            if match:
                replay_session_stats["matches"] += 1
            else:
                replay_session_stats["mismatches"] += 1

        return jsonify({
            "status": "success",
            "predicted_label": predicted_label,
            "prediction": prediction,
            "ground_truth": ground_truth,
            "match": match,
            "confidence": confidence,
            "is_attack": is_attack,
            "latency_ms": latency_ms
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "error": f"Internal replay inference error: {e}"
        }), 500


@app.route('/api/replay-status', methods=['GET'])
def get_replay_status():
    """Returns dedicated replay telemetry without touching live monitoring state."""
    with replay_stats_lock:
        stats = dict(replay_session_stats)
    return jsonify({
        "status": "success",
        "replay_stats": stats
    }), 200




# ==============================================================================
# Isolated Port & Network Scanner Endpoints
# Architecture: Independent async manager, zero interference with DDoS core.
# ==============================================================================
from modules.port_scanner.scanner import port_scanner_manager
from modules.common.network_detector import get_active_routable_ip
from modules.network_discovery.discovery import get_network_discovery_info


@app.route('/api/port-scan/network-info', methods=['GET'])
def get_port_scan_network_info():
    """Returns local host IP and suggested subnet for network scanning without hardcoded fallbacks."""
    try:
        net_info = get_network_discovery_info()
        is_conn = bool(net_info.get("is_connected"))
        local_ip = net_info.get("local_ip") if is_conn else "127.0.0.1"
        suggested_subnet = net_info.get("subnet_cidr") if is_conn else None
        return jsonify({
            "status": "success",
            "is_connected": is_conn,
            "adapter_name": net_info.get("adapter_name"),
            "adapter_type": net_info.get("adapter_type"),
            "local_ip": local_ip,
            "suggested_subnet": suggested_subnet
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/port-scan/start', methods=['POST'])
@subscription_required(feature="can_port_scan")
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


# ==============================================================================
# Isolated Network Discovery Endpoints
# Architecture: Independent multi-method LAN discovery, zero interference with DDoS core or Port Scanner.
# ==============================================================================
from modules.network_discovery.discovery import network_discovery_manager, get_network_discovery_info


@app.route('/network-discovery')
def network_discovery_page():
    """Renders the standalone Network Discovery cybersecurity dashboard."""
    return render_template('network_discovery.html')


@app.route('/api/network-discovery/network-info', methods=['GET'])
def get_network_discovery_info_route():
    """Returns detected adapter, IP, subnet mask, prefix length, and default gateway."""
    try:
        info = get_network_discovery_info()
        return jsonify({"status": "success", "network": info}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/network-discovery/start', methods=['POST'])
@subscription_required(feature="can_network_discovery")
def start_network_discovery():
    """Initiates an isolated network discovery sweep across the target local subnet."""
    try:
        data = request.get_json(silent=True) or {}
        subnet_cidr = data.get("subnet")
        timeout = float(data.get("timeout", 0.6))
        concurrency = int(data.get("concurrency", 50))

        res = network_discovery_manager.start_scan(
            subnet_cidr=subnet_cidr,
            timeout=timeout,
            concurrency=concurrency
        )
        return jsonify(res), 200
    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/network-discovery/status', methods=['GET'])
def get_network_discovery_status():
    """Polls real-time progress, metrics, and accumulated discovered devices."""
    try:
        state = network_discovery_manager.get_status()
        return jsonify(state), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/network-discovery/stop', methods=['POST'])
def stop_network_discovery():
    """Cooperatively cancels the active network discovery sweep immediately."""
    try:
        res = network_discovery_manager.stop_scan()
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/network-discovery/device/<ip>', methods=['GET'])
def get_network_discovery_device(ip: str):
    """Retrieves deep details for a single discovered device by IP address."""
    try:
        state = network_discovery_manager.get_status()
        devices = state.get("devices", [])
        for dev in devices:
            if dev.get("ip") == ip:
                return jsonify({"status": "success", "device": dev}), 200
        return jsonify({"status": "not_found", "message": f"Device {ip} not found in current scan results."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn


class BenignTrafficHandler(BaseHTTPRequestHandler):
    """
    Handles benign HTTP test traffic from the Sender Computer.
    Acknowledges requests with standard HTTP 200 OK responses to ensure full
    TCP three-way handshake, payload transfer, and clean teardown over Ethernet.
    """
    def log_message(self, format, *args):
        # Quiet standard HTTP server stderr logging
        pass

    def do_GET(self):
        body = json.dumps({
            "status": "success",
            "service": "SocNet Benign Traffic Sink",
            "message": "Benign network probe received and acknowledged.",
            "path": self.path,
            "timestamp": time.time()
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_len) if content_len > 0 else b""
        body = json.dumps({
            "status": "success",
            "service": "SocNet Benign Traffic Sink",
            "message": "Benign POST probe received and acknowledged.",
            "bytes_received": content_len,
            "timestamp": time.time()
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()


def start_benign_traffic_service(host: str = "0.0.0.0", port: int = 8080):
    """Starts the in-process Benign Traffic Test Service in a background thread."""
    try:
        from http.server import HTTPServer
        from socketserver import ThreadingMixIn
        class ThreadedTrafficServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        server = ThreadedTrafficServer((host, port), BenignTrafficHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        log_diag("TRAFFIC_SERVICE", f"Benign Traffic Test Server active on http://{host}:{port}")
        return server
    except Exception as ex:
        log_diag("TRAFFIC_SERVICE_ERROR", f"Could not bind Benign Traffic Server to port {port}: {ex}")
        return None


def check_port_availability(port: int = 5000):
    """Detects and alerts if port is already bound."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex(('127.0.0.1', port)) == 0:
            print(f"\n⚠️ [PORT WARNING] Port {port} is already in use by another process!")
            print(f"   Please stop any existing background api.py process before starting a new instance.\n", flush=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="SCOUT — Autonomous Cyber Threat Defense & Telemetry Platform")
    parser.add_argument("--host", default=os.environ.get("SOCNET_HOST", "0.0.0.0"), help="Host IP to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SOCNET_PORT", 5000)), help="Port to bind Flask API (default: 5000)")
    parser.add_argument("--traffic-port", type=int, default=int(os.environ.get("SOCNET_TRAFFIC_PORT", 8080)), help="Port for benign test traffic service (default: 8080)")
    parser.add_argument("--no-traffic-service", action="store_true", help="Disable the in-process benign traffic test service")
    args = parser.parse_args()

    load_model_and_scaler()
    check_port_availability(args.port)

    # Detect active primary adapter to display genuine IP to user
    primary_ad_info = {}
    try:
        primary_ad_info, _ = auto_detect_primary_interface()
    except Exception:
        pass

    ad_ip = primary_ad_info.get("primary_ip") or "127.0.0.1"
    ad_name = primary_ad_info.get("name") or "Primary Interface"
    ad_type = primary_ad_info.get("type") or "Network"

    if not args.no_traffic_service:
        app.traffic_test_port = args.traffic_port
        start_benign_traffic_service(host=args.host, port=args.traffic_port)

    # Dynamic metrics from active environment
    model_name = type(model).__name__ if model is not None else "Multi-Class XGBoost"
    feature_count = getattr(model, 'n_features_in_', len(FEATURE_COLUMNS) if FEATURE_COLUMNS is not None else 77)
    class_count = len(CLASS_LABELS) if CLASS_LABELS else 15
    scaler_name = type(scaler).__name__ if scaler is not None else "StandardScaler"

    print("=" * 90)
    print("   SCOUT : Autonomous Cyber Threat Defense & Telemetry Platform")
    print("   Real-Time Traffic Inspection • AI Intrusion Detection • Subnet & Port Recon")
    print("=" * 90)
    print(" [ENGINE STATUS]")
    print(f"   • Champion Model     : {model_name} ({feature_count} Flow Features, {class_count} Traffic Classes)")
    print(f"   • Telemetry Scaler   : {scaler_name} (Normalized Flow Dynamics)")
    print(f"   • Network Adapter    : [{ad_type}: {ad_name}] (Host IP: {ad_ip})")
    print(f"   • System Core        : Operational · Active Telemetry & Guarding")
    print("")
    print(" [ACTIVE WORKSTATIONS & URLS]")
    print(f"   → Web SOC Dashboard  : http://127.0.0.1:{args.port} (Localhost)")
    if ad_ip and ad_ip != "127.0.0.1":
        print(f"   → Remote / LAN Access: http://{ad_ip}:{args.port} [{ad_type}: {ad_name}]")
    print(f"   → Live Threat Radar  : http://127.0.0.1:{args.port}/?view=monitoring")
    print(f"   → Port & Host Scanner: http://127.0.0.1:{args.port}/?view=port-scanner")
    print(f"   → Subnet Discovery   : http://127.0.0.1:{args.port}/network-discovery")
    print(f"   → Architecture Map   : http://127.0.0.1:{args.port}/#system-architecture")
    if not args.no_traffic_service:
        print(f"   → Benign Traffic Sink: http://{ad_ip}:{args.traffic_port} (Port for send_traffic.py)")
    print("")
    print(" [CORE PLATFORM CAPABILITIES]")
    print("   • Live Flow Telemetry    : Real-time packet sniffer with 77-feature extraction engine")
    print("   • Multi-Class AI Defense : 15 traffic categories (DoS/DDoS, Web Attacks, Brute Force)")
    print("   • Subnet Reconnaissance  : Autonomous ARP/ICMP sweep & OUI hardware fingerprinting")
    print("   • Port Security Auditor  : Pure-Python async TCP port scanner (Localhost, IP, Subnet /24)")
    print("   • SOC Governance & RBAC  : Role-based access control, audit logs & telemetry analytics")
    print("=" * 90)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)