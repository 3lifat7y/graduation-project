#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: 77-Feature Live Traffic Extraction & WinDivert Flow Sniffer Engine
Extracts the exact 77 flow features defined in CIC-IDS2017 / final_output_new_dataset,
with microsecond flow timing using WinDivert (pydivert) and automatic network discovery.
"""

import os
import sys
import json
import time
import socket
import argparse
import subprocess
from collections import defaultdict, deque
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import numpy as np

# Import our network detector
try:
    from network_detector import auto_detect_primary_interface, find_tshark_path, is_admin_user
except ImportError:
    from .network_detector import auto_detect_primary_interface, find_tshark_path, is_admin_user

try:
    import pydivert
    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False

BASE_DIR = Path(__file__).resolve().parent
CONFIG_COLS_PATH = BASE_DIR / "final_output_new_dataset" / "configs" / "feature_columns.json"

# Load official 77 feature names in exact order
if CONFIG_COLS_PATH.exists():
    with open(CONFIG_COLS_PATH, "r", encoding="utf-8") as f:
        OFFICIAL_77_FEATURES = json.load(f)
else:
    OFFICIAL_77_FEATURES = [
        "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
        "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
        "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
        "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
        "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
        "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
        "Subflow Bwd Bytes", "Init Fwd Win Bytes", "Init Bwd Win Bytes",
        "Fwd Act Data Packets", "Fwd Seg Size Min", "Active Mean", "Active Std",
        "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
    ]


class FlowStatsCollector:
    """Collects and aggregates packet metadata to compute the standard 77 flow features."""

    def __init__(self, target_interface_index: Optional[int] = None):
        self.target_interface_index = target_interface_index
        self.reset()

    def reset(self):
        self.src_ip = None
        self.dst_ip = None
        self.src_port = 0
        self.dst_port = 0
        self.protocol_num = 6  # Default TCP
        self.start_time = None
        self.end_time = None
        self.last_packet_time = None

        # Packet sizes
        self.all_packet_sizes: List[int] = []
        self.fwd_packet_sizes: List[int] = []
        self.bwd_packet_sizes: List[int] = []

        # Timestamps in seconds
        self.all_packet_times: List[float] = []
        self.fwd_packet_times: List[float] = []
        self.bwd_packet_times: List[float] = []

        # Header lengths
        self.fwd_header_len = 0
        self.bwd_header_len = 0

        # TCP Window sizes
        self.init_fwd_win_bytes = 0
        self.init_bwd_win_bytes = 0

        # Data packets with payload
        self.fwd_act_data_pkts = 0
        self.fwd_seg_size_min = 20

        # Flags
        self.flags = defaultdict(int)
        self.fwd_psh = 0
        self.bwd_psh = 0
        self.fwd_urg = 0
        self.bwd_urg = 0

    def add_packet(self, pkt_info: Dict[str, Any]):
        """Processes a single raw or parsed packet dictionary."""
        # Strictly reject loopback or internal control packets if passed here
        if pkt_info.get("is_loopback", False):
            return
        src = pkt_info.get("src_ip", "0.0.0.0")
        dst = pkt_info.get("dst_ip", "0.0.0.0")
        if src.startswith("127.") or dst.startswith("127.") or src == "::1" or dst == "::1":
            return
        s_port = int(pkt_info.get("src_port", 0))
        d_port = int(pkt_info.get("dst_port", 0))
        if s_port in (5000, 50505) or d_port in (5000, 50505):
            return

        ts = pkt_info.get("timestamp", time.time())
        if self.start_time is None:
            self.start_time = ts
        self.end_time = ts
        self.last_packet_time = ts

        src = pkt_info.get("src_ip", "0.0.0.0")
        dst = pkt_info.get("dst_ip", "0.0.0.0")
        length = int(pkt_info.get("length", 60))
        proto = int(pkt_info.get("protocol", 6))
        header_len = int(pkt_info.get("header_len", 20))
        win_size = int(pkt_info.get("win_size", 0))
        payload_len = int(pkt_info.get("payload_len", max(0, length - header_len)))

        flags_dict = pkt_info.get("flags", {})

        if self.src_ip is None:
            self.src_ip = src
            self.dst_ip = dst
            self.protocol_num = proto
            self.src_port = pkt_info.get("src_port", 0)
            self.dst_port = pkt_info.get("dst_port", 0)

        is_fwd = (src == self.src_ip)

        self.all_packet_sizes.append(length)
        self.all_packet_times.append(ts)

        if is_fwd:
            self.fwd_packet_sizes.append(length)
            self.fwd_packet_times.append(ts)
            self.fwd_header_len += header_len
            if payload_len > 0:
                self.fwd_act_data_pkts += 1
            if header_len > 0:
                self.fwd_seg_size_min = min(self.fwd_seg_size_min, header_len)
            if self.init_fwd_win_bytes == 0 and win_size > 0:
                self.init_fwd_win_bytes = win_size
            if flags_dict.get("PSH"):
                self.fwd_psh += 1
            if flags_dict.get("URG"):
                self.fwd_urg += 1
        else:
            self.bwd_packet_sizes.append(length)
            self.bwd_packet_times.append(ts)
            self.bwd_header_len += header_len
            if self.init_bwd_win_bytes == 0 and win_size > 0:
                self.init_bwd_win_bytes = win_size
            if flags_dict.get("PSH"):
                self.bwd_psh += 1
            if flags_dict.get("URG"):
                self.bwd_urg += 1

        for f_name, f_val in flags_dict.items():
            if f_val:
                self.flags[f_name] += 1

    @property
    def packet_count(self) -> int:
        return len(self.all_packet_sizes)

    def compute_77_features(self) -> Dict[str, float]:
        """Calculates and returns all 77 flow features in exact schema alignment."""
        total_fwd_pkts = len(self.fwd_packet_sizes)
        total_bwd_pkts = len(self.bwd_packet_sizes)
        total_pkts = total_fwd_pkts + total_bwd_pkts

        now = time.time()
        start = self.start_time if self.start_time is not None else now
        end = self.end_time if self.end_time is not None else now
        duration_sec = max(end - start, 1e-6)
        # Flow duration in microseconds (standard for CIC-IDS2017)
        flow_duration_us = duration_sec * 1e6

        fwd_bytes = sum(self.fwd_packet_sizes)
        bwd_bytes = sum(self.bwd_packet_sizes)
        total_bytes = fwd_bytes + bwd_bytes

        def dist_stats(arr):
            if not arr:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            a = np.array(arr, dtype=np.float64)
            return float(np.max(a)), float(np.min(a)), float(np.mean(a)), float(np.std(a)), float(np.var(a))

        f_max, f_min, f_mean, f_std, _ = dist_stats(self.fwd_packet_sizes)
        b_max, b_min, b_mean, b_std, _ = dist_stats(self.bwd_packet_sizes)
        p_max, p_min, p_mean, p_std, p_var = dist_stats(self.all_packet_sizes)

        def iat_stats(times):
            if len(times) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            # diffs in microseconds
            diffs = np.diff(np.array(times, dtype=np.float64)) * 1e6
            diffs = diffs[diffs >= 0]
            if len(diffs) == 0:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            return float(np.sum(diffs)), float(np.mean(diffs)), float(np.std(diffs)), float(np.max(diffs)), float(np.min(diffs))

        flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = iat_stats(self.all_packet_times)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = iat_stats(self.fwd_packet_times)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = iat_stats(self.bwd_packet_times)

        flow_bytes_per_s = total_bytes / duration_sec
        flow_pkts_per_s = total_pkts / duration_sec
        fwd_pkts_per_s = total_fwd_pkts / duration_sec
        bwd_pkts_per_s = total_bwd_pkts / duration_sec

        down_up_ratio = float(total_bwd_pkts / max(1, total_fwd_pkts))
        avg_pkt_size = float(total_bytes / max(1, total_pkts))
        avg_fwd_seg = float(fwd_bytes / max(1, total_fwd_pkts))
        avg_bwd_seg = float(bwd_bytes / max(1, total_bwd_pkts))

        # Active / Idle time in microseconds
        # Threshold: 1,000,000 us (1 second)
        active_times = []
        idle_times = []
        if len(self.all_packet_times) >= 2:
            diffs_us = np.diff(np.array(self.all_packet_times, dtype=np.float64)) * 1e6
            for d in diffs_us:
                if d >= 1e6:
                    idle_times.append(d)
                else:
                    active_times.append(d)

        def simple_stats(arr):
            if not arr:
                return 0.0, 0.0, 0.0, 0.0
            a = np.array(arr, dtype=np.float64)
            return float(np.mean(a)), float(np.std(a)), float(np.max(a)), float(np.min(a))

        act_mean, act_std, act_max, act_min = simple_stats(active_times)
        idle_mean, idle_std, idle_max, idle_min = simple_stats(idle_times)

        if not active_times and flow_duration_us > 0:
            act_mean = flow_duration_us
            act_max = flow_duration_us
            act_min = flow_duration_us

        feat_dict = {
            "Protocol": float(self.protocol_num),
            "Flow Duration": float(round(flow_duration_us, 2)),
            "Total Fwd Packets": float(total_fwd_pkts),
            "Total Backward Packets": float(total_bwd_pkts),
            "Fwd Packets Length Total": float(fwd_bytes),
            "Bwd Packets Length Total": float(bwd_bytes),
            "Fwd Packet Length Max": float(f_max),
            "Fwd Packet Length Min": float(f_min),
            "Fwd Packet Length Mean": float(f_mean),
            "Fwd Packet Length Std": float(f_std),
            "Bwd Packet Length Max": float(b_max),
            "Bwd Packet Length Min": float(b_min),
            "Bwd Packet Length Mean": float(b_mean),
            "Bwd Packet Length Std": float(b_std),
            "Flow Bytes/s": float(flow_bytes_per_s),
            "Flow Packets/s": float(flow_pkts_per_s),
            "Flow IAT Mean": float(flow_iat_mean),
            "Flow IAT Std": float(flow_iat_std),
            "Flow IAT Max": float(flow_iat_max),
            "Flow IAT Min": float(flow_iat_min),
            "Fwd IAT Total": float(fwd_iat_tot),
            "Fwd IAT Mean": float(fwd_iat_mean),
            "Fwd IAT Std": float(fwd_iat_std),
            "Fwd IAT Max": float(fwd_iat_max),
            "Fwd IAT Min": float(fwd_iat_min),
            "Bwd IAT Total": float(bwd_iat_tot),
            "Bwd IAT Mean": float(bwd_iat_mean),
            "Bwd IAT Std": float(bwd_iat_std),
            "Bwd IAT Max": float(bwd_iat_max),
            "Bwd IAT Min": float(bwd_iat_min),
            "Fwd PSH Flags": float(self.fwd_psh),
            "Bwd PSH Flags": float(self.bwd_psh),
            "Fwd URG Flags": float(self.fwd_urg),
            "Bwd URG Flags": float(self.bwd_urg),
            "Fwd Header Length": float(self.fwd_header_len),
            "Bwd Header Length": float(self.bwd_header_len),
            "Fwd Packets/s": float(fwd_pkts_per_s),
            "Bwd Packets/s": float(bwd_pkts_per_s),
            "Packet Length Min": float(p_min),
            "Packet Length Max": float(p_max),
            "Packet Length Mean": float(p_mean),
            "Packet Length Std": float(p_std),
            "Packet Length Variance": float(p_var),
            "FIN Flag Count": float(self.flags.get("FIN", 0)),
            "SYN Flag Count": float(self.flags.get("SYN", 0)),
            "RST Flag Count": float(self.flags.get("RST", 0)),
            "PSH Flag Count": float(self.flags.get("PSH", 0)),
            "ACK Flag Count": float(self.flags.get("ACK", 0)),
            "URG Flag Count": float(self.flags.get("URG", 0)),
            "CWE Flag Count": float(self.flags.get("CWE", 0)),
            "ECE Flag Count": float(self.flags.get("ECE", 0)),
            "Down/Up Ratio": float(round(down_up_ratio, 3)),
            "Avg Packet Size": float(avg_pkt_size),
            "Avg Fwd Segment Size": float(avg_fwd_seg),
            "Avg Bwd Segment Size": float(avg_bwd_seg),
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(total_fwd_pkts),
            "Subflow Fwd Bytes": float(fwd_bytes),
            "Subflow Bwd Packets": float(total_bwd_pkts),
            "Subflow Bwd Bytes": float(bwd_bytes),
            "Init Fwd Win Bytes": float(self.init_fwd_win_bytes),
            "Init Bwd Win Bytes": float(self.init_bwd_win_bytes),
            "Fwd Act Data Packets": float(self.fwd_act_data_pkts),
            "Fwd Seg Size Min": float(self.fwd_seg_size_min),
            "Active Mean": float(act_mean),
            "Active Std": float(act_std),
            "Active Max": float(act_max),
            "Active Min": float(act_min),
            "Idle Mean": float(idle_mean),
            "Idle Std": float(idle_std),
            "Idle Max": float(idle_max),
            "Idle Min": float(idle_min)
        }

        # Order strictly by the 77 official features
        ordered_dict = {}
        for feat in OFFICIAL_77_FEATURES:
            val = feat_dict.get(feat, 0.0)
            if np.isnan(val) or np.isinf(val):
                val = 0.0
            ordered_dict[feat] = val

        return ordered_dict


def validate_flow_features(features_dict: Any, min_packets: int = 3) -> Tuple[bool, str]:
    """
    Strict validation gate to ensure flow features originate from real intercepted traffic.
    Prevents empty, all-zero, or default synthetic features from triggering false predictions.
    """
    if not isinstance(features_dict, dict) or not features_dict:
        return False, "Feature dictionary is empty or not a valid dictionary."

    # Unwrap nested features if passed
    if "features" in features_dict and isinstance(features_dict["features"], dict):
        features_dict = features_dict["features"]

    # Check key packet count indicators
    fwd_pkts = float(features_dict.get("Total Fwd Packets", 0))
    bwd_pkts = float(features_dict.get("Total Backward Packets", 0))
    total_pkts = fwd_pkts + bwd_pkts

    if total_pkts < min_packets:
        return False, f"Total packets ({total_pkts}) is less than minimum required ({min_packets})."

    # Check byte volume and non-zero counts
    fwd_bytes = float(features_dict.get("Fwd Packets Length Total", 0))
    bwd_bytes = float(features_dict.get("Bwd Packets Length Total", 0))
    total_bytes = fwd_bytes + bwd_bytes

    if total_bytes <= 0:
        return False, "Total packet bytes is zero. No valid network flow payload or headers."

    non_zero_count = sum(1 for k, v in features_dict.items() if isinstance(v, (int, float)) and abs(float(v)) > 1e-9)
    if non_zero_count < 5:
        return False, f"Feature vector contains only {non_zero_count} non-zero values; invalid network flow."

    return True, "Valid flow features."


class RollingFlowStatsCollector:
    """
    Maintains a thread-safe sliding window buffer of intercepted packets.
    Enables continuous, non-stop packet capture while generating fresh 77-feature
    snapshots for real-time monitoring (e.g. every 500ms).
    """

    def __init__(self, target_interface_index: Optional[int] = None, window_seconds: float = 2.0, max_buffer_packets: int = 10000):
        self.target_interface_index = target_interface_index
        self.window_seconds = window_seconds
        self.max_buffer_packets = max_buffer_packets
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.packet_buffer: deque = deque(maxlen=self.max_buffer_packets)
            self.session_start_time = time.time()
            self.total_packets_seen = 0
            self.total_bytes_seen = 0
            self.last_packet_time: Optional[float] = None

    def add_packet(self, pkt_info: Dict[str, Any]):
        """Processes and appends a single packet dictionary into the rolling window buffer."""
        if not pkt_info or pkt_info.get("is_loopback", False):
            return
        src = pkt_info.get("src_ip", "0.0.0.0")
        dst = pkt_info.get("dst_ip", "0.0.0.0")
        if src.startswith("127.") or dst.startswith("127.") or src == "::1" or dst == "::1":
            return
        s_port = int(pkt_info.get("src_port", 0))
        d_port = int(pkt_info.get("dst_port", 0))
        if s_port in (5000, 50505) or d_port in (5000, 50505):
            return

        ts = float(pkt_info.get("timestamp", time.time()))
        length = int(pkt_info.get("length", 60))

        with self.lock:
            self.total_packets_seen += 1
            self.total_bytes_seen += length
            self.last_packet_time = ts
            self.packet_buffer.append((ts, pkt_info))

    def prune_old_packets(self, now: Optional[float] = None):
        """Purges packets older than window_seconds from the front of the deque."""
        cur_t = now or time.time()
        cutoff = cur_t - self.window_seconds
        with self.lock:
            while self.packet_buffer and self.packet_buffer[0][0] < cutoff:
                self.packet_buffer.popleft()

    def get_window_snapshot(self, now: Optional[float] = None, min_packets: int = 3) -> Dict[str, Any]:
        """
        Extracts a fresh snapshot of the active sliding window:
        - Prunes expired packets.
        - Computes instantaneous throughput (KB/s).
        - Determines dominant protocol.
        - If window is empty: returns status 'no_traffic'.
        - If window < min_packets: returns status 'insufficient_traffic'.
        - If window >= min_packets: builds FlowStatsCollector on windowed packets and computes 77 features.
        """
        cur_t = now or time.time()
        self.prune_old_packets(cur_t)

        with self.lock:
            active_packets = [pkt for _, pkt in self.packet_buffer]
            total_seen = self.total_packets_seen
            total_bytes = self.total_bytes_seen
            last_pkt = self.last_packet_time
            session_dur = round(max(0.0, cur_t - self.session_start_time), 2)

        window_count = len(active_packets)
        window_bytes = sum(int(p.get("length", 60)) for p in active_packets)
        throughput_bytes_per_s = round(window_bytes / max(0.5, self.window_seconds), 2)
        throughput_kbps = round(throughput_bytes_per_s / 1024.0, 2)

        # Dominant protocol in active window
        proto_counts = defaultdict(int)
        for p in active_packets:
            proto_counts[int(p.get("protocol", 6))] += 1
        active_proto = max(proto_counts, key=proto_counts.get) if proto_counts else 6

        base_res = {
            "session_duration": session_dur,
            "total_packets": total_seen,
            "total_bytes": total_bytes,
            "window_packets": window_count,
            "window_bytes": window_bytes,
            "throughput_bytes_per_s": throughput_bytes_per_s,
            "throughput_kbps": throughput_kbps,
            "protocol": active_proto,
            "last_packet_time": last_pkt,
            "window_seconds": self.window_seconds,
            "features": None
        }

        if window_count == 0:
            base_res["status"] = "no_traffic"
            base_res["message"] = f"No traffic detected in the last {self.window_seconds}s window."
            return base_res

        if window_count < min_packets:
            base_res["status"] = "insufficient_traffic"
            base_res["message"] = f"Network quiet: only {window_count} packet(s) in active window (min required: {min_packets})."
            return base_res

        # Build FlowStatsCollector on the active window
        collector = FlowStatsCollector(target_interface_index=self.target_interface_index)
        for pkt in active_packets:
            collector.add_packet(pkt)

        features = collector.compute_77_features()
        is_valid, reason = validate_flow_features(features, min_packets=min_packets)
        if not is_valid:
            base_res["status"] = "invalid_features"
            base_res["message"] = f"Flow feature validation failed: {reason}"
            return base_res

        base_res["status"] = "monitoring"
        base_res["features"] = features
        base_res["message"] = f"Active traffic: {window_count} packets in current window ({throughput_kbps} KB/s)."
        return base_res


def parse_windivert_packet(packet, target_if_idx: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Extracts transport and IP headers from a pydivert Packet object, rejecting loopback/management."""
    try:
        # 1. Reject loopback flag from WinDivert kernel driver
        if getattr(packet, 'is_loopback', False):
            return None

        # 2. Extract and check interface index
        if_tuple = getattr(packet, 'interface', None)
        if_idx = if_tuple[0] if if_tuple and len(if_tuple) > 0 else None
        if target_if_idx is not None and if_idx is not None and if_idx != target_if_idx:
            return None

        ts = float(packet.timestamp.timestamp()) if hasattr(packet.timestamp, 'timestamp') else time.time()
        length = len(packet.raw) if packet.raw else 60

        src_ip = str(packet.src_addr or "0.0.0.0")
        dst_ip = str(packet.dst_addr or "0.0.0.0")

        # 3. Reject loopback IP addresses
        if src_ip.startswith("127.") or dst_ip.startswith("127.") or src_ip == "::1" or dst_ip == "::1":
            return None

        src_port = int(packet.src_port or 0)
        dst_port = int(packet.dst_port or 0)

        # 4. Reject local management ports (Flask: 5000, IPC: 50505)
        if src_port in (5000, 50505) or dst_port in (5000, 50505):
            return None

        proto = 6
        if packet.ipv4:
            proto = int(packet.ipv4.protocol)
        elif packet.ipv6:
            proto = int(packet.ipv6.next_hdr)
        elif isinstance(packet.protocol, tuple):
            proto = int(packet.protocol[0])

        header_len = 20
        win_size = 0
        payload_len = 0
        flags = {}

        if packet.tcp:
            proto = 6
            header_len = int(getattr(packet.tcp, 'header_len', 20))
            win_size = int(getattr(packet.tcp, 'window', 0))
            payload_len = int(getattr(packet.tcp, 'payload_len', 0))
            flags["FIN"] = 1 if getattr(packet.tcp, 'fin', False) else 0
            flags["SYN"] = 1 if getattr(packet.tcp, 'syn', False) else 0
            flags["RST"] = 1 if getattr(packet.tcp, 'rst', False) else 0
            flags["PSH"] = 1 if getattr(packet.tcp, 'psh', False) else 0
            flags["ACK"] = 1 if getattr(packet.tcp, 'ack', False) else 0
            flags["URG"] = 1 if getattr(packet.tcp, 'urg', False) else 0
            flags["CWE"] = 1 if getattr(packet.tcp, 'cwr', False) else 0
            flags["ECE"] = 1 if getattr(packet.tcp, 'ece', False) else 0
        elif packet.udp:
            proto = 17
            header_len = int(getattr(packet.udp, 'header_len', 8))
            payload_len = int(getattr(packet.udp, 'payload_len', max(0, length - 28)))

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length": length,
            "header_len": header_len,
            "win_size": win_size,
            "payload_len": payload_len,
            "flags": flags,
            "interface_index": if_idx,
            "is_loopback": False
        }
    except Exception:
        return None


def parse_pyshark_packet(packet) -> Optional[Dict[str, Any]]:
    """Extracts transport and IP headers from a PyShark packet object (fallback)."""
    try:
        ts = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else time.time()
        length = int(packet.length) if hasattr(packet, 'length') else 60

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        proto = 6

        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = int(getattr(packet.ip, 'proto', 6))
        elif hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
            proto = 6

        src_port = 0
        dst_port = 0
        header_len = 20
        win_size = 0
        payload_len = 0
        flags = {}

        if hasattr(packet, 'tcp'):
            proto = 6
            src_port = int(getattr(packet.tcp, 'srcport', 0))
            dst_port = int(getattr(packet.tcp, 'dstport', 0))
            header_len = int(getattr(packet.tcp, 'hdr_len', 20))
            win_size = int(getattr(packet.tcp, 'window_size', 0))
            payload_len = int(getattr(packet.tcp, 'len', 0))

            raw_flags = str(getattr(packet.tcp, 'flags', ""))
            flags["FIN"] = int("0x0001" in raw_flags or "FIN" in raw_flags)
            flags["SYN"] = int("0x0002" in raw_flags or "SYN" in raw_flags)
            flags["RST"] = int("0x0004" in raw_flags or "RST" in raw_flags)
            flags["PSH"] = int("0x0008" in raw_flags or "PSH" in raw_flags)
            flags["ACK"] = int("0x0010" in raw_flags or "ACK" in raw_flags)
            flags["URG"] = int("0x0020" in raw_flags or "URG" in raw_flags)
            flags["CWE"] = int("0x0040" in raw_flags)
            flags["ECE"] = int("0x0080" in raw_flags)

        elif hasattr(packet, 'udp'):
            proto = 17
            src_port = int(getattr(packet.udp, 'srcport', 0))
            dst_port = int(getattr(packet.udp, 'dstport', 0))
            header_len = 8
            payload_len = max(0, length - 28)

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length": length,
            "header_len": header_len,
            "win_size": win_size,
            "payload_len": payload_len,
            "flags": flags
        }
    except Exception:
        return None


def write_features_atomic(payload: Dict[str, Any], output_path: Path):
    """Atomically writes features and metadata to target JSON file."""
    tmp_path = output_path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        tmp_path.replace(output_path)
    except Exception as e:
        print(f"[Error] Failed to write {output_path}: {e}", file=sys.stderr)


def capture_window_windivert(
    interface_name: Optional[str] = None,
    interface_index: Optional[int] = None,
    duration: float = 3.0,
    min_packets: int = 3,
    filter_str: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Captures live packets via WinDivert kernel filter in SNIFF mode for `duration` seconds.
    Strictly excludes loopback traffic and binds to target interface when index is provided.
    Returns:
        (status_dict, features_dict)
    """
    if not HAS_PYDIVERT:
        return {
            "status": "error",
            "error_type": "ModuleMissing",
            "message": "pydivert module is not installed. Install with 'pip install pydivert'."
        }, {}

    # Build safe kernel filter that eliminates loopback and restricts to physical traffic
    if not filter_str or filter_str.strip() == "true":
        base_exclude = "!loopback && (ip || ipv6) && (!tcp || (tcp.SrcPort != 5000 && tcp.DstPort != 5000 && tcp.SrcPort != 50505 && tcp.DstPort != 50505))"
        if interface_index is not None and int(interface_index) > 0:
            effective_filter = f"ifIdx == {int(interface_index)} && {base_exclude}"
        else:
            effective_filter = base_exclude
    else:
        effective_filter = filter_str

    collector = FlowStatsCollector(target_interface_index=interface_index)
    start_t = time.time()

    try:
        with pydivert.WinDivert(effective_filter, flags=pydivert.Flag.SNIFF) as w:
            while True:
                elapsed = time.time() - start_t
                if elapsed >= duration:
                    break
                time_left = max(0.05, duration - elapsed)
                try:
                    packet = w.recv(timeout=min(time_left, 0.4))
                    if packet:
                        pkt_dict = parse_windivert_packet(packet, target_if_idx=interface_index)
                        if pkt_dict:
                            collector.add_packet(pkt_dict)
                except TimeoutError:
                    continue
                except Exception:
                    break
    except PermissionError as pe:
        return {
            "status": "error",
            "error_type": "DriverPermissionError",
            "message": (
                "WinDivert requires Windows Administrator privileges to open kernel packet filters. "
                "Please launch your command prompt, IDE, or terminal as Administrator."
            ),
            "packets_captured": collector.packet_count,
            "duration": round(time.time() - start_t, 2)
        }, {}
    except Exception as e:
        err_msg = str(e)
        return {
            "status": "error",
            "error_type": "WinDivertError",
            "message": err_msg,
            "packets_captured": collector.packet_count,
            "duration": round(time.time() - start_t, 2)
        }, {}

    actual_duration = round(time.time() - start_t, 2)
    pkt_count = collector.packet_count

    if pkt_count == 0:
        return {
            "status": "no_traffic",
            "packets_captured": 0,
            "min_required": min_packets,
            "duration": actual_duration,
            "interface": interface_name or "Network Adapter",
            "last_packet_time": None,
            "message": f"No traffic detected on [{interface_name or 'Network Adapter'}]. 0 packets intercepted."
        }, {}
    elif pkt_count < min_packets:
        return {
            "status": "insufficient_traffic",
            "packets_captured": pkt_count,
            "min_required": min_packets,
            "duration": actual_duration,
            "interface": interface_name or "Network Adapter",
            "last_packet_time": collector.last_packet_time,
            "message": f"Only {pkt_count} packet(s) intercepted during the {actual_duration}s observation window. Insufficient data to form a full statistical flow."
        }, {}

    features = collector.compute_77_features()
    is_valid, val_reason = validate_flow_features(features, min_packets=min_packets)
    if not is_valid:
        return {
            "status": "error",
            "error_type": "InvalidFlowFeatures",
            "message": f"Feature validation failed: {val_reason}",
            "packets_captured": pkt_count,
            "duration": actual_duration,
            "interface": interface_name or "Network Adapter",
            "last_packet_time": collector.last_packet_time
        }, {}

    return {
        "status": "captured",
        "packets_captured": pkt_count,
        "duration": actual_duration,
        "interface": interface_name or "WinDivert (Physical)",
        "last_packet_time": collector.last_packet_time
    }, features


def capture_window_pyshark(
    interface_name: str,
    duration: float = 3.0,
    min_packets: int = 3,
    tshark_path: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Captures live packets on the specified interface for `duration` seconds via PyShark fallback."""
    collector = FlowStatsCollector()
    tshark_path = tshark_path or find_tshark_path()

    kwargs = {"interface": interface_name}
    if tshark_path:
        kwargs["tshark_path"] = tshark_path

    start_t = time.time()
    try:
        cap = pyshark.LiveCapture(**kwargs)
        for packet in cap.sniff_continuously():
            pkt_dict = parse_pyshark_packet(packet)
            if pkt_dict:
                collector.add_packet(pkt_dict)
            if time.time() - start_t >= duration:
                break
        cap.close()
    except Exception as e:
        return {
            "status": "error",
            "error_type": "SniffError",
            "message": str(e),
            "packets_captured": collector.packet_count,
            "duration": round(time.time() - start_t, 2)
        }, {}

    actual_duration = round(time.time() - start_t, 2)
    pkt_count = collector.packet_count

    if pkt_count < min_packets:
        return {
            "status": "insufficient_traffic",
            "packets_captured": pkt_count,
            "min_required": min_packets,
            "duration": actual_duration,
            "message": f"Only {pkt_count} packet(s) intercepted during the {actual_duration}s observation window."
        }, {}

    features = collector.compute_77_features()
    return {
        "status": "captured",
        "packets_captured": pkt_count,
        "duration": actual_duration,
        "interface": interface_name
    }, features


def main():
    p = argparse.ArgumentParser(description="DDoS-Guard: 77-Feature WinDivert Flow Sniffer Engine")
    p.add_argument("--duration", "-d", type=float, default=3.0, help="Sniff window duration in seconds (Default: 3.0)")
    p.add_argument("--min-packets", "-m", type=int, default=3, help="Minimum packets required for valid flow (Default: 3)")
    p.add_argument("--iface", "-i", type=str, default=None, help="Interface override (e.g. 'Wi-Fi')")
    p.add_argument("--engine", "-e", type=str, default="windivert", choices=["windivert", "pyshark"], help="Capture engine (Default: windivert)")
    p.add_argument("--output", "-o", type=str, default="extracted_features.json", help="Path to output JSON")
    args = p.parse_args()

    out_path = Path(args.output).resolve()

    print("=" * 65)
    print("   DDoS-Guard: 77-FEATURE WinDivert PACKET SNIFFER & FLOW EXTRACTOR")
    print("=" * 65)

    try:
        adapter, drivers = auto_detect_primary_interface()
    except Exception as e:
        print(f"❌ Interface Error: {e}", file=sys.stderr)
        err_payload = {"status": "error", "error_type": "InterfaceError", "message": str(e)}
        write_features_atomic(err_payload, out_path)
        sys.exit(1)

    iface_to_use = args.iface or adapter["name"]
    print(f"🔍 Active Adapter Detected : {adapter['name']} ({adapter['type']})")
    print(f"   IP Address              : {adapter['primary_ip']}")
    print(f"   Engine Selected         : {args.engine.upper()}")
    print(f"   Observation Window      : {args.duration}s (Threshold: {args.min_packets} packets)")

    if args.engine == "windivert":
        if not drivers["windivert_available"]:
            print(f"\n⚠️ Notice: {drivers['remediation_guide']}\n")
            status = {"status": "error", "error_type": "DriverMissing", "message": drivers["remediation_guide"]}
            write_features_atomic(status, out_path)
            sys.exit(1)

        print(f"🚀 Capturing packets via WinDivert kernel filter for {args.duration}s...")
        status, features = capture_window_windivert(
            interface_name=iface_to_use,
            duration=args.duration,
            min_packets=args.min_packets
        )
    else:
        print(f"🚀 Sniffing packets via PyShark on [{iface_to_use}] for {args.duration}s...")
        status, features = capture_window_pyshark(
            iface_to_use,
            duration=args.duration,
            min_packets=args.min_packets
        )

    if status["status"] == "captured":
        print(f"✅ Success! Captured {status['packets_captured']} packets in {status['duration']}s.")
        print(f"   Computed {len(features)} standard flow features.")
        payload = {**status, **features}
        write_features_atomic(payload, out_path)
    elif status["status"] == "insufficient_traffic":
        print(f"⚠️ Insufficient Traffic: {status['message']}")
        write_features_atomic(status, out_path)
    else:
        print(f"❌ Capture Error: {status.get('message')}")
        write_features_atomic(status, out_path)


if __name__ == "__main__":
    main()