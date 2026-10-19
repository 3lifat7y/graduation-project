#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SocNet: Automated Unit Tests for Dataset Replay Inference Pipeline
Covers:
1. Dynamic label discovery and case-insensitive label selection.
2. Sampling with replacement.
3. Correct 77-feature payload construction.
4. Ground-truth label excluded from model input.
5. Successful inference response.
6. Correct and incorrect prediction comparisons.
7. Malformed payloads and invalid labels.
8. Missing features, extra metadata, and non-numeric values.
9. Model/preprocessing errors and network timeouts.
10. Continuous replay stopping cleanly.
11. Accurate session metrics and terminal output.
12. Replay results not contaminating live monitoring state.
13. Existing API routes and live-monitoring tests remaining compatible.
"""

import sys
import os
import json
import time
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import api
import scripts.send_traffic as st


class TestDatasetReplayInference(unittest.TestCase):
    """Unit tests for the dedicated dataset replay endpoint and sender pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.client = api.app.test_client()
        # Ensure model and scaler are loaded
        api.load_model_and_scaler()
        # Load sample dataset
        dataset_path = st.resolve_dataset_path()
        cls.dataset_path = dataset_path
        cls.records_by_label, cls.label_counts = st.load_dataset_records(dataset_path)

    def test_01_dynamic_label_discovery_and_case_insensitive_selection(self):
        """1. Dynamically discovers labels from dataset and resolves labels case-insensitively."""
        self.assertGreater(len(self.label_counts), 0)
        labels = [lbl for lbl, _ in self.label_counts]
        self.assertIn("Benign", labels)

        # Test case-insensitive resolution
        res_benign = st.resolve_label_argument("benign", self.label_counts)
        self.assertEqual(res_benign, "Benign")

        res_upper = st.resolve_label_argument("BENIGN", self.label_counts)
        self.assertEqual(res_upper, "Benign")

        # Test numeric index resolution
        res_first = st.resolve_label_argument("1", self.label_counts)
        self.assertEqual(res_first, self.label_counts[0][0])

        # Test invalid label
        res_invalid = st.resolve_label_argument("NonExistentLabel999", self.label_counts)
        self.assertIsNone(res_invalid)

    def test_02_sampling_with_replacement(self):
        """2. Verifies that random selection samples with replacement and allows infinite replay."""
        benign_records = self.records_by_label.get("Benign", [])
        self.assertGreater(len(benign_records), 0)

        # Sampling does not mutate or deplete records
        initial_len = len(benign_records)
        import random
        sampled = [random.choice(benign_records) for _ in range(50)]
        self.assertEqual(len(sampled), 50)
        self.assertEqual(len(benign_records), initial_len)

    def test_03_correct_77_feature_payload_construction(self):
        """3. Verifies that sender extracts 77 features and separates ground truth."""
        sample_rec = self.records_by_label.get("Benign", [])[0]
        self.assertIn("Label", sample_rec)

        features = {k: v for k, v in sample_rec.items() if k != "Label"}
        ground_truth = str(sample_rec.get("Label")).strip()

        payload = {
            "features": features,
            "ground_truth": ground_truth
        }

        self.assertEqual(len(payload["features"]), 77)
        self.assertEqual(payload["ground_truth"], "Benign")
        self.assertNotIn("Label", payload["features"])

    def test_04_ground_truth_excluded_from_model_input(self):
        """4. Ensures ground truth label is completely excluded from model input array X."""
        sample_rec = self.records_by_label.get("Benign", [])[0]
        features = {k: v for k, v in sample_rec.items() if k != "Label"}

        # Even if someone accidentally includes ground_truth in features dict
        tainted_features = dict(features)
        tainted_features["ground_truth"] = "DDoS"
        tainted_features["Label"] = "DDoS"

        X = api.prepare_features(tainted_features)
        self.assertEqual(X.shape, (1, 77))
        # Ensure input array is purely numeric
        self.assertTrue(issubclass(X.values.dtype.type if hasattr(X, 'values') else X.dtype.type, (float, int, 'float64')))

    def test_05_successful_inference_response(self):
        """5. Verifies POST /api/replay-feature returns structured prediction feedback."""
        sample_rec = self.records_by_label.get("Benign", [])[0]
        features = {k: v for k, v in sample_rec.items() if k != "Label"}

        resp = self.client.post("/api/replay-feature", json={
            "features": features,
            "ground_truth": "Benign"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertEqual(data.get("status"), "success")
        self.assertIn("predicted_label", data)
        self.assertIn("prediction", data)
        self.assertEqual(data.get("ground_truth"), "Benign")
        self.assertIn("match", data)
        self.assertIn("confidence", data)
        self.assertIn("is_attack", data)
        self.assertIn("latency_ms", data)
        self.assertGreater(data.get("confidence"), 0.0)

    def test_06_correct_and_incorrect_prediction_comparisons(self):
        """6. Verifies match=True when ground truth matches and match=False on mismatch."""
        sample_rec = self.records_by_label.get("Benign", [])[0]
        features = {k: v for k, v in sample_rec.items() if k != "Label"}

        # Benign sample tested with matching ground truth
        resp_match = self.client.post("/api/replay-feature", json={
            "features": features,
            "ground_truth": "Benign"
        })
        self.assertEqual(resp_match.status_code, 200)
        data_match = resp_match.get_json()
        self.assertEqual(data_match.get("predicted_label"), "Benign")
        self.assertTrue(data_match.get("match"))

        # Benign sample tested with intentionally mismatched ground truth (e.g. DDoS)
        resp_mismatch = self.client.post("/api/replay-feature", json={
            "features": features,
            "ground_truth": "DDoS"
        })
        self.assertEqual(resp_mismatch.status_code, 200)
        data_mismatch = resp_mismatch.get_json()
        self.assertEqual(data_mismatch.get("predicted_label"), "Benign")
        self.assertFalse(data_mismatch.get("match"))
        # A mismatch is a valid inference result, not an error
        self.assertEqual(data_mismatch.get("status"), "success")

    def test_07_malformed_payloads_and_empty_requests(self):
        """7. Verifies rejection of malformed or non-dict payloads with HTTP 400."""
        # Non-JSON or empty
        resp1 = self.client.post("/api/replay-feature", data="not json", content_type="text/plain")
        self.assertEqual(resp1.status_code, 400)
        self.assertEqual(resp1.get_json().get("status"), "error")

        # Empty dict
        resp2 = self.client.post("/api/replay-feature", json={})
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("error", resp2.get_json())

        # List instead of dict
        resp3 = self.client.post("/api/replay-feature", json=[1, 2, 3])
        self.assertEqual(resp3.status_code, 400)

    def test_08_missing_features_and_invalid_data_types(self):
        """8. Verifies rejection of missing features or invalid feature values."""
        # 'features' is not a dict
        resp1 = self.client.post("/api/replay-feature", json={"features": "invalid_string", "ground_truth": "DDoS"})
        self.assertEqual(resp1.status_code, 400)

        # Zero-duration and zero-length feature vector (fails validate_flow_features)
        zero_features = {k: 0.0 for k in api.FEATURE_COLUMNS} if api.FEATURE_COLUMNS else {"Protocol": 0.0}
        resp2 = self.client.post("/api/replay-feature", json={"features": zero_features, "ground_truth": "Benign"})
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("Feature validation", resp2.get_json().get("error", ""))

    def test_09_model_and_preprocessing_exception_handling(self):
        """9. Verifies graceful HTTP 500 when model is missing or fails."""
        sample_rec = self.records_by_label.get("Benign", [])[0]
        features = {k: v for k, v in sample_rec.items() if k != "Label"}

        with patch.object(api, 'model', None):
            resp = self.client.post("/api/replay-feature", json={
                "features": features,
                "ground_truth": "Benign"
            })
            self.assertEqual(resp.status_code, 500)
            self.assertIn("Model is not loaded", resp.get_json().get("error", ""))

    def test_10_continuous_replay_stops_cleanly(self):
        """10. Verifies sender loop handles Ctrl+C and consecutive transmission failures cleanly."""
        records = self.records_by_label.get("Benign", [])[:2]

        # Test Ctrl+C simulation
        with patch("urllib.request.urlopen", side_effect=KeyboardInterrupt):
            captured_out = StringIO()
            with patch("sys.stdout", captured_out):
                st.run_dataset_feature_stream(
                    records=records,
                    label="Benign",
                    target_api_url="http://127.0.0.1:5000",
                    interval=0.01,
                    count=5
                )
            out_text = captured_out.getvalue()
            self.assertIn("[STOP] Replay stopped cleanly by user (Ctrl+C)", out_text)
            self.assertIn("DATASET REPLAY INFERENCE SUMMARY", out_text)

        # Test 10 consecutive errors stops cleanly
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            captured_out = StringIO()
            with patch("sys.stdout", captured_out):
                st.run_dataset_feature_stream(
                    records=records,
                    label="Benign",
                    target_api_url="http://127.0.0.1:5000",
                    interval=0.0,
                    count=20
                )
            out_text = captured_out.getvalue()
            self.assertIn("Reached 10 consecutive transmission errors. Replay stopped cleanly.", out_text)

    def test_11_accurate_session_metrics_and_terminal_output(self):
        """11. Verifies terminal output displays real inference results, match status, and accuracy %."""
        records = self.records_by_label.get("Benign", [])[:3]

        mock_resp_match = MagicMock()
        mock_resp_match.read.return_value = json.dumps({
            "status": "success",
            "predicted_label": "Benign",
            "prediction": 0,
            "ground_truth": "Benign",
            "match": True,
            "confidence": 98.7,
            "is_attack": False,
            "latency_ms": 14.2
        }).encode('utf-8')
        mock_resp_match.__enter__.return_value = mock_resp_match

        with patch("urllib.request.urlopen", return_value=mock_resp_match):
            captured_out = StringIO()
            with patch("sys.stdout", captured_out):
                st.run_dataset_feature_stream(
                    records=records,
                    label="Benign",
                    target_api_url="http://127.0.0.1:5000",
                    interval=0.01,
                    count=3
                )
            out_text = captured_out.getvalue()
            self.assertIn("[REPLAY]     #1/3 | Truth=Benign         | Prediction=Benign         | Confidence= 98.7% | Match=YES | Latency=", out_text)
            self.assertIn("Correct Predictions   : 3 (100.0%)", out_text)
            self.assertIn("Prediction Mismatches : 0 (0.0%)", out_text)
            self.assertIn("Model Accuracy on Session: 100.0%", out_text)

    def test_12_replay_does_not_contaminate_live_monitoring_state(self):
        """12. Verifies that replay requests do NOT contaminate current_scan_session or live_collector."""
        initial_collector_count = api.live_collector.packet_count
        initial_scan_status = dict(api.current_scan_session)

        sample_rec = self.records_by_label.get("Benign", [])[0]
        features = {k: v for k, v in sample_rec.items() if k != "Label"}

        resp = self.client.post("/api/replay-feature", json={
            "features": features,
            "ground_truth": "Benign"
        })
        self.assertEqual(resp.status_code, 200)

        # Ensure live_collector packet count is completely unchanged
        self.assertEqual(api.live_collector.packet_count, initial_collector_count)

        # Ensure current_scan_session is completely untouched
        self.assertEqual(api.current_scan_session.get("status"), initial_scan_status.get("status"))
        self.assertEqual(api.current_scan_session.get("packets_captured"), initial_scan_status.get("packets_captured"))

        # Verify dedicated replay status endpoint reflects the replay
        replay_status_resp = self.client.get("/api/replay-status")
        self.assertEqual(replay_status_resp.status_code, 200)
        stats = replay_status_resp.get_json().get("replay_stats", {})
        self.assertGreater(stats.get("total_replayed", 0), 0)

    def test_13_existing_routes_remain_compatible(self):
        """13. Verifies that /api/receive-packet, /api/predict-direct, /api/scan-status are unchanged."""
        # 1. /api/receive-packet
        recv_resp = self.client.post("/api/receive-packet", json={"Protocol": 6, "Flow Duration": 1000})
        self.assertEqual(recv_resp.status_code, 200)
        self.assertEqual(recv_resp.get_json().get("status"), "received")

        # 2. /api/predict-direct
        sample_rec = self.records_by_label.get("Benign", [])[0]
        features = {k: v for k, v in sample_rec.items() if k != "Label"}
        direct_resp = self.client.post("/api/predict-direct", json=features)
        self.assertEqual(direct_resp.status_code, 200)
        self.assertEqual(direct_resp.get_json().get("status"), "success")

        # 3. /api/scan-status
        status_resp = self.client.get("/api/scan-status")
        self.assertEqual(status_resp.status_code, 200)
        self.assertIn("status", status_resp.get_json())


if __name__ == '__main__':
    unittest.main()
