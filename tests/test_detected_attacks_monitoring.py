"""
Regression and Verification Test Suite for Live Monitoring & Detected Attacks
Covering all 14 points required by the live monitoring specification.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import time

import api


class TestDetectedAttacksMonitoring(unittest.TestCase):
    def setUp(self):
        self.app = api.app.test_client()
        self.app.testing = True
        api.clear_detected_attacks_history()

    def tearDown(self):
        api.clear_detected_attacks_history()

    # -------------------------------------------------------------------------
    # 1. No Benign result is ever added to Detected Attacks
    # -------------------------------------------------------------------------
    def test_01_benign_never_added_to_detected_attacks(self):
        flow_meta = {
            "flow_id": "192.168.1.50:443-192.168.1.10:52341-TCP",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.50",
            "src_port": 52341,
            "dst_port": 443,
            "protocol": "TCP",
            "flow_summary": {"packets_captured": 12, "flow_duration_us": 1500000}
        }
        # Check that benign label is recognized
        self.assertTrue(api.is_benign_label("Benign"))
        self.assertTrue(api.is_benign_index(0))

        # Direct attempt via record_detected_attack
        rec_res = api.record_detected_attack(
            label="Benign",
            prediction=0,
            confidence=99.0,
            flow_meta=flow_meta,
            scan_id="scan_test_01"
        )
        self.assertIsNone(rec_res, "record_detected_attack must reject 'Benign'")
        self.assertEqual(len(api.get_detected_attacks_history()), 0, "Detected attacks history must remain empty for Benign")

    # -------------------------------------------------------------------------
    # 2. All non-benign model classes can be dynamically added
    # -------------------------------------------------------------------------
    def test_02_all_supported_attack_labels_can_be_added(self):
        supported_attacks = api.get_supported_attack_labels()
        self.assertGreater(len(supported_attacks), 0, "Model should support at least 1 attack label")
        
        for idx, label in api.CLASS_LABELS.items():
            if api.is_benign_label(label):
                continue
            
            flow_meta = {
                "flow_id": f"flow_attack_idx_{idx}",
                "src_ip": f"10.0.0.{idx}",
                "dst_ip": "192.168.1.100",
                "src_port": 10000 + idx,
                "dst_port": 80,
                "protocol": "TCP"
            }
            ev_res = api.record_detected_attack(
                label=label,
                prediction=idx,
                confidence=92.0 + (idx % 8),
                flow_meta=flow_meta,
                scan_id="scan_all_classes"
            )
            self.assertIsNotNone(ev_res, f"Non-benign attack '{label}' (idx={idx}) must be recorded")
            self.assertEqual(ev_res["label"], label)

        history = api.get_detected_attacks_history()
        history_labels = {item["label"] for item in history}
        for label in supported_attacks:
            self.assertIn(label, history_labels, f"Expected attack label '{label}' in detected attacks log")

    # -------------------------------------------------------------------------
    # 3. Case-insensitivity and whitespace handling for labels
    # -------------------------------------------------------------------------
    def test_03_case_insensitivity_and_whitespace_handling(self):
        test_benign_variants = ["benign", "BENIGN", " Benign ", "  benign  \n", "\tBENIGN\t"]
        for variant in test_benign_variants:
            self.assertTrue(
                api.is_benign_label(variant),
                f"Variant '{variant}' must be recognized as benign"
            )
            rec = api.record_detected_attack(
                label=variant,
                confidence=95.0,
                flow_meta={"flow_id": f"flow_{variant}"},
                scan_id="scan_case_test"
            )
            self.assertIsNone(rec, f"Variant '{variant}' should be rejected from detected attacks")

        # Attack labels with whitespace or case variants
        self.assertFalse(api.is_benign_label("ddos"))
        self.assertFalse(api.is_benign_label("  PortScan  "))
        self.assertFalse(api.is_benign_label("BOT"))

    # -------------------------------------------------------------------------
    # 4. Clear error if normal label cannot be determined
    # -------------------------------------------------------------------------
    def test_04_config_error_when_normal_label_cannot_be_determined(self):
        # Temporarily mock CLASS_LABELS without any benign variant
        corrupted_labels = {0: "Malformed_Attack_1", 1: "Malformed_Attack_2"}
        idx, label, err = api.resolve_benign_configuration(corrupted_labels)
        self.assertIsNone(idx)
        self.assertIsNone(label)
        self.assertIsNotNone(err)
        self.assertIn("Configuration Error", err)

    # -------------------------------------------------------------------------
    # 5. No detections created unless from genuine model outputs
    # -------------------------------------------------------------------------
    def test_05_detections_only_from_genuine_model_outputs(self):
        # Empty or invalid inputs must not create bogus detections
        empty_rec = api.record_detected_attack(
            label="",
            confidence=0.0,
            flow_meta={},
            scan_id="scan_empty"
        )
        self.assertIsNone(empty_rec)
        self.assertEqual(len(api.get_detected_attacks_history()), 0)

        none_rec = api.record_detected_attack(
            label=None,
            confidence=50.0,
            flow_meta={},
            scan_id="scan_none"
        )
        self.assertIsNone(none_rec)
        self.assertEqual(len(api.get_detected_attacks_history()), 0)

    # -------------------------------------------------------------------------
    # 6. Live traffic stream continues updating while attacks are added
    # -------------------------------------------------------------------------
    def test_06_live_traffic_continues_updating_with_attacks(self):
        # Record an attack
        api.record_detected_attack(
            label="DDoS",
            confidence=97.0,
            flow_meta={"flow_id": "flow_ddos_1", "src_ip": "10.0.0.1"},
            scan_id="scan_live_update"
        )
        self.assertEqual(len(api.get_detected_attacks_history()), 1)

        # Query scan-status and verify both live_packets and detected_attacks are distinct
        resp = self.app.get("/api/scan-status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("live_packets", data)
        self.assertIn("detected_attacks", data)
        self.assertIsInstance(data["live_packets"], list)
        self.assertIsInstance(data["detected_attacks"], list)
        self.assertEqual(len(data["detected_attacks"]), 1)

    # -------------------------------------------------------------------------
    # 7. Previous detections remain visible after traffic updates
    # -------------------------------------------------------------------------
    def test_07_previous_detections_persist_across_status_updates(self):
        api.record_detected_attack(
            label="PortScan",
            confidence=88.0,
            flow_meta={"flow_id": "flow_ps_1", "src_ip": "10.0.0.99"},
            scan_id="scan_persist_test"
        )
        # Call status multiple times
        for _ in range(5):
            resp = self.app.get("/api/scan-status")
            data = resp.get_json()
            self.assertEqual(data["detected_attacks_count"], 1)
            self.assertEqual(data["detected_attacks"][0]["label"], "PortScan")

    # -------------------------------------------------------------------------
    # 8. Prevent duplicate detections from repeated API polls
    # -------------------------------------------------------------------------
    def test_08_deduplication_of_same_flow_in_continuous_polling(self):
        flow_meta = {
            "flow_id": "192.168.1.100:80-10.0.0.1:44321-TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "src_port": 44321,
            "dst_port": 80,
            "protocol": "TCP"
        }
        # Simulate 10 polling intervals of the same ongoing flow attack
        for _ in range(10):
            api.record_detected_attack(
                label="DoS Hulk",
                confidence=94.5,
                flow_meta=flow_meta,
                scan_id="scan_dedup"
            )

        history = api.get_detected_attacks_history()
        self.assertEqual(len(history), 1, "Repeated polls for the same flow must update in-place without duplicating records")
        self.assertEqual(history[0]["occurrence_count"], 10)

    # -------------------------------------------------------------------------
    # 9. Preserve distinct events even if attack type is the same
    # -------------------------------------------------------------------------
    def test_09_preserve_independent_events_with_same_attack_type(self):
        flow_1 = {"flow_id": "flow_alpha", "src_ip": "10.1.1.1", "src_port": 1111}
        flow_2 = {"flow_id": "flow_beta", "src_ip": "10.1.1.2", "src_port": 2222}

        api.record_detected_attack(
            label="DDoS",
            confidence=95.0,
            flow_meta=flow_1,
            scan_id="scan_independent"
        )
        api.record_detected_attack(
            label="DDoS",
            confidence=96.0,
            flow_meta=flow_2,
            scan_id="scan_independent"
        )

        history = api.get_detected_attacks_history()
        self.assertEqual(len(history), 2, "Distinct flows with the same attack label must both be preserved")
        flow_ids = {h["flow_id"] for h in history}
        self.assertIn("flow_alpha", flow_ids)
        self.assertIn("flow_beta", flow_ids)

    # -------------------------------------------------------------------------
    # 10. No confusion between flow-level classification and raw packets
    # -------------------------------------------------------------------------
    def test_10_flow_classification_distinct_from_raw_packets(self):
        flow_meta = {
            "flow_id": "flow_test_10",
            "src_ip": "192.168.1.5",
            "dst_ip": "192.168.1.1",
            "src_port": 8080,
            "dst_port": 50000,
            "protocol": "TCP"
        }
        rec = api.record_detected_attack(
            label="Bot",
            confidence=89.0,
            flow_meta=flow_meta,
            scan_id="scan_flow_vs_pkt"
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["flow_id"], "flow_test_10")
        # Ensure attack event represents the flow
        self.assertIn("flow_id", rec)
        self.assertNotIn("live_packets", rec, "Individual live packets must not be stored inside the flow attack record")

    # -------------------------------------------------------------------------
    # 11. Correct behavior when monitoring stops and restarts
    # -------------------------------------------------------------------------
    def test_11_persistence_and_session_binding_across_scan_lifecycle(self):
        # Session 1 detection
        api.record_detected_attack(
            label="FTP-Patator",
            confidence=91.0,
            flow_meta={"flow_id": "flow_session_1"},
            scan_id="session_001"
        )
        # Session 2 detection
        api.record_detected_attack(
            label="SSH-Patator",
            confidence=93.0,
            flow_meta={"flow_id": "flow_session_2"},
            scan_id="session_002"
        )

        history = api.get_detected_attacks_history()
        self.assertEqual(len(history), 2)
        scan_ids = {h["scan_id"] for h in history}
        self.assertIn("session_001", scan_ids)
        self.assertIn("session_002", scan_ids)

    # -------------------------------------------------------------------------
    # 12. Clear History does NOT affect active capture or model state
    # -------------------------------------------------------------------------
    def test_12_clear_history_does_not_affect_capture_or_model(self):
        api.record_detected_attack(
            label="DDoS",
            confidence=99.0,
            flow_meta={"flow_id": "flow_clear_test"},
            scan_id="scan_clear"
        )
        self.assertEqual(len(api.get_detected_attacks_history()), 1)

        resp = self.app.post("/api/detected-attacks/clear")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(api.get_detected_attacks_history()), 0)

        # Verify model and scaler are untouched
        self.assertIsNotNone(api.model)
        self.assertIsNotNone(api.scaler)
        self.assertEqual(len(api.FEATURE_COLUMNS), 77)

    # -------------------------------------------------------------------------
    # 13. Dataset Replay results do NOT leak into live monitoring attack log
    # -------------------------------------------------------------------------
    def test_13_dataset_replay_does_not_contaminate_live_detected_attacks(self):
        api.clear_detected_attacks_history()
        initial_count = len(api.get_detected_attacks_history())

        # Send a dataset replay request with DDoS attack vector
        sample_features = {col: 10.0 for col in api.FEATURE_COLUMNS}
        resp = self.app.post(
            "/api/replay-feature",
            data=json.dumps({"features": sample_features}),
            content_type="application/json"
        )
        self.assertIn(resp.status_code, [200, 400, 500])
        
        # Verify detected_attacks_history in live monitoring remains strictly untouched
        after_count = len(api.get_detected_attacks_history())
        self.assertEqual(
            after_count,
            initial_count,
            "Dataset Replay feature prediction must NEVER inject into live monitoring detected attacks history"
        )

    # -------------------------------------------------------------------------
    # 14. Label transition handling
    # -------------------------------------------------------------------------
    def test_14_label_transition_handling(self):
        flow_meta = {"flow_id": "flow_trans_1", "src_ip": "10.0.0.5"}
        # Initial prediction: PortScan
        api.record_detected_attack(
            label="PortScan",
            confidence=85.0,
            flow_meta=flow_meta,
            scan_id="scan_trans"
        )
        # Classification changes to DDoS on same flow
        api.record_detected_attack(
            label="DDoS",
            confidence=95.0,
            flow_meta=flow_meta,
            scan_id="scan_trans"
        )
        history = api.get_detected_attacks_history()
        # Should record the new transition event rather than silently hiding it
        self.assertEqual(len(history), 2)
        labels = [h["label"] for h in history]
        self.assertEqual(labels, ["PortScan", "DDoS"])


if __name__ == "__main__":
    unittest.main()
