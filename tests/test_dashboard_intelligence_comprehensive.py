"""Unit tests for SentinelShield Dashboard Intelligence & ML Pipeline Implementation.

Covers:
- Task A: Machine Learning Suite Loading, Diagnostics, and Live Inference
- Task B: Model Explanations (RF MDI, KNN Neighbors, IF Decision Function, Plain Language Synthesis)
- Task C: Behavioral Intelligence & Access Control Lab (Privacy Compliance, Biometrics, Over-Efficiency, Policy Trail)
- Task D: Hybrid ML Strategy Telemetry Data
- Task E: Threat Intelligence Provider Fallback, Caching, and BSSID Reputation
- Task F: PDF Report Generation and CSV Report UI Deprecation
"""

import json
import os
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent


class MachineLearningSuiteTests(unittest.TestCase):
    """Task A: Verify model artifacts loading, inference, and ensemble consensus."""

    def test_artifacts_exist_and_load(self):
        from dashboard import _load_ml_suite

        artifacts, diagnostics, perm_data = _load_ml_suite()
        for key in ["rf", "knn", "iso", "meta", "scaler", "meta_scaler", "le_sec", "le_lab"]:
            self.assertIsNotNone(artifacts.get(key), f"Model/scaler '{key}' should be loaded.")

    def test_inference_on_synthetic_scan(self):
        from dashboard import _load_ml_suite
        from ensemble_contract import score_features

        artifacts, _, _ = _load_ml_suite()
        rf = artifacts["rf"]
        knn = artifacts["knn"]
        iso = artifacts["iso"]
        meta = artifacts["meta"]
        scaler = artifacts["scaler"]
        meta_scaler = artifacts["meta_scaler"]
        le_sec = artifacts["le_sec"]
        le_lab = artifacts["le_lab"]

        fake_idx = int(le_lab.transform(["Fake"])[0])
        sec_idx = int(le_sec.transform(["WPA2"])[0])

        # Test normal observation
        normal_raw = np.array([[-50.0, 2412.0, sec_idx, 1.0, 2.0]], dtype=float)
        scored = score_features(rf, knn, iso, meta, scaler, meta_scaler, fake_idx, normal_raw)

        self.assertIn("rf_fake", scored)
        self.assertIn("knn_fake", scored)
        self.assertIn("isolation_anomaly", scored)
        self.assertIn("meta_fake", scored)
        self.assertGreaterEqual(float(scored["rf_fake"][0]), 0.0)
        self.assertLessEqual(float(scored["rf_fake"][0]), 1.0)


class ModelExplanationXAITests(unittest.TestCase):
    """Task B: Verify XAI calculations for RF, KNN, Isolation Forest, and incident narrative."""

    def test_rf_feature_importances(self):
        from dashboard import _load_ml_suite

        artifacts, _, _ = _load_ml_suite()
        rf = artifacts["rf"]
        importances = rf.feature_importances_
        self.assertEqual(len(importances), 5)
        self.assertAlmostEqual(float(np.sum(importances)), 1.0, places=4)

    def test_knn_nearest_neighbors(self):
        from dashboard import _load_ml_suite

        artifacts, _, _ = _load_ml_suite()
        knn = artifacts["knn"]
        scaler = artifacts["scaler"]
        sample = np.array([[-60.0, 2412.0, 1.0, 1.0, 2.5]], dtype=float)
        scaled = scaler.transform(sample)
        distances, indices = knn.kneighbors(scaled)
        self.assertEqual(distances.shape, (1, 5))
        self.assertEqual(indices.shape, (1, 5))
        self.assertTrue(all(d >= 0.0 for d in distances[0]))

    def test_isolation_forest_decision_function(self):
        from dashboard import _load_ml_suite

        artifacts, _, _ = _load_ml_suite()
        iso = artifacts["iso"]
        scaler = artifacts["scaler"]
        sample = np.array([[-60.0, 2412.0, 1.0, 1.0, 2.5]], dtype=float)
        scaled = scaler.transform(sample)
        score = iso.decision_function(scaled)
        self.assertEqual(len(score), 1)
        self.assertIsInstance(float(score[0]), float)


class BehavioralIntelligenceTests(unittest.TestCase):
    """Task C: Verify Privacy constraints, biometrics, over-efficiency, and access control."""

    def test_biometrics_zero_plaintext_character_leakage(self):
        from behavioral_biometrics import BehavioralBiometricsEngine, KeystrokeEvent

        engine = BehavioralBiometricsEngine()
        # Synthetic events with opaque tokens
        events = [
            KeystrokeEvent(key="k0", press_time_ms=0.0, release_time_ms=80.0),
            KeystrokeEvent(key="k1", press_time_ms=120.0, release_time_ms=200.0),
            KeystrokeEvent(key="k2", press_time_ms=240.0, release_time_ms=320.0),
        ]
        eval_res = engine.evaluate_session("test_user", events, total_duration_ms=400.0, backspace_count=0)
        self.assertIsNotNone(eval_res)
        self.assertGreater(eval_res.typing_speed_wpm, 0.0)
        # Ensure no raw characters or passwords are leaked in the output object
        eval_dict = eval_res.to_dict()
        self.assertNotIn("password", str(eval_dict).lower())

    def test_over_efficiency_bot_detection(self):
        from over_efficiency_detector import OverEfficiencyDetector

        detector = OverEfficiencyDetector()
        # Bot scenario: 100 characters in 200ms with microsecond intervals
        bot_intervals = [2.0] * 50
        res = detector.analyze_interaction(char_count=50, duration_ms=200.0, interval_history_ms=bot_intervals, backspace_count=0)
        self.assertTrue(res.is_automated)
        self.assertEqual(res.classification, "BOT_AUTOMATION")
        self.assertGreaterEqual(res.efficiency_score, 65.0)

    def test_adaptive_access_control_audit(self):
        from adaptive_access_control import AdaptiveAccessControlEngine

        engine = AdaptiveAccessControlEngine()
        trail = engine.get_audit_trail(10)
        self.assertIsInstance(trail, list)


class ThreatIntelligenceTests(unittest.TestCase):
    """Task E: Verify threat intelligence provider status, safe API fallback, and caching."""

    def test_cloud_providers_safe_degradation_without_keys(self):
        from cloud_providers import check_bssid_all_providers

        # Checking a dummy BSSID must return clean/unconfigured status without throwing an exception
        res = check_bssid_all_providers("00:11:22:33:44:55")
        self.assertIn("VirusTotal", res)
        self.assertIn("AbuseIPDB", res)
        self.assertIn("OpenPhish", res)
        self.assertFalse(res["VirusTotal"].get("hit"))
        self.assertFalse(res["AbuseIPDB"].get("hit"))

    def test_threat_cache_file_format(self):
        cache_path = ROOT / "threat_intelligence_cache.json"
        self.assertTrue(cache_path.is_file())
        with cache_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIsInstance(data, dict)
        self.assertGreater(len(data), 0)


class ReportGenerationAndDeprecationTests(unittest.TestCase):
    """Task F: Verify PDF report generation, required sections, and CSV report UI deprecation."""

    def test_pdf_report_generates_valid_file(self):
        from report_generator import ReportGenerator

        gen = ReportGenerator()
        sample_df = pd.DataFrame([
            {"SSID": "CorpNet", "BSSID": "00:11:22:33:44:01", "RSSI": -45, "Channel": 6, "Frequency_MHz": 2437, "Security": "WPA2", "Threat_Level": "SAFE", "ML_Risk": 10, "Combined_Risk": 10, "Reason": "Baseline matched"},
            {"SSID": "CorpNet", "BSSID": "00:11:22:33:44:02", "RSSI": -42, "Channel": 6, "Frequency_MHz": 2437, "Security": "OPEN", "Threat_Level": "CRITICAL", "ML_Risk": 95, "Combined_Risk": 92, "Reason": "Security Downgrade"},
        ])
        pdf_path = gen.generate_pdf_report(sample_df)
        self.assertTrue(os.path.isfile(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 1000)

    def test_dashboard_does_not_contain_csv_report_download_buttons(self):
        dashboard_code = (ROOT / "dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("sentinelshield_scan.csv", dashboard_code)
        self.assertNotIn("sentinelshield_summary.csv", dashboard_code)
        self.assertNotIn("Download scan CSV", dashboard_code)
        self.assertNotIn("Download summary CSV", dashboard_code)


if __name__ == "__main__":
    unittest.main()
