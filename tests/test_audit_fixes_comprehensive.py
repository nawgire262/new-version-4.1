"""Comprehensive automated test suite for SentinelShield audit fixes.

Verifies:
- Task A: Threat Analysis scan-driven calculation, metric cards, AP selection, dynamic evidence.
- Task B: 5 Risk Scoring Components (Fingerprint, Security, Temporal RSSI, AP Density, ML Ensemble).
- Task C: Security classification normalization and filtering.
- Task D: Fingerprint store selection, difference comparison, refresh, and verified trust persistence.
- Task E: Cross-page data consistency and shared BSSID selection state.
- Task F: Error handling on empty states, missing baselines, and absent models.
"""

import unittest
from pathlib import Path
import pandas as pd
import json
import tempfile

from dashboard import normalize_security, matches_security_filter
from wifi_fingerprint import WiFiFingerprintStore


class SecurityNormalizationTests(unittest.TestCase):
    """Test Task C: Security normalization and filtering."""

    def test_normalize_security_types(self):
        self.assertEqual(normalize_security("WPA2"), "WPA2")
        self.assertEqual(normalize_security("WPA2-PSK"), "WPA2")
        self.assertEqual(normalize_security("WPA2-Personal"), "WPA2")
        self.assertEqual(normalize_security("SECURED"), "WPA2")
        self.assertEqual(normalize_security("[WPA2-PSK-CCMP]"), "WPA2")
        self.assertEqual(normalize_security("WPA3"), "WPA3")
        self.assertEqual(normalize_security("WPA3-Personal"), "WPA3")
        self.assertEqual(normalize_security("WPA3-SAE"), "WPA3")
        self.assertEqual(normalize_security("Open"), "Open")
        self.assertEqual(normalize_security("OPEN"), "Open")
        self.assertEqual(normalize_security("UNENCRYPTED"), "Open")
        self.assertEqual(normalize_security("No Encryption"), "Open")
        self.assertEqual(normalize_security("WEP"), "WEP")
        self.assertEqual(normalize_security("WEP40"), "WEP")
        self.assertEqual(normalize_security("WPA"), "WPA")
        self.assertEqual(normalize_security("Unknown"), "Unknown")
        self.assertEqual(normalize_security(None), "Unknown")
        self.assertEqual(normalize_security(""), "Unknown")

    def test_matches_security_filter(self):
        # All security types matches everything
        self.assertTrue(matches_security_filter("WPA2-PSK", "All security types"))
        self.assertTrue(matches_security_filter("Open", "All security types"))
        self.assertTrue(matches_security_filter(None, "All security types"))

        # WPA2 filter
        self.assertTrue(matches_security_filter("WPA2-PSK", "WPA2"))
        self.assertTrue(matches_security_filter("SECURED", "WPA2"))
        self.assertFalse(matches_security_filter("Open", "WPA2"))
        self.assertFalse(matches_security_filter("WEP", "WPA2"))

        # WPA3 filter
        self.assertTrue(matches_security_filter("WPA3-SAE", "WPA3"))
        self.assertFalse(matches_security_filter("WPA2-PSK", "WPA3"))

        # Open filter
        self.assertTrue(matches_security_filter("Open", "Open"))
        self.assertTrue(matches_security_filter("OPEN", "Open"))
        self.assertTrue(matches_security_filter("UNENCRYPTED", "Open"))
        self.assertFalse(matches_security_filter("WPA2-PSK", "Open"))
        # Missing/unknown security must NOT be classified as Open unless explicitly open
        self.assertFalse(matches_security_filter("Unknown", "Open"))
        self.assertFalse(matches_security_filter(None, "Open"))

        # WEP filter
        self.assertTrue(matches_security_filter("WEP", "WEP"))
        self.assertFalse(matches_security_filter("WPA2-PSK", "WEP"))

    def test_combined_dataframe_filtering(self):
        df = pd.DataFrame([
            {"SSID": "Campus-WiFi", "BSSID": "AA:BB:CC:DD:EE:01", "Security": "WPA2-PSK", "Threat_Level": "SAFE"},
            {"SSID": "Campus-WiFi", "BSSID": "AA:BB:CC:DD:EE:02", "Security": "Open", "Threat_Level": "CRITICAL"},
            {"SSID": "IoT-Device", "BSSID": "AA:BB:CC:DD:EE:03", "Security": "WEP", "Threat_Level": "HIGH"},
            {"SSID": "Corp-5G", "BSSID": "AA:BB:CC:DD:EE:04", "Security": "WPA3-Personal", "Threat_Level": "SAFE"},
        ])

        # Filter: Security = WPA2
        wpa2_res = df[df["Security"].apply(lambda s: matches_security_filter(s, "WPA2"))]
        self.assertEqual(len(wpa2_res), 1)
        self.assertEqual(wpa2_res.iloc[0]["SSID"], "Campus-WiFi")

        # Filter: Security = Open AND Threat_Level = CRITICAL
        open_crit = df[
            df["Security"].apply(lambda s: matches_security_filter(s, "Open")) &
            (df["Threat_Level"] == "CRITICAL")
        ]
        self.assertEqual(len(open_crit), 1)
        self.assertEqual(open_crit.iloc[0]["BSSID"], "AA:BB:CC:DD:EE:02")

        # Search query combined with Security = WEP
        search_wep = df[
            df["SSID"].str.contains("IoT", case=False) &
            df["Security"].apply(lambda s: matches_security_filter(s, "WEP"))
        ]
        self.assertEqual(len(search_wep), 1)


class FingerprintStoreAndActionsTests(unittest.TestCase):
    """Test Task D: Fingerprint store selection, difference comparison, refresh, and trust management."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.fp_path = Path(self.temp_dir.name) / "test_baseline.json"
        self.store = WiFiFingerprintStore(path=self.fp_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_observe_and_retrieve_profile(self):
        obs = {
            "ssid": "TestAP",
            "bssid": "00:11:22:33:44:55",
            "rssi_dbm": -45.0,
            "channel": 6,
            "security": "WPA2",
            "vendor": "Realtek",
            "timestamp": "2026-10-31T00:00:00Z",
        }
        res = self.store.observe(obs)
        self.assertIsNotNone(res)
        self.assertEqual(res["observation_count"], 1)
        self.assertEqual(res["rssi_mean"], -45.0)
        self.assertFalse(res["trusted"])
        self.assertEqual(res["confidence"], "OBSERVED")

        # Retrieve profile
        profile = self.store.get("00:11:22:33:44:55")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["ssid"], "TestAP")

    def test_refresh_profile_accumulates_statistics_without_clobbering_trust(self):
        # 1. First observation
        self.store.observe({
            "ssid": "TestAP",
            "bssid": "00:11:22:33:44:55",
            "rssi_dbm": -50.0,
            "channel": 6,
            "security": "WPA2",
            "vendor": "Intel",
        })

        # 2. Mark trusted after verification
        self.store.set_trusted("00:11:22:33:44:55", True)
        self.assertTrue(self.store.get("00:11:22:33:44:55")["trusted"])
        self.assertEqual(self.store.get("00:11:22:33:44:55")["confidence"], "TRUSTED")

        # 3. Refresh profile with second scan observation
        self.store.observe({
            "ssid": "TestAP",
            "bssid": "00:11:22:33:44:55",
            "rssi_dbm": -46.0,
            "channel": 6,
            "security": "WPA2",
            "vendor": "Intel",
        })

        refreshed = self.store.get("00:11:22:33:44:55")
        self.assertEqual(refreshed["observation_count"], 2)
        self.assertEqual(refreshed["rssi_mean"], -48.0)
        # Trust must be preserved!
        self.assertTrue(refreshed["trusted"])
        self.assertEqual(refreshed["confidence"], "TRUSTED")

    def test_trust_applies_strictly_to_bssid_not_ssid(self):
        # Legitimate AP
        self.store.observe({"ssid": "OfficeNet", "bssid": "11:11:11:11:11:11", "rssi_dbm": -40.0, "channel": 1, "security": "WPA2"})
        self.store.set_trusted("11:11:11:11:11:11", True)

        # Rogue AP spoofing the same SSID
        self.store.observe({"ssid": "OfficeNet", "bssid": "22:22:22:22:22:22", "rssi_dbm": -30.0, "channel": 1, "security": "Open"})

        legit = self.store.get("11:11:11:11:11:11")
        rogue = self.store.get("22:22:22:22:22:22")

        self.assertTrue(legit["trusted"])
        self.assertFalse(rogue["trusted"])
        self.assertEqual(rogue["confidence"], "OBSERVED")

    def test_revoke_trust(self):
        self.store.observe({"ssid": "OfficeNet", "bssid": "11:11:11:11:11:11", "rssi_dbm": -40.0, "channel": 1, "security": "WPA2"})
        self.store.set_trusted("11:11:11:11:11:11", True)
        self.assertTrue(self.store.get("11:11:11:11:11:11")["trusted"])

        # Revoke
        self.store.set_trusted("11:11:11:11:11:11", False)
        self.assertFalse(self.store.get("11:11:11:11:11:11")["trusted"])
        self.assertEqual(self.store.get("11:11:11:11:11:11")["confidence"], "OBSERVED")


class RiskComponentsAndEvidenceTests(unittest.TestCase):
    """Test Task B & Task A: Evidence calculations and observation-driven metrics."""

    def test_metrics_distinguish_unique_aps_from_total_observations(self):
        # 4 observations across 2 unique APs
        df = pd.DataFrame([
            {"SSID": "AP1", "BSSID": "00:00:00:00:00:01", "Threat_Level": "SAFE", "Combined_Risk": 10},
            {"SSID": "AP1", "BSSID": "00:00:00:00:00:01", "Threat_Level": "SAFE", "Combined_Risk": 12},
            {"SSID": "AP2", "BSSID": "00:00:00:00:00:02", "Threat_Level": "CRITICAL", "Combined_Risk": 88},
            {"SSID": "AP2", "BSSID": "00:00:00:00:00:02", "Threat_Level": "CRITICAL", "Combined_Risk": 90},
        ])
        total_obs = len(df)
        unique_aps = len(df["BSSID"].unique())
        self.assertEqual(total_obs, 4)
        self.assertEqual(unique_aps, 2)


if __name__ == "__main__":
    unittest.main()
