"""
archive_all_research_papers.py
==============================
Archives all 10 research papers with clean, academic canonical filenames in:
1. Brain directory: C:\\Users\\OM\\.gemini\\antigravity\\brain\\442e5ece-4ce7-4b94-a44b-d52db3a3ecb0\\research_papers\\
2. Project directory: C:\\Users\\OM\\Downloads\\SentinelShield-WiFi-Threat-Detection-Latest\\SentinelShield-WiFi-Threat-Detection\\research_papers\\
Generates a structured metadata JSON and an academic index markdown file.
"""

import shutil
import json
from pathlib import Path

BRAIN_DIR = Path(r"C:\Users\OM\.gemini\antigravity\brain\442e5ece-4ce7-4b94-a44b-d52db3a3ecb0")
USER_UPLOADS = BRAIN_DIR / ".user_uploaded"
BRAIN_PAPERS_DIR = BRAIN_DIR / "research_papers"
PROJECT_PAPERS_DIR = Path(r"C:\Users\OM\Downloads\SentinelShield-WiFi-Threat-Detection-Latest\SentinelShield-WiFi-Threat-Detection\research_papers")

BRAIN_PAPERS_DIR.mkdir(parents=True, exist_ok=True)
PROJECT_PAPERS_DIR.mkdir(parents=True, exist_ok=True)

PAPERS_MAPPING = [
    {
        "id": "Paper_01",
        "source_file": "media_1792960863212_4fddd0a1.pdf",
        "target_filename": "Paper_01_Ahmad_2025_Lightweight_CNN_WiFi_IDS_2D_Traffic_Purdue_NW.pdf",
        "title": "Lightweight CNN-Based Wi-Fi Intrusion Detection Using 2D Traffic Representations",
        "authors": "Rayed Suhail Ahmad, Rehan Ahmad, Quamar Niyaz",
        "affiliation": "Purdue University Northwest, Hammond, IN, USA",
        "venue": "arXiv preprint arXiv:2510.11898 [cs.CR]",
        "year": 2025,
        "dataset": "AWID3 (1,046,692 test records)",
        "method": "2D-2L CNN + Gramian Angular Field (GAF) Transformation",
        "key_metrics": {"accuracy": "99.93%", "f1_score": "99.73%", "latency": "48 us/record"},
        "relevance": "Validates SentinelShield link-layer feature selection and ultra-low latency frame classification."
    },
    {
        "id": "Paper_02",
        "source_file": "media_1792960862837_4714eff9.pdf",
        "target_filename": "Paper_02_Bacztub_2025_Stealth_Evasion_Rogue_AP_Attacks_Purdue.pdf",
        "title": "Stealth and Evasion in Rogue AP Attacks: An Analysis of Modern Detection and Bypass Techniques",
        "authors": "Kaleb Bacztub, Braden Vester, Matteo Hodge, Liulseged Abate",
        "affiliation": "Purdue University Indianapolis, IN, USA",
        "venue": "arXiv preprint arXiv:2512.10470 [cs.CR]",
        "year": 2025,
        "dataset": "Virtualized VMware Lab + Alfa AWUS036ACH (500 events)",
        "method": "Wifipumpkin3 captive portal + Suricata NIDS Layer-3 evaluation",
        "key_metrics": {"suricata_detection_rate": "0.0%", "attacker_harvest": "100%"},
        "relevance": "Demonstrates why traditional NIDS (Suricata) fail against Layer-2 Evil Twin attacks, proving the critical need for SentinelShield's Layer-2 WIDS monitor."
    },
    {
        "id": "Paper_03",
        "source_file": "media_1792961462622_24e693b4.pdf",
        "target_filename": "Paper_03_Banakh_2024_Data_Mining_Evil_Twin_Identification_WiFi_MDPI.pdf",
        "title": "Data Mining Approach for Evil Twin Attack Identification in Wi-Fi Networks",
        "authors": "Roman Banakh, Elena Nyemkova, Connie Justice (Purdue), Andrian Piskozub, Yuriy Lakh",
        "affiliation": "Lviv Polytechnic National University / Purdue University Indianapolis",
        "venue": "Data (MDPI), vol. 9, no. 10, art. 119",
        "year": 2024,
        "dataset": "UniFi AP-AC-LR + >17.3M generative signal combinations (3.4M test records)",
        "method": "Generative Signal Power Algorithm + KNN (K=3, Minkowski p=2)",
        "key_metrics": {"accuracy": "100.0%", "precision": "100.0%", "f1_score": "100.0%", "fpr": "0.0%"},
        "relevance": "Direct mathematical basis for SentinelShield's KNN classifier (knn_model.pkl) and signal feature divergence analysis."
    },
    {
        "id": "Paper_04",
        "source_file": "media_1792961458943_cf663224.pdf",
        "target_filename": "Paper_04_Sadhana_2026_Explainable_Deep_Learning_IDS_WSN_Streamlit.pdf",
        "title": "Explainable Deep Learning-Based Intrusion Detection System for Wireless Sensor Networks with Real-Time Edge Deployment",
        "authors": "Chilka Sadhana, Mr K Appala Raju",
        "affiliation": "Andhra Loyola Institute of Engineering and Technology, Vijayawada, India",
        "venue": "IJARCCE, vol. 15, no. 4, pp. 407-413",
        "year": 2026,
        "dataset": "AWID-CLS-R Balanced Undersampled (45,265 test records)",
        "method": "1D-CNN + SHAP GradientExplainer + Streamlit Real-Time Dashboard",
        "key_metrics": {"accuracy": "99.03%", "macro_f1": "0.992", "latency": "500 records in <3s"},
        "relevance": "Direct architectural parallel to SentinelShield's Streamlit dashboard (dashboard.py) and feature importance attribution (xai_explain.py)."
    },
    {
        "id": "Paper_05",
        "source_file": "media_1792960260209_ac455133.pdf",
        "target_filename": "Paper_05_Chen_2023_Anomaly_Detection_WSN_Improved_Isolation_Forest.pdf",
        "title": "An Anomaly Detection Method for Wireless Sensor Networks Based on the Improved Isolation Forest",
        "authors": "Junxiang Chen, Jilin Zhang, Ruixiang Qian, Junfeng Yuan, Yongjian Ren",
        "affiliation": "Hangzhou Dianzi University, China",
        "venue": "Applied Sciences (MDPI), vol. 13, no. 2, art. 702",
        "year": 2023,
        "dataset": "Campus-CRS University Data Center Telemetry (27,066 records)",
        "method": "BS-iForest: Box Plot Subsampling + Tree Fitness Pruning",
        "key_metrics": {"accuracy": "98.96%", "auc": "0.9890", "f1_score": "95.0%"},
        "relevance": "Validates SentinelShield's Isolation Forest anomaly detector (iso_model.pkl) for unsupervised zero-day attack identification."
    },
    {
        "id": "Paper_06",
        "source_file": "media_1792960259633_86684c80.pdf",
        "target_filename": "Paper_06_Liu_2024_Position_Based_Rogue_AP_Detection_RAIM.pdf",
        "title": "Position-based Rogue Access Point Detection",
        "authors": "Wenjie Liu, Panos Papadimitratos",
        "affiliation": "KTH Royal Institute of Technology, Stockholm, Sweden",
        "venue": "arXiv preprint arXiv:2406.01927 [cs.CR]",
        "year": 2024,
        "dataset": "Shopping Mall Wi-Fi RSSI Dataset (170x90m, 8 APs/point, WHUWearTrack)",
        "method": "Gaussian Mixture RAIM + 3-sigma Subset Exclusion Majority Voting",
        "key_metrics": {"accuracy": "96.0%", "tpr": "67-97%", "fpr": "1-10%"},
        "relevance": "Direct mathematical adaptation in SentinelShield's AP distance-consistency engine (rssi_raim.py)."
    },
    {
        "id": "Paper_07",
        "source_file": "media_1792960259748_e2895a74.pdf",
        "target_filename": "Paper_07_Daldoul_2022_Robust_Certificate_Management_System_RCMS.pdf",
        "title": "A Robust Certificate Management System to Prevent Evil Twin Attacks in IEEE 802.11 Networks",
        "authors": "Yousri Daldoul",
        "affiliation": "University of Monastir, Tunisia",
        "venue": "Faculty of Sciences of Monastir Research Report",
        "year": 2022,
        "dataset": "Eduroam / WPA2-Enterprise 802.1X Network Analysis",
        "method": "RCMS 48-bit HMAC-SHA256 Root CA Verification Code Pinning",
        "key_metrics": {"rogue_mitigation": "100%", "mitigates_eduroam_vulnerability": "61%"},
        "relevance": "Direct foundation for SentinelShield's security downgrade detection and fingerprint certificate verification."
    },
    {
        "id": "Paper_08",
        "source_file": "media_1792961459145_a453b7a5.pdf",
        "target_filename": "Paper_08_Indira_2020_Hybrid_IDS_SDWSN_Random_Forest.pdf",
        "title": "A Hybrid Intrusion Detection System for SDWSN using Random Forest (RF) Machine Learning Approach",
        "authors": "Indira K, Sakthi U",
        "affiliation": "Sathyabama Institute of Science and Technology / St. Joseph's Institute, Chennai, India",
        "venue": "IJACSA, vol. 11, no. 2, pp. 275-284",
        "year": 2020,
        "dataset": "NSL-KDD / KDD Cup 1999 (25,000 records)",
        "method": "Salp Swarm Optimization (SSO) + Random Forest Classifier",
        "key_metrics": {"accuracy": "96.5%", "delay_reduction": "75% less delay than KNN", "delivery_ratio": "0.95"},
        "relevance": "Validates SentinelShield's Random Forest classifier (rf_model.pkl) and ensemble stacking."
    },
    {
        "id": "Paper_09",
        "source_file": "media_1792960259848_67aae328.pdf",
        "target_filename": "Paper_09_Banakh_2023_Evil_Twin_Detection_KNN_Model.pdf",
        "title": "Devising a method for detecting 'Evil Twin' attacks on IEEE 802.11 networks with KNN classification model",
        "authors": "Roman Banakh, Andrian Piskozub, Ivan Opirskyy",
        "affiliation": "Lviv Polytechnic National University, Ukraine",
        "venue": "Eastern-European Journal of Enterprise Technologies, vol. 3, no. 9(123), pp. 20-32",
        "year": 2023,
        "dataset": "Raspberry Pi 4 + Alfa AWUS036NHA (35,189 records, 7,038 test samples)",
        "method": "K-Nearest Neighbors (K=3) on Beacon RSSI metrics (min, max, avg, mode)",
        "key_metrics": {"accuracy": "100.0%", "precision": "100.0%", "recall": "100.0%", "f1_score": "100.0%"},
        "relevance": "Foundational proof of beacon RSSI feature engineering without frame count metric ('np')."
    },
    {
        "id": "Paper_10",
        "source_file": "media_1792777277046_fb7ba4e1.pdf",
        "target_filename": "Paper_10_SentinelShield_Dashboard_Design_and_Screen_Specification.pdf",
        "title": "SentinelShield: Security Operations Console - Multi-View Specification and UI Archetype",
        "authors": "SentinelShield Development Team",
        "affiliation": "Academic MCA Dissertation Project",
        "venue": "Technical Specification Document",
        "year": 2026,
        "dataset": "10 Operational Pages (Overview, Live Scan, Networks, Threat Analysis, ML Detection, etc.)",
        "method": "Real-time SOC interface with radar telemetry and automated report generation",
        "key_metrics": {"views_specified": 10, "scan_modes": "Quick + Adaptive + Continuous"},
        "relevance": "Primary visual archetype and dashboard specification for the SentinelShield frontend."
    }
]

print("=== Archiving Research Papers to Brain and Project Directories ===")

for p in PAPERS_MAPPING:
    src = USER_UPLOADS / p["source_file"]
    if src.exists():
        # Copy to brain papers directory
        dst_brain = BRAIN_PAPERS_DIR / p["target_filename"]
        shutil.copy2(src, dst_brain)
        
        # Copy to project papers directory
        dst_project = PROJECT_PAPERS_DIR / p["target_filename"]
        shutil.copy2(src, dst_project)
        print(f"[+] Archived {p['id']}: {p['target_filename']} ({src.stat().st_size} bytes)")
    else:
        print(f"[-] Source missing for {p['id']}: {p['source_file']}")

# Save Metadata JSON in both locations
meta_json_brain = BRAIN_PAPERS_DIR / "research_papers_metadata.json"
meta_json_project = PROJECT_PAPERS_DIR / "research_papers_metadata.json"

with open(meta_json_brain, "w", encoding="utf-8") as f:
    json.dump(PAPERS_MAPPING, f, indent=2)

with open(meta_json_project, "w", encoding="utf-8") as f:
    json.dump(PAPERS_MAPPING, f, indent=2)

print(f"\n[+] Saved Metadata JSON: {meta_json_brain}")
print(f"[+] Saved Metadata JSON: {meta_json_project}")

# Generate Markdown Index
index_md = """# SentinelShield: Research Papers Archive & Academic Library
**Archive Location (Brain):** `C:\\Users\\OM\\.gemini\\antigravity\\brain\\442e5ece-4ce7-4b94-a44b-d52db3a3ecb0\\research_papers\\`  
**Archive Location (Project):** `C:\\Users\\OM\\Downloads\\SentinelShield-WiFi-Threat-Detection-Latest\\SentinelShield-WiFi-Threat-Detection\\research_papers\\`  
**Purpose:** Permanent academic preservation of all reference literature for MCA dissertation, viva defense, and future research iterations.

---

## Master Catalog of Archived Papers

| ID | Canonical Filename | Primary Authors | Year | Venue | Core Methodology | Key Contribution to SentinelShield |
|---|---|---|:---:|---|---|---|
| **01** | `Paper_01_Ahmad_2025_Lightweight_CNN_WiFi_IDS_2D_Traffic_Purdue_NW.pdf` | Ahmad, Ahmad, Niyaz | 2025 | arXiv:2510.11898 | 2D-CNN + GAF matrix on 16 link-layer features | Validates link-layer feature selection & 48µs inference speed. |
| **02** | `Paper_02_Bacztub_2025_Stealth_Evasion_Rogue_AP_Attacks_Purdue.pdf` | Bacztub, Vester, Hodge, Abate | 2025 | arXiv:2512.10470 | Wifipumpkin3 vs Suricata NIDS | Explains why traditional NIDS fail (0% detection) at Layer 2. |
| **03** | `Paper_03_Banakh_2024_Data_Mining_Evil_Twin_Identification_WiFi_MDPI.pdf` | Banakh, Nyemkova, Justice (Purdue), Piskozub, Lakh | 2024 | MDPI Data, 9(10) | Generative RSSI algorithm + KNN ($K=3$) | Direct basis for `knn_model.pkl` and signal mode divergence. |
| **04** | `Paper_04_Sadhana_2026_Explainable_Deep_Learning_IDS_WSN_Streamlit.pdf` | Sadhana & Raju | 2026 | IJARCCE, 15(4) | 1D-CNN + SHAP + Streamlit Edge UI | Architectural parallel to SentinelShield Streamlit dashboard & XAI. |
| **05** | `Paper_05_Chen_2023_Anomaly_Detection_WSN_Improved_Isolation_Forest.pdf` | Chen, Zhang, Qian, Yuan, Ren | 2023 | MDPI Appl. Sci. | BS-iForest: Box plot tree pruning | Direct basis for SentinelShield Isolation Forest (`iso_model.pkl`). |
| **06** | `Paper_06_Liu_2024_Position_Based_Rogue_AP_Detection_RAIM.pdf` | Liu & Papadimitratos | 2024 | arXiv:2406.01927 | Gaussian Mixture RAIM subset voting | Direct mathematical adaptation in `rssi_raim.py`. |
| **07** | `Paper_07_Daldoul_2022_Robust_Certificate_Management_System_RCMS.pdf` | Yousri Daldoul | 2022 | Univ. Monastir | HMAC-SHA256 48-bit Root CA Pinning | Foundation for security downgrade rules in `wifi_fingerprint.py`. |
| **08** | `Paper_08_Indira_2020_Hybrid_IDS_SDWSN_Random_Forest.pdf` | Indira & Sakthi | 2020 | IJACSA, 11(2) | Salp Swarm Optimization + Random Forest | Justifies pairing Random Forest (`rf_model.pkl`) with KNN. |
| **09** | `Paper_09_Banakh_2023_Evil_Twin_Detection_KNN_Model.pdf` | Banakh, Piskozub, Opirskyy | 2023 | EEJET, 3/9(123) | KNN ($K=3$) on Beacon RSSI metrics | Proves beacon signal strength is a unique physical fingerprint. |
| **10** | `Paper_10_SentinelShield_Dashboard_Design_and_Screen_Specification.pdf` | SentinelShield Team | 2026 | Technical Spec | 10-view SOC analyst interface | UI archetype and layout specification for `dashboard.py`. |

---
"""

(BRAIN_PAPERS_DIR / "RESEARCH_PAPERS_ARCHIVE_INDEX.md").write_text(index_md, encoding="utf-8")
(PROJECT_PAPERS_DIR / "RESEARCH_PAPERS_ARCHIVE_INDEX.md").write_text(index_md, encoding="utf-8")
print("[+] Generated RESEARCH_PAPERS_ARCHIVE_INDEX.md in brain and project repositories!")

