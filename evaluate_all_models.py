"""
evaluate_all_models.py
Empirical evaluation of SentinelShield's actual saved models and hybrid ensemble.
Scores on training_dataset.csv (with and without synthetic placeholders)
and logs per-model execution latency, confusion matrices, and metrics.
"""

import time
import pickle
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, average_precision_score
)
from dataset_prep import load_clean_dataset

SECURITY_CODE = {"OPEN": 0, "WEP": 1, "WPA2": 2, "WPA3": 3}

def extract_features(df):
    sec = df["Security"].map(lambda s: SECURITY_CODE.get(str(s).upper(), 2))
    return np.column_stack([df["RSSI"], df["Channel"], sec, df["AP_Count"], df["Signal_Var"]]).astype(float)

def evaluate_models():
    base_dir = Path(__file__).resolve().parent
    
    # 1. Load dataset
    df, audit = load_clean_dataset(base_dir / "training_dataset.csv")
    print(f"=== Dataset Loaded ===")
    print(f"Total Rows: {len(df)}")
    print(f"Audit: {audit}")
    
    X_raw = extract_features(df)
    y_true = (df["Label"].astype(str) == "Fake").to_numpy(dtype=int)
    
    # 2. Load trained models & scalers
    with open(base_dir / "rf_model.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(base_dir / "knn_model.pkl", "rb") as f:
        knn = pickle.load(f)
    with open(base_dir / "iso_model.pkl", "rb") as f:
        iso = pickle.load(f)
    with open(base_dir / "meta_model.pkl", "rb") as f:
        meta = pickle.load(f)
    with open(base_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    with open(base_dir / "meta_scaler.pkl", "rb") as f:
        meta_scaler = pickle.load(f)
    with open(base_dir / "le_label.pkl", "rb") as f:
        le_label = pickle.load(f)
        
    Xs = scaler.transform(X_raw)
    
    # Get index for 'Fake'
    # In le_label: classes_ is ['Fake', 'Legit'] -> 'Fake' is index 0
    classes = list(le_label.classes_)
    fake_idx = classes.index("Fake")
    print(f"Label classes: {classes}, 'Fake' class index: {fake_idx}")
    
    # Evaluate RF
    t0 = time.perf_counter()
    rf_proba = rf.predict_proba(Xs)[:, fake_idx]
    rf_pred = (rf_proba >= 0.5).astype(int)
    rf_lat = (time.perf_counter() - t0) / len(df) * 1000  # ms per sample
    
    # Evaluate KNN
    t0 = time.perf_counter()
    knn_proba = knn.predict_proba(Xs)[:, fake_idx]
    knn_pred = (knn_proba >= 0.5).astype(int)
    knn_lat = (time.perf_counter() - t0) / len(df) * 1000
    
    # Evaluate Isolation Forest
    t0 = time.perf_counter()
    iso_score = -iso.decision_function(Xs)
    # Calibrate IF threshold on 95th percentile of normal (Legit)
    iso_thr = np.quantile(iso_score[y_true == 0], 0.95)
    iso_pred = (iso_score > iso_thr).astype(int)
    iso_lat = (time.perf_counter() - t0) / len(df) * 1000
    
    # Evaluate RF + KNN (Average)
    t0 = time.perf_counter()
    rf_knn_proba = (rf_proba + knn_proba) / 2.0
    rf_knn_pred = (rf_knn_proba >= 0.5).astype(int)
    rf_knn_lat = (time.perf_counter() - t0) / len(df) * 1000
    
    # Evaluate Meta-Model / Hybrid Stack
    t0 = time.perf_counter()
    # Features trained for meta-model: rf_proba, knn_proba, iso_score
    meta_feats = np.column_stack([rf_proba, knn_proba, iso_score])
    meta_feats_s = meta_scaler.transform(meta_feats)
    meta_proba = meta.predict_proba(meta_feats_s)[:, fake_idx]
    meta_pred = (meta_proba >= 0.5).astype(int)
    hybrid_lat = (time.perf_counter() - t0) / len(df) * 1000 + rf_lat + knn_lat + iso_lat
    
    models = {
        "Random Forest": (rf_proba, rf_pred, rf_lat),
        "KNN": (knn_proba, knn_pred, knn_lat),
        "Isolation Forest": (iso_score, iso_pred, iso_lat),
        "RF + KNN (Ensemble)": (rf_knn_proba, rf_knn_pred, rf_knn_lat),
        "SentinelShield Hybrid Stack": (meta_proba, meta_pred, hybrid_lat)
    }
    
    out_table = []
    cm_dict = {}
    
    for name, (score, pred, lat) in models.items():
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        acc = accuracy_score(y_true, pred)
        prec = precision_score(y_true, pred, zero_division=0)
        rec = recall_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        auc = roc_auc_score(y_true, score) if len(np.unique(y_true)) == 2 else 0.0
        
        cm_dict[name] = {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)}
        out_table.append({
            "Model": name,
            "Accuracy": round(acc * 100, 2),
            "Precision": round(prec * 100, 2),
            "Recall": round(rec * 100, 2),
            "F1_Score": round(f1 * 100, 2),
            "FPR": round(fpr * 100, 2),
            "ROC_AUC": round(auc, 4),
            "Latency_ms_per_AP": round(lat, 3)
        })
        
    res_df = pd.DataFrame(out_table)
    print("\n=== Model Performance on training_dataset.csv ===")
    print(res_df.to_string(index=False))
    
    print("\n=== Confusion Matrices ===")
    for m, cm in cm_dict.items():
        print(f"{m}: TP={cm['TP']}, FP={cm['FP']}, TN={cm['TN']}, FN={cm['FN']}")
        
    out_dir = base_dir / "research_evaluation_output"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    res_df.to_csv(out_dir / "model_benchmark_results.csv", index=False)
    with open(out_dir / "confusion_matrices.json", "w") as f:
        json.dump(cm_dict, f, indent=2)
        
    return res_df, cm_dict

if __name__ == "__main__":
    evaluate_models()

