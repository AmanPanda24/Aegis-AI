#!/usr/bin/env python3
import os
import sys
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.processing.feature_extraction import FeatureExtractor

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

MODELS_DIR = "./models"
DATA_DIR = "./data"

def ensure_dirs():
    Path(MODELS_DIR).mkdir(parents=True, exist_ok=True)
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

FEATURE_COUNT = len(FeatureExtractor().feature_names)
FEATURE_NAMES_NO_ENTROPY = [f for f in FeatureExtractor().feature_names if f != "payload_entropy_mean"]

def generate_synthetic_data(n_samples=10000, n_features=FEATURE_COUNT):
    print("[TRAIN] Generating synthetic training data...")
    np.random.seed(42)

    n_normal = int(n_samples * 0.7)
    X_normal = np.random.randn(n_normal, n_features) * 0.5 + 2

    n_dos = int(n_samples * 0.1)
    X_dos = np.random.randn(n_dos, n_features) * 0.3 + 5
    X_dos[:, 0] = np.random.exponential(2, n_dos)
    X_dos[:, 9] = np.random.exponential(10000, n_dos)

    n_scan = int(n_samples * 0.05)
    X_scan = np.random.randn(n_scan, n_features) * 0.2 + 1
    X_scan[:, 1] = np.random.poisson(50, n_scan)
    X_scan[:, 2] = np.random.poisson(2, n_scan)

    n_brute = int(n_samples * 0.05)
    X_brute = np.random.randn(n_brute, n_features) * 0.4 + 2
    X_brute[:, 25] = np.random.poisson(30, n_brute)
    X_brute[:, 3] = np.random.exponential(500, n_brute)

    n_ddos = int(n_samples * 0.05)
    X_ddos = np.random.randn(n_ddos, n_features) * 0.5 + 4
    X_ddos[:, 9] = np.random.exponential(50000, n_ddos)

    n_web = int(n_samples * 0.03)
    X_web = np.random.randn(n_web, n_features) * 0.3 + 2
    X_web[:, 50] = np.random.uniform(7.5, 8.0, n_web)

    n_bot = int(n_samples * 0.02)
    X_bot = np.random.randn(n_bot, n_features) * 0.2 + 1.5

    X = np.vstack([X_normal, X_dos, X_scan, X_brute, X_ddos, X_web, X_bot])
    y = np.array(
        ["BENIGN"] * n_normal +
        ["DoS"] * n_dos +
        ["PortScan"] * n_scan +
        ["BruteForce"] * n_brute +
        ["DDoS"] * n_ddos +
        ["WebAttack"] * n_web +
        ["Bot"] * n_bot
    )

    indices = np.random.permutation(len(X))
    return X[indices], y[indices]

# ---------------------------------------------------------------------------
# Column maps: three independent CICFlowMeter exports (CIC-IDS2017,
# CSE-CIC-IDS2018, and CIC-Darknet2020) each use slightly different header
# spellings/abbreviations for the same underlying flow features. Rather than
# a fuzzy/heuristic matcher (risky for a security-relevant model - a silent
# mis-map here means the model is trained on the wrong meaning of a column),
# each dataset gets its own explicit, hand-verified map onto the exact
# feature names/order src/processing/feature_extraction.py produces at
# inference time. None of these three datasets captures payload bytes
# (they're flow-level exports), so `payload_entropy_mean` is filled with 0.0
# for all of them.
# ---------------------------------------------------------------------------

CICIDS2017_COLUMN_MAP = {
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_fwd_bytes",
    "Total Length of Bwd Packets": "total_bwd_bytes",
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Fwd Packet Length Std": "fwd_packet_length_std",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Bwd Packet Length Std": "bwd_packet_length_std",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Length": "fwd_header_length",
    "Bwd Header Length": "bwd_header_length",
    "Min Packet Length": "min_packet_length",
    "Max Packet Length": "max_packet_length",
    "Packet Length Mean": "packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "Packet Length Variance": "packet_length_variance",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "URG Flag Count": "urg_flag_count",
    "ECE Flag Count": "ece_flag_count",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "avg_packet_size",
    "Avg Fwd Segment Size": "avg_fwd_segment_size",
    "Avg Bwd Segment Size": "avg_bwd_segment_size",
    "Fwd Header Length.1": "fwd_header_length2",  # CSV has this column twice; pandas renames the dup with .1
    "Subflow Fwd Packets": "subflow_fwd_packets",
    "Subflow Fwd Bytes": "subflow_fwd_bytes",
    "Subflow Bwd Packets": "subflow_bwd_packets",
    "Subflow Bwd Bytes": "subflow_bwd_bytes",
    "Init_Win_bytes_forward": "init_win_bytes_forward",
    "Init_Win_bytes_backward": "init_win_bytes_backward",
    "act_data_pkt_fwd": "act_data_pkt_forward",
    "min_seg_size_forward": "min_seg_size_forward",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}

CICIDS2018_COLUMN_MAP = {
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "total_fwd_packets",
    "Tot Bwd Pkts": "total_bwd_packets",
    "TotLen Fwd Pkts": "total_fwd_bytes",
    "TotLen Bwd Pkts": "total_bwd_bytes",
    "Fwd Pkt Len Mean": "fwd_packet_length_mean",
    "Fwd Pkt Len Std": "fwd_packet_length_std",
    "Bwd Pkt Len Mean": "bwd_packet_length_mean",
    "Bwd Pkt Len Std": "bwd_packet_length_std",
    "Flow Byts/s": "flow_bytes_per_sec",
    "Flow Pkts/s": "flow_packets_per_sec",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Len": "fwd_header_length",
    "Bwd Header Len": "bwd_header_length",
    "Pkt Len Min": "min_packet_length",
    "Pkt Len Max": "max_packet_length",
    "Pkt Len Mean": "packet_length_mean",
    "Pkt Len Std": "packet_length_std",
    "Pkt Len Var": "packet_length_variance",
    "FIN Flag Cnt": "fin_flag_count",
    "SYN Flag Cnt": "syn_flag_count",
    "RST Flag Cnt": "rst_flag_count",
    "PSH Flag Cnt": "psh_flag_count",
    "ACK Flag Cnt": "ack_flag_count",
    "URG Flag Cnt": "urg_flag_count",
    "ECE Flag Cnt": "ece_flag_count",
    "Down/Up Ratio": "down_up_ratio",
    "Pkt Size Avg": "avg_packet_size",
    "Fwd Seg Size Avg": "avg_fwd_segment_size",
    "Bwd Seg Size Avg": "avg_bwd_segment_size",
    "Subflow Fwd Pkts": "subflow_fwd_packets",
    "Subflow Fwd Byts": "subflow_fwd_bytes",
    "Subflow Bwd Pkts": "subflow_bwd_packets",
    "Subflow Bwd Byts": "subflow_bwd_bytes",
    "Init Fwd Win Byts": "init_win_bytes_forward",
    "Init Bwd Win Byts": "init_win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_forward",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}

DARKNET2020_COLUMN_MAP = {
    "Flow Duration": "flow_duration",
    "Total Fwd Packet": "total_fwd_packets",
    "Total Bwd packets": "total_bwd_packets",
    "Total Length of Fwd Packet": "total_fwd_bytes",
    "Total Length of Bwd Packet": "total_bwd_bytes",
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Fwd Packet Length Std": "fwd_packet_length_std",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Bwd Packet Length Std": "bwd_packet_length_std",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Length": "fwd_header_length",
    "Bwd Header Length": "bwd_header_length",
    "Packet Length Min": "min_packet_length",
    "Packet Length Max": "max_packet_length",
    "Packet Length Mean": "packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "Packet Length Variance": "packet_length_variance",
    "FIN Flag Count": "fin_flag_count",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "URG Flag Count": "urg_flag_count",
    "ECE Flag Count": "ece_flag_count",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "avg_packet_size",
    "Fwd Segment Size Avg": "avg_fwd_segment_size",
    "Bwd Segment Size Avg": "avg_bwd_segment_size",
    "Subflow Fwd Packets": "subflow_fwd_packets",
    "Subflow Fwd Bytes": "subflow_fwd_bytes",
    "Subflow Bwd Packets": "subflow_bwd_packets",
    "Subflow Bwd Bytes": "subflow_bwd_bytes",
    "FWD Init Win Bytes": "init_win_bytes_forward",
    "Bwd Init Win Bytes": "init_win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_forward",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}


def categorize_cicids2017(raw_label):
    """Collapses CIC-IDS2017's fine-grained attack labels onto the shared
    taxonomy. Heartbleed is extremely rare (11 rows total) and is a
    memory-disclosure exploit rather than a denial-of-service, so it's
    grouped with Infiltration rather than DoS."""
    label = str(raw_label).strip()
    if label == "BENIGN":
        return "BENIGN"
    if label == "Heartbleed":
        return "Infiltration"
    if label.startswith("DoS"):
        return "DoS"
    if label == "DDoS":
        return "DDoS"
    if label == "PortScan":
        return "PortScan"
    if label in ("FTP-Patator", "SSH-Patator"):
        return "BruteForce"
    if label.startswith("Web Attack"):
        return "WebAttack"
    if label == "Bot":
        return "Bot"
    if label == "Infiltration":
        return "Infiltration"
    return None


def categorize_cicids2018(raw_label):
    """CSE-CIC-IDS2018 uses a differently-worded label set than 2017 for
    the same attack families (e.g. 'SSH-Bruteforce' vs 'SSH-Patator');
    this maps the known 2018 label vocabulary onto the same shared
    taxonomy used for 2017, so both datasets contribute to the same
    classes instead of fragmenting into near-duplicate categories."""
    label = str(raw_label).strip()
    if label == "Benign":
        return "BENIGN"
    if "bruteforce" in label.lower() or "brute-force" in label.lower():
        return "BruteForce"
    if label.startswith("DoS attacks"):
        return "DoS"
    if label.startswith("DDOS attack") or label.startswith("DDoS attacks"):
        return "DDoS"
    if label == "Bot":
        return "Bot"
    if label in ("Infilteration", "Infiltration"):
        return "Infiltration"
    if label.startswith("Brute Force") or label == "SQL Injection":
        return "WebAttack"
    return None


def categorize_darknet2020(raw_label):
    """CIC-Darknet2020 isn't an attack dataset - it's Tor/VPN traffic
    fingerprinting. Non-anonymized traffic is treated as BENIGN; Tor/VPN
    traffic is labeled as a new 'TOR_VPN' class, since detecting
    anonymization-tool usage on a monitored network is a legitimate,
    distinct signal worth surfacing (possible exfiltration/policy-evasion
    indicator) even though it isn't an 'attack' in the same sense as the
    other classes. Rows with a corrupted/unexpected label (a handful of
    malformed rows exist in the published CSV) are dropped by returning
    None here."""
    label = str(raw_label).strip()
    if label in ("Non-Tor", "NonVPN"):
        return "BENIGN"
    if label in ("Tor", "VPN"):
        return "TOR_VPN"
    return None


def _strip_cols(df):
    df.columns = [c.strip() for c in df.columns]
    return df


def load_flow_csv(csv_path, column_map, label_column, categorize_fn, max_per_class=60000, seed=42):
    """Generic loader shared by all three CICFlowMeter-derived datasets.
    Reads only the columns needed (by exact name match against column_map,
    tolerant of incidental leading/trailing whitespace CICFlowMeter exports
    are known to have), renames them onto the live feature schema, maps the
    dataset's own label vocabulary onto the shared taxonomy via
    categorize_fn, drops rows whose label doesn't map to anything known,
    and optionally caps rows per class so a single CPU core can train on
    everything in reasonable time.

    Reads in chunks and downcasts to float32 as each chunk is read, rather
    than loading the whole file as float64 in one pd.read_csv call. The
    CICFlowMeter CSVs in this dataset run 50-225MB each; a naive full-file
    float64 read peaks at well over the file's on-disk size once pandas'
    parsing overhead is included, which is enough to OOM-kill the process
    on a memory-constrained host (observed directly: this cost an in-
    progress training run on a 3.9GB-RAM instance). Chunked reading with
    per-chunk downcasting keeps peak memory roughly bounded by chunk size
    regardless of total file size.
    """
    header = pd.read_csv(csv_path, nrows=0).columns.tolist()
    norm_to_orig = {c.strip(): c for c in header}

    wanted_orig = [norm_to_orig[k] for k in column_map if k in norm_to_orig]
    missing = [k for k in column_map if k not in norm_to_orig]
    if missing:
        name = csv_path.name if hasattr(csv_path, "name") else csv_path
        print(f"[TRAIN]   WARNING: {name} is missing expected columns: {missing}")

    label_orig = norm_to_orig.get(label_column)
    if label_orig is None:
        raise ValueError(f"Label column '{label_column}' not found in {csv_path}")

    usecols = wanted_orig + [label_orig]
    chunk_parts = []
    for chunk in pd.read_csv(csv_path, usecols=usecols, low_memory=False, chunksize=200_000):
        _strip_cols(chunk)
        chunk = chunk.rename(columns=column_map)

        if "fwd_header_length" in chunk.columns and "fwd_header_length2" not in chunk.columns:
            chunk["fwd_header_length2"] = chunk["fwd_header_length"]

        chunk["category"] = chunk[label_column].map(categorize_fn)
        chunk = chunk[chunk["category"].notna()].drop(columns=[label_column])
        chunk = chunk.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Downcast numeric columns to float32 per-chunk instead of after
        # concatenating everything - this is the actual memory saving,
        # not just a final cast.
        numeric_cols = [c for c in chunk.columns if c != "category"]
        chunk[numeric_cols] = chunk[numeric_cols].astype(np.float32)

        # Cap per class WITHIN each chunk too, so a single huge chunk from
        # a heavily-skewed file (e.g. mostly BENIGN) can't blow past
        # max_per_class before the final cap below runs.
        if max_per_class is not None:
            parts = [g.sample(n=min(len(g), max_per_class), random_state=seed)
                      for _, g in chunk.groupby("category")]
            chunk = pd.concat(parts, ignore_index=True) if parts else chunk

        chunk_parts.append(chunk)

    df = pd.concat(chunk_parts, ignore_index=True) if chunk_parts else pd.DataFrame(columns=["category"])

    if max_per_class is not None and not df.empty:
        parts = []
        for cat, g in df.groupby("category"):
            parts.append(g.sample(n=min(len(g), max_per_class), random_state=seed))
        df = pd.concat(parts, ignore_index=True)

    y = df["category"].values
    missing_features = [f for f in FEATURE_NAMES_NO_ENTROPY if f not in df.columns]
    for f in missing_features:
        df[f] = 0.0
    X = df[FEATURE_NAMES_NO_ENTROPY].values.astype(np.float32)
    # None of these datasets capture payload bytes (flow-level exports only).
    X = np.hstack([X, np.zeros((len(X), 1), dtype=np.float32)])

    return X, y


def load_cicids2017_file(csv_path, max_per_class=60000, seed=42):
    return load_flow_csv(csv_path, CICIDS2017_COLUMN_MAP, "Label", categorize_cicids2017, max_per_class, seed)


def load_cicids2018_file(csv_path, max_per_class=60000, seed=42):
    return load_flow_csv(csv_path, CICIDS2018_COLUMN_MAP, "Label", categorize_cicids2018, max_per_class, seed)


def load_darknet2020_file(csv_path, max_per_class=60000, seed=42):
    return load_flow_csv(csv_path, DARKNET2020_COLUMN_MAP, "Label", categorize_darknet2020, max_per_class, seed)


def load_cicids2017(csv_dir, max_per_class=60000):
    csv_dir = Path(csv_dir)
    csv_files = sorted(csv_dir.glob("*.csv")) + sorted(csv_dir.glob("*.CSV"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {csv_dir}")

    X_parts, y_parts = [], []
    for f in csv_files:
        print(f"[TRAIN] Loading (CIC-IDS2017) {f.name}...")
        X_f, y_f = load_cicids2017_file(f, max_per_class=max_per_class)
        print(f"[TRAIN]   -> {len(X_f)} rows after per-class capping")
        X_parts.append(X_f)
        y_parts.append(y_f)

    return np.vstack(X_parts), np.concatenate(y_parts)


def load_dataset_dir(csv_dir, loader_fn, dataset_label, max_per_class=60000):
    csv_dir = Path(csv_dir)
    csv_files = sorted(csv_dir.glob("*.csv")) + sorted(csv_dir.glob("*.CSV"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {csv_dir}")

    X_parts, y_parts = [], []
    for f in csv_files:
        print(f"[TRAIN] Loading ({dataset_label}) {f.name}...")
        X_f, y_f = loader_fn(f, max_per_class=max_per_class)
        print(f"[TRAIN]   -> {len(X_f)} rows after per-class capping")
        X_parts.append(X_f)
        y_parts.append(y_f)

    return np.vstack(X_parts), np.concatenate(y_parts)


def train_isolation_forest(X, y=None):
    # IMPORTANT: src/ml/anomaly_detector.py calls model.decision_function(X)
    # directly on the raw feature vector produced by FeatureExtractor -- it
    # never loads or applies a scaler. Fit on raw, unscaled features to
    # match inference exactly. A scaler is still saved for reference/future
    # use, but is not part of the active model path.
    print("[TRAIN] Training Isolation Forest...")
    scaler = StandardScaler()
    scaler.fit(X)

    # Anomaly detection is more principled when fit mostly on normal
    # traffic. If labels are available, fit on BENIGN flows only so the
    # model actually learns a baseline of "normal", rather than learning
    # to treat a large slice of attack traffic as part of the norm.
    if y is not None and "BENIGN" in set(y):
        X_fit = X[y == "BENIGN"]
        contamination = 0.01
        print(f"[TRAIN] Fitting on {len(X_fit)} BENIGN-only flows (contamination={contamination})")
    else:
        X_fit = X
        contamination = 0.1

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1)
    model.fit(X_fit)

    import pickle
    with open(f"{MODELS_DIR}/isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(f"{MODELS_DIR}/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    print("[TRAIN] Isolation Forest saved.")

def train_classifier(X, y, use_xgboost=False):
    # IMPORTANT: src/ml/classifier.py's AttackClassifier.classify() calls
    # self.model.predict()/.predict_proba() directly on the raw feature
    # vector -- like the isolation forest above, it never applies a scaler.
    # Train on raw features to match. RandomForest/XGBoost are tree-based
    # and don't need feature scaling to perform well anyway, so this is a
    # correctness fix with no accuracy downside. A scaler is still fit and
    # saved for reference, but the model itself is fit on unscaled X.
    print("[TRAIN] Training Attack Classifier...")

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    scaler = StandardScaler()
    scaler.fit(X_train)

    if use_xgboost and XGBOOST_AVAILABLE:
        print("[TRAIN] Using XGBoost classifier...")
        model = xgb.XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1, random_state=42, eval_metric="mlogloss")
    else:
        print("[TRAIN] Using Random Forest classifier...")
        model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1, class_weight='balanced')

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[TRAIN] Classifier accuracy: {acc:.4f}")
    print("\nClassification Report:")
    report = classification_report(y_test, y_pred, target_names=le.classes_)
    print(report)

    import pickle
    with open(f"{MODELS_DIR}/classifier.pkl", "wb") as f:
        pickle.dump({"model": model, "classes": list(le.classes_)}, f)
    with open(f"{MODELS_DIR}/classifier_scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(f"{MODELS_DIR}/label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    print("[TRAIN] Classifier saved.")
    return acc, report

def train_lstm(X, y):
    if not TF_AVAILABLE:
        print("[TRAIN] TensorFlow not available. Skipping LSTM training.")
        return

    print("[TRAIN] Training LSTM sequence detector...")

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    seq_length = 10
    n_features = X.shape[1]

    X_seq = []
    y_seq = []
    for i in range(len(X) - seq_length):
        X_seq.append(X[i:i+seq_length])
        y_seq.append(1 if any(y_encoded[i:i+seq_length] != y_encoded[0]) else 0)

    X_seq = np.array(X_seq)
    y_seq = np.array(y_seq)

    X_train, X_test, y_train, y_test = train_test_split(X_seq, y_seq, test_size=0.2, random_state=42)

    model = Sequential([
        LSTM(64, return_sequences=True, input_shape=(seq_length, n_features)),
        Dropout(0.2),
        LSTM(32),
        Dropout(0.2),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=10, batch_size=64, validation_split=0.1, verbose=1)

    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f"[TRAIN] LSTM accuracy: {acc:.4f}")

    model.save(f"{MODELS_DIR}/lstm_detector")
    print("[TRAIN] LSTM saved.")

def main():
    parser = argparse.ArgumentParser(description='Train Aegis-AI ML models')
    parser.add_argument('--dataset', type=str, default='synthetic',
                         choices=['synthetic', 'cicids2017', 'combined'],
                         help="'combined' trains on any of --csv-dir/--cicids2018-dir/--darknet-dir/--darknet-csv that are provided")
    parser.add_argument('--csv', type=str, default='', help='Path to a single CIC-IDS2017 CSV file')
    parser.add_argument('--csv-dir', type=str, default='', help='Path to a directory of CIC-IDS2017 day-CSVs')
    parser.add_argument('--cicids2018-dir', type=str, default='', help='Path to a directory of CSE-CIC-IDS2018 CSVs')
    parser.add_argument('--cicids2018-csv', type=str, default='', help='Path to a single CSE-CIC-IDS2018 CSV file')
    parser.add_argument('--darknet-dir', type=str, default='', help='Path to a directory of CIC-Darknet2020 CSVs')
    parser.add_argument('--darknet-csv', type=str, default='', help='Path to a single CIC-Darknet2020 CSV file')
    parser.add_argument('--max-per-class', type=int, default=60000, help='Cap rows per class per file (0 to disable)')
    parser.add_argument('--xgboost', action='store_true', help='Use XGBoost instead of Random Forest')
    parser.add_argument('--samples', type=int, default=10000, help='Number of synthetic samples')
    parser.add_argument('--skip-lstm', action='store_true', help='Skip LSTM training (also auto-skipped if TensorFlow is unavailable)')
    args = parser.parse_args()

    ensure_dirs()
    max_per_class = None if args.max_per_class == 0 else args.max_per_class

    if args.dataset == 'cicids2017' and args.csv_dir:
        X, y = load_cicids2017(args.csv_dir, max_per_class=max_per_class)
    elif args.dataset == 'cicids2017' and args.csv:
        X, y = load_cicids2017_file(args.csv, max_per_class=max_per_class)
    elif args.dataset == 'combined':
        X_parts, y_parts = [], []
        if args.csv_dir:
            Xp, yp = load_dataset_dir(args.csv_dir, load_cicids2017_file, "CIC-IDS2017", max_per_class)
            X_parts.append(Xp); y_parts.append(yp)
        if args.cicids2018_dir:
            Xp, yp = load_dataset_dir(args.cicids2018_dir, load_cicids2018_file, "CSE-CIC-IDS2018", max_per_class)
            X_parts.append(Xp); y_parts.append(yp)
        if args.cicids2018_csv:
            print(f"[TRAIN] Loading (CSE-CIC-IDS2018) {args.cicids2018_csv}...")
            Xp, yp = load_cicids2018_file(args.cicids2018_csv, max_per_class=max_per_class)
            print(f"[TRAIN]   -> {len(Xp)} rows after per-class capping")
            X_parts.append(Xp); y_parts.append(yp)
        if args.darknet_dir:
            Xp, yp = load_dataset_dir(args.darknet_dir, load_darknet2020_file, "CIC-Darknet2020", max_per_class)
            X_parts.append(Xp); y_parts.append(yp)
        if args.darknet_csv:
            print(f"[TRAIN] Loading (CIC-Darknet2020) {args.darknet_csv}...")
            Xp, yp = load_darknet2020_file(args.darknet_csv, max_per_class=max_per_class)
            print(f"[TRAIN]   -> {len(Xp)} rows after per-class capping")
            X_parts.append(Xp); y_parts.append(yp)
        if not X_parts:
            raise ValueError("--dataset combined requires at least one of --csv-dir/--cicids2018-dir/--cicids2018-csv/--darknet-dir/--darknet-csv")
        X = np.vstack(X_parts)
        y = np.concatenate(y_parts)
    else:
        X, y = generate_synthetic_data(args.samples)

    print(f"[TRAIN] Training set: {X.shape[0]} samples, {X.shape[1]} features")
    classes, counts = np.unique(y, return_counts=True)
    print(f"[TRAIN] Classes: {dict(zip(classes, counts))}")

    train_isolation_forest(X, y)
    train_classifier(X, y, use_xgboost=args.xgboost)
    if not args.skip_lstm:
        train_lstm(X, y)

    print("[TRAIN] All models trained successfully!")

if __name__ == "__main__":
    main()
