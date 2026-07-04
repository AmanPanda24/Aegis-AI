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

def load_cicids2017(csv_path):
    print(f"[TRAIN] Loading CIC-IDS2017 from {csv_path}...")
    df = pd.read_csv(csv_path)
    df = df.dropna()

    label_col = 'Label' if 'Label' in df.columns else 'label'
    if label_col not in df.columns:
        for col in df.columns:
            if 'label' in col.lower():
                label_col = col
                break

    feature_cols = [c for c in df.columns if c != label_col and c not in ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp']]
    X = df[feature_cols].select_dtypes(include=[np.number]).values
    y = df[label_col].values

    return X, y

def train_isolation_forest(X):
    print("[TRAIN] Training Isolation Forest...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
    model.fit(X_scaled)

    import pickle
    with open(f"{MODELS_DIR}/isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(f"{MODELS_DIR}/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    print("[TRAIN] Isolation Forest saved.")

def train_classifier(X, y, use_xgboost=False):
    print("[TRAIN] Training Attack Classifier...")

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    if use_xgboost and XGBOOST_AVAILABLE:
        print("[TRAIN] Using XGBoost classifier...")
        model = xgb.XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1, random_state=42, eval_metric="mlogloss")
    else:
        print("[TRAIN] Using Random Forest classifier...")
        model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1, class_weight='balanced')

    model.fit(X_train_s, y_train)

    y_pred = model.predict(X_test_s)
    acc = accuracy_score(y_test, y_pred)
    print(f"[TRAIN] Classifier accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    import pickle
    with open(f"{MODELS_DIR}/classifier.pkl", "wb") as f:
        pickle.dump({"model": model, "classes": list(le.classes_)}, f)
    with open(f"{MODELS_DIR}/classifier_scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(f"{MODELS_DIR}/label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    print("[TRAIN] Classifier saved.")

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
    parser.add_argument('--dataset', type=str, default='synthetic', choices=['synthetic', 'cicids2017'])
    parser.add_argument('--csv', type=str, default='', help='Path to CIC-IDS2017 CSV file')
    parser.add_argument('--xgboost', action='store_true', help='Use XGBoost instead of Random Forest')
    parser.add_argument('--samples', type=int, default=10000, help='Number of synthetic samples')
    args = parser.parse_args()

    ensure_dirs()

    if args.dataset == 'cicids2017' and args.csv:
        X, y = load_cicids2017(args.csv)
    else:
        X, y = generate_synthetic_data(args.samples)

    print(f"[TRAIN] Training set: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"[TRAIN] Classes: {np.unique(y)}")

    train_isolation_forest(X)
    train_classifier(X, y, use_xgboost=args.xgboost)
    train_lstm(X, y)

    print("[TRAIN] All models trained successfully!")

if __name__ == "__main__":
    main()
