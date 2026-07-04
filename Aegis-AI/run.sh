#!/bin/bash

set -e

echo "=========================================="
echo "  AEGIS-AI PROTOTYPE LAUNCHER"
echo "  Intelligent Network Behavior Analysis"
echo "=========================================="
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required but not installed."
    exit 1
fi

mkdir -p data/pcaps models logs config

if [ ! -d ".venv" ]; then
    echo "[SETUP] Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[SETUP] Installing dependencies..."
pip install -q -r requirements.txt

if [ ! -f "models/isolation_forest.pkl" ] || [ ! -f "models/classifier.pkl" ]; then
    echo "[SETUP] Training ML models..."
    python scripts/train_models.py --dataset synthetic --samples 10000
else
    echo "[SETUP] ML models found."
fi

echo ""
echo "[START] Launching Aegis-AI..."
echo "  Dashboard: http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo "  Mode:      Simulation (VM traffic)"
echo ""
echo "Press Ctrl+C to stop"
echo "=========================================="

python src/api/main.py
