# Aegis-AI Prototype
## Intelligent Network Behavior Analysis System

### SRS v1.0 Compliant - Local VM Deployment

---

## Quick Start

```bash
chmod +x run.sh
./run.sh
```

### Or with Docker:
```bash
docker-compose up --build
```

### Or manually:
```bash
pip install -r requirements.txt
python scripts/train_models.py --dataset synthetic --samples 10000
python src/api/main.py
```

Open http://localhost:8000 in your browser.

---

## Architecture (4 Layers + L2 Sidecar)

| Layer | Component | SRS Requirement |
|-------|-----------|---------------|
| 1 - Data Acquisition | `packet_capture.py` | ACQ-01, ACQ-02, ACQ-03 |
| 2 - Processing | `feature_extraction.py`, `dpi_engine.py` | PROC-01, PROC-02, PROC-03, PROC-05 |
| 3 - AI/ML | `anomaly_detector.py`, `classifier.py`, `lstm_detector.py`, `threat_scorer.py` | ML-01, ML-02, ML-03, ML-04, ML-05, ML-07 |
| 4 - Dashboard | `index.html`, `app.js`, `main.py` | DASH-01..DASH-06, ALT-01..ALT-05 |
| L2 - Non-IP Monitoring | `l2_capture.py`, `l2_analyzer.py` | see below |

The core 4-layer pipeline above only sees IP traffic (TCP/UDP/ICMP), so it
is blind to Layer 2 attack tooling like **Yersinia**, which forges frames
that never carry an IP header at all. The L2 sidecar runs in parallel and
covers that gap with rule-based (not ML-based) detection, since these
attacks have no "flow" to compute statistics over:

| Attack | Detected by |
|---|---|
| ARP spoofing / cache poisoning | conflicting IP→MAC bindings across ARP replies |
| MAC flooding (CAM table overflow) | burst of unseen source MACs in a short window |
| STP root bridge hijack | a new BPDU claiming a superior (lower) bridge ID |
| STP topology-change flood | repeated forced topology-change BPDUs |
| CDP flood | abnormal rate of Cisco Discovery Protocol frames |
| DTP switch spoofing | any DTP trunk-negotiation frame from an end host |
| VTP configuration attack | a suspicious jump in VTP revision number |
| VLAN hopping | frames carrying two stacked 802.1Q tags |

L2 alerts flow through the same alert pipeline, database, WebSocket feed,
and dashboard as regular alerts (tagged `layer: "L2"`), so they show up in
the same alert panel with a distinct **L2** badge. Filter by layer via
`/api/alerts?layer=L2`, and check `/api/l2/status` for the analyzer's
current internal state (learned ARP table size, current STP root, etc.).

Like the main pipeline, `config.l2.mode` can be `simulation` (synthetic
ARP/STP/CDP/DTP/VTP/VLAN-hop events) or `live` (real capture via scapy,
requires root/raw-socket access — same as `capture.mode: live`).

---

## Features
- Real-time packet capture (live or simulation)
- Deep Packet Inspection (DPI) with protocol detection
- Isolation Forest anomaly detection
- XGBoost/Random Forest attack classification
- LSTM sequence analysis (optional)
- Threat Score 0-100 with risk levels
- **Layer 2 monitoring**: ARP spoofing, MAC flooding, STP/CDP/DTP/VTP attacks, VLAN hopping
- WebSocket real-time dashboard
- Alert export (JSON/CSV)
- Configurable thresholds
- Docker containerization

---

## Project Structure
```
aegis-ai/
├── config/
│   └── config.yaml
├── data/
│   ├── aegis.db
│   └── pcaps/
├── models/
│   ├── isolation_forest.pkl
│   ├── classifier.pkl
│   └── lstm_detector/
├── src/
│   ├── capture/
│   ├── processing/
│   ├── ml/
│   ├── api/
│   └── dashboard/
├── scripts/
│   ├── train_models.py
│   └── generate_traffic.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── run.sh
└── README.md
```

---

## VM Environment (3 VMs)
- VM1: Aegis Engine (this system)
- VM2: Victim (Ubuntu 22.04)
- VM3: Attacker (Kali Linux)

Configure `config.yaml` for live capture mode on VM deployment.
