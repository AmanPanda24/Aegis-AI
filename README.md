<div align="center">

# 🛡️ AEGIS-AI

### **Intelligent Network Behavior Analysis System**

*Real-time traffic intelligence · Machine learning threat detection · Layer 2 attack coverage*

![Status](https://img.shields.io/badge/status-prototype-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/SRS-v1.0%20compliant-brightgreen)
![Docker](https://img.shields.io/badge/docker-ready-2496ED)

</div>

---

## ⚡ What is Aegis-AI?

**Aegis-AI** is a full-stack network security prototype that watches traffic, thinks about it, and tells you the moment something looks wrong — in real time, on a live dashboard.

It's built as a **4-layer AI pipeline** for IP traffic, backed by a **rule-based Layer 2 sidecar** that catches the attacks machine learning can't — because they never show up as a "flow" in the first place.

> Port scans. DoS floods. Brute force. Data exfiltration. Slow APTs. ARP spoofing. MAC flooding. STP hijacks. VLAN hopping.
> **Aegis-AI is watching for all of it.**

---

## 🚀 Quick Start

Pick your speed:

```bash
# 🏃 Fastest — one script does everything
chmod +x run.sh
./run.sh
```

```bash
# 🐳 Containerized
docker-compose up --build
```

```bash
# 🔧 Manual / full control
pip install -r requirements.txt
python scripts/train_models.py --dataset synthetic --samples 10000
python src/api/main.py
```

Then open **[http://localhost:8000](http://localhost:8000)** and watch the dashboard come alive. 🎯

---

## 🏗️ Architecture — 4 Layers + an L2 Sidecar

```
┌─────────────────────────────────────────────────────────────┐
│                      🌐  DASHBOARD (Layer 4)                 │
│         index.html · app.js · WebSocket live feed            │
└───────────────────────────▲───────────────────────────────────┘
                             │
┌───────────────────────────┴───────────────────────────────────┐
│                    🧠  AI / ML  (Layer 3)                     │
│   Isolation Forest · Classifier · LSTM · Threat Scorer 0-100 │
└───────────────────────────▲───────────────────────────────────┘
                             │
┌───────────────────────────┴───────────────────────────────────┐
│                  ⚙️  PROCESSING  (Layer 2)                    │
│         Feature Extraction · Deep Packet Inspection            │
└───────────────────────────▲───────────────────────────────────┘
                             │
┌───────────────────────────┴───────────────────────────────────┐
│               📡  DATA ACQUISITION  (Layer 1)                 │
│              Live capture (scapy) or Simulation                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│      🔌  L2 SIDECAR — runs in PARALLEL, non-IP traffic       │
│   ARP · STP · CDP · DTP · VTP · MAC Flood · VLAN Hopping     │
│         → feeds into the SAME alerts, DB & dashboard          │
└─────────────────────────────────────────────────────────────┘
```

| Layer | Component | SRS Requirement |
|---|---|---|
| 1 — Data Acquisition | `packet_capture.py` | `ACQ-01` `ACQ-02` `ACQ-03` |
| 2 — Processing | `feature_extraction.py`, `dpi_engine.py` | `PROC-01` `PROC-02` `PROC-03` `PROC-05` |
| 3 — AI / ML | `anomaly_detector.py`, `classifier.py`, `lstm_detector.py`, `threat_scorer.py` | `ML-01`…`ML-05` `ML-07` |
| 4 — Dashboard | `index.html`, `app.js`, `main.py` | `DASH-01`…`06` `ALT-01`…`05` |
| **L2** — Non-IP Monitoring | `l2_capture.py`, `l2_analyzer.py` | *see below* |

### 🕳️ Why the L2 sidecar exists

The core pipeline only ever sees **IP traffic** (TCP/UDP/ICMP) — so it's completely blind to Layer 2 attack tooling like **Yersinia**, which forges frames that never carry an IP header at all. The sidecar runs **in parallel**, using rule-based detection (no flow statistics needed) to close that gap:

| 🎯 Attack | 🔍 Detected By |
|---|---|
| ARP spoofing / cache poisoning | conflicting IP→MAC bindings across ARP replies |
| MAC flooding (CAM overflow) | burst of unseen source MACs in a short window |
| STP root bridge hijack | new BPDU claiming a superior (lower) bridge ID |
| STP topology-change flood | repeated forced topology-change BPDUs |
| CDP flood | abnormal rate of Cisco Discovery Protocol frames |
| DTP switch spoofing | any DTP trunk-negotiation frame from an end host |
| VTP configuration attack | suspicious jump in VTP revision number |
| VLAN hopping | frames carrying two stacked 802.1Q tags |

L2 alerts flow through the **same** alert pipeline, database, WebSocket feed, and dashboard as regular alerts — tagged `layer: "L2"` with a distinct badge. Filter them via `GET /api/alerts?layer=L2`, and check live analyzer state at `GET /api/l2/status`.

---

## ✨ Features

- 🔴 **Real-time packet capture** — live (scapy) or simulation mode
- 🔬 **Deep Packet Inspection** with protocol detection
- 🌲 **Isolation Forest** anomaly detection
- 🧩 **XGBoost / Random Forest** attack classification
- 🔁 **LSTM** sequence analysis *(optional)*
- 🎯 **Threat Score 0–100** with risk levels
- 🔌 **Layer 2 monitoring** — ARP spoofing, MAC flooding, STP/CDP/DTP/VTP, VLAN hopping
- 📊 **WebSocket-powered live dashboard**
- 📤 **Alert export** — JSON / CSV
- ⚙️ **Fully configurable thresholds**
- 🐳 **Docker containerized**

---

## 🔗 API Surface

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/stats` | Live system stats |
| `GET` | `/api/flows` | Active network flows |
| `GET` | `/api/flows/{flow_id}` | Flow detail |
| `GET` | `/api/packets` | Recent packet sample |
| `GET` | `/api/network/talkers` | Top talkers |
| `GET` | `/api/alerts` | Alerts (filter with `?layer=L2`) |
| `GET` | `/api/l2/status` | L2 analyzer internal state |
| `GET` | `/api/traffic` | Traffic overview |
| `POST` | `/api/config` | Update runtime config |
| `GET` | `/api/export/alerts` | Export alerts (JSON/CSV) |
| `WS` | `/ws` | Live real-time feed |

---

## 📁 Project Structure

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
│   ├── capture/        📡 Layer 1 — packet & L2 frame capture
│   ├── processing/      ⚙️ Layer 2 — DPI & feature extraction
│   ├── ml/              🧠 Layer 3 — anomaly, classification, scoring
│   ├── api/             🔗 FastAPI backend
│   └── dashboard/       📊 HTML/CSS/JS live UI
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

## 🖥️ VM Deployment Environment

| VM | Role | OS |
|---|---|---|
| **VM1** | Aegis Engine *(this system)* | — |
| **VM2** | Victim | Ubuntu 22.04 |
| **VM3** | Attacker | Kali Linux |

Set `capture.mode: "live"` and `l2.mode: "live"` in `config.yaml` to switch from simulation to real packet capture on VM deployment (requires root / raw-socket access).

---

## 🧪 Simulation Scenarios (Out of the Box)

**IP layer:** `normal` · `port_scan` · `dos` · `brute_force` · `data_exfil` · `slow_apt`

**L2 layer:** `normal_l2` · `arp_spoof` · `mac_flood` · `stp_attack` · `cdp_flood` · `dtp_negotiation` · `vtp_attack` · `vlan_double_tag`

No live network needed — spin it up and watch realistic attacks unfold on the dashboard immediately.

---

<div align="center">

### 🛡️ Built for visibility where it matters — from Layer 2 to Layer 7.

</div>
