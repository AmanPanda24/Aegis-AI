# Training Provenance — Verifiable Record

This file exists so anyone can independently confirm the shipped
`models/*.pkl` files were trained on the real, original datasets bundled
in `data/raw_datasets/`, not synthetic or fabricated data. This replaces
the previous state where the training datasets weren't included in the
repo at all (`data/cicids2017/` shipped as an empty placeholder).

## Datasets included (compressed originals, unmodified)

| File | Dataset | SHA-256 |
|---|---|---|
| `data/raw_datasets/CIC-IDS2017.zip` | CIC-IDS2017 (8 day-CSVs, CICFlowMeter export) | `51c868a526d3ad493ca0cdd6630d9cb608b6818c19a5bb883c017bf3ad48b666` |
| `data/raw_datasets/CSE-CIC-IDS2018.zip` | CSE-CIC-IDS2018 (`cic.csv`, CICFlowMeter export) | `415d0d5b7a1ebcf23062c9ba49b597f8f0a216454d2efea70d65306ae494ec49` |
| `data/raw_datasets/CIC-Darknet2020.zip` | CIC-Darknet2020 (`Darknet.CSV`, Tor/VPN fingerprinting) | `5ff0280aadc684d9e4bda0e4cc1bee0f90a927fad329685db640fc0a08aaf157` |

Per-file SHA-256 of the extracted CSVs (for after you unzip, to confirm
nothing was altered in transit):

```
6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b  Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000  Friday-WorkingHours-Morning.pcap_ISCX.csv
852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34  Monday-WorkingHours.pcap_ISCX.csv
6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5  Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d  Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851  Tuesday-WorkingHours.pcap_ISCX.csv
893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a  Wednesday-workingHours.pcap_ISCX.csv
acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147  cic.csv (CSE-CIC-IDS2018)
3e89b9747841c44401fdceeea18b0fd3932f7a38f53d15a47395872cbac18433  Darknet.CSV
```

**Why the originals are stored compressed, not as raw CSVs:** the
decompressed CSVs total ~1.3GB; keeping them raw in the repo would make
routine cloning/downloading unnecessarily heavy for a tool most people
run without ever retraining. The zipped originals here are exactly what
was downloaded and used — nothing was pre-filtered, subsampled, or
edited before zipping — so unzipping and re-running the command below
reproduces training exactly.

## Exact command used to train the shipped models

```bash
python scripts/train_models.py --dataset combined \
  --csv-dir data/cicids2017 \
  --cicids2018-csv data/cicids2018/cic.csv \
  --darknet-csv data/darknet2020/Darknet.CSV \
  --max-per-class 15000 \
  --skip-lstm
```

(`--csv-dir`/`--cicids2018-csv`/`--darknet-csv` point at the *extracted*
CSVs - unzip the three archives in `data/raw_datasets/` into
`data/cicids2017/`, `data/cicids2018/`, `data/darknet2020/` first, or use
`scripts/prepare_datasets.sh`, included alongside this file, which does
that extraction for you.)

`--max-per-class 15000` was chosen for tractability on a constrained
build host (1 CPU core, ~3.9GB RAM); the loader itself was fixed as part
of this run to read each CSV in 200k-row chunks with per-chunk float32
downcasting rather than loading a whole file as float64 at once, since
the original single-pass full-file read was observed to OOM-kill the
process on that host reading the 135MB Tuesday-WorkingHours.pcap file. If
you have more RAM available, raise `--max-per-class` (or pass `0` to
disable the cap entirely) for a larger training set.

## Resulting training set

```
Training set: 243,028 samples, 55 features
Classes: {'BENIGN': 150000, 'Bot': 1966, 'BruteForce': 28835, 'DDoS': 15000,
          'DoS': 15000, 'Infiltration': 47, 'PortScan': 15000,
          'TOR_VPN': 15000, 'WebAttack': 2180}
```

`Bot` (1,966) and `Infiltration` (47) are small because those attack
types are genuinely rare in the source datasets themselves (CIC-IDS2017
has only 1,966 Bot rows and 36 Infiltration rows total across all 8
days) - this is not a sampling artifact, it's what real-world attack
class imbalance looks like, and it's exactly why those two classes have
the weakest precision/recall below. Reporting that honestly is more
useful than hiding it.

## Held-out test results (20% split, stratified, `random_state=42`)

```
Classifier accuracy: 0.9844

              precision    recall  f1-score   support

      BENIGN       1.00      0.98      0.99     30000
         Bot       0.56      0.99      0.72       393
  BruteForce       1.00      1.00      1.00      5767
        DDoS       1.00      1.00      1.00      3000
         DoS       0.95      1.00      0.97      3000
Infiltration       1.00      0.50      0.67        10
    PortScan       1.00      1.00      1.00      3000
     TOR_VPN       0.94      0.99      0.97      3000
   WebAttack       0.92      0.98      0.95       436

    accuracy                           0.98     48606
   macro avg       0.93      0.94      0.92     48606
weighted avg       0.99      0.98      0.99     48606
```

`Bot` precision (0.56) and `Infiltration` recall (0.50, on a 10-row test
split) are the known weak points, directly caused by how few real
examples of those classes exist in the source data. This matches the
same pattern in the model this replaced - reproducible, not a
regression.

## Verifying this yourself

1. Confirm the archives weren't tampered with: `sha256sum data/raw_datasets/*.zip` and compare against the table above.
2. Run `bash scripts/prepare_datasets.sh` to extract them.
3. Run the training command above.
4. Compare your `models/classifier.pkl`'s reported accuracy/report against the numbers here - tree-based models with a fixed `random_state` should reproduce closely (not bit-identical across all pandas/numpy/sklearn versions, but the same shape of result).

## What was NOT changed in this training run
- `models/isolation_forest.pkl` / `models/scaler.pkl` — fit on the same combined dataset's BENIGN-only rows (150,000 of them), contamination=0.01, as `train_isolation_forest()` in `scripts/train_models.py` always does.
- The LSTM sequence model was skipped (`--skip-lstm`) — see `requirements-optional.txt` and the LSTM section of the main README for why it's optional and how `ThreatScorer` handles its absence.
