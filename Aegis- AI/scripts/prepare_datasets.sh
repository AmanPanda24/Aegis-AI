#!/usr/bin/env bash
# Extracts the dataset archives in data/raw_datasets/ into the directory
# layout scripts/train_models.py expects, so `data/TRAINING_PROVENANCE.md`'s
# training command can be reproduced exactly. Idempotent - safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."

RAW_DIR="data/raw_datasets"
for f in CIC-IDS2017.zip CSE-CIC-IDS2018.zip CIC-Darknet2020.zip; do
    if [ ! -f "$RAW_DIR/$f" ]; then
        echo "ERROR: $RAW_DIR/$f not found. Are you running this from the project root?" >&2
        exit 1
    fi
done

echo "Verifying checksums against data/TRAINING_PROVENANCE.md..."
python3 - <<'EOF'
import hashlib, sys

expected = {
    "data/raw_datasets/CIC-IDS2017.zip": "51c868a526d3ad493ca0cdd6630d9cb608b6818c19a5bb883c017bf3ad48b666",
    "data/raw_datasets/CSE-CIC-IDS2018.zip": "415d0d5b7a1ebcf23062c9ba49b597f8f0a216454d2efea70d65306ae494ec49",
    "data/raw_datasets/CIC-Darknet2020.zip": "5ff0280aadc684d9e4bda0e4cc1bee0f90a927fad329685db640fc0a08aaf157",
}
ok = True
for path, expect in expected.items():
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    actual = h.hexdigest()
    status = "OK" if actual == expect else "MISMATCH"
    if actual != expect:
        ok = False
    print(f"  {path}: {status}")
if not ok:
    print("Checksum mismatch - archive may be corrupted or modified. Aborting.", file=sys.stderr)
    sys.exit(1)
EOF

echo "Extracting CIC-IDS2017 -> data/cicids2017/ ..."
mkdir -p data/cicids2017
unzip -o -q "$RAW_DIR/CIC-IDS2017.zip" -d data/cicids2017

echo "Extracting CSE-CIC-IDS2018 -> data/cicids2018/ ..."
mkdir -p data/cicids2018
unzip -o -q "$RAW_DIR/CSE-CIC-IDS2018.zip" -d data/cicids2018

echo "Extracting CIC-Darknet2020 -> data/darknet2020/ ..."
mkdir -p data/darknet2020
unzip -o -q "$RAW_DIR/CIC-Darknet2020.zip" -d data/darknet2020

echo "Done. You can now run the training command in data/TRAINING_PROVENANCE.md:"
echo
echo "  python scripts/train_models.py --dataset combined \\"
echo "    --csv-dir data/cicids2017 \\"
echo "    --cicids2018-csv data/cicids2018/cic.csv \\"
echo "    --darknet-csv data/darknet2020/Darknet.CSV \\"
echo "    --max-per-class 15000 --skip-lstm"
