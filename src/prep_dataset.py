"""
Converts CICIDS2017's numeric flow-record CSVs into log-line format:
{log_id, log_line, notes_field, source_flow_label}.

WHY THIS EXISTS
----------------
CICIDS2017 is flow data (packet counts, byte counts, durations) with no free
text field like a User-Agent or filename — which is normally where an
attacker would sneak injected instructions into a real system. So this
script does two things per row:

  1. Builds a synthetic, human-readable log LINE from the numeric fields,
     e.g. "Connection from 192.168.1.5 to 10.0.0.9, protocol TCP, duration
     4.20s, 12 fwd packets, flagged as PortScan."
  2. Appends one extra free-text field (a fake "notes" field, styled like a
     device/monitoring-agent annotation) that Phase 3 will use as the
     injection point for attack payloads. In this baseline dataset it's
     just a bland placeholder string — Phase 3's harness will overwrite it
     per test case.

This limitation (no native free-text field) and this workaround are called
out explicitly in the threat model doc so it can be copied into the
Phase 5 report too.

Note: this script does NOT map CICIDS2017's attack-type labels (PortScan,
DDoS, etc.) to LOW/MEDIUM/HIGH/CRITICAL severity. It just carries the raw
label through as `source_flow_label`. That mapping is a separate concern
for whoever builds the scoring/evaluation logic.

INPUT
-----
One or more of CICIDS2017's CSVs, e.g.:
    Monday-WorkingHours.pcap_ISCX.csv
    Tuesday-WorkingHours.pcap_ISCX.csv
    Wednesday-workingHours.pcap_ISCX.csv
    Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
    Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
    Friday-WorkingHours-Morning.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
    Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

Get them from the Kaggle mirror (easier than UNB's gated download form):
    https://www.kaggle.com/datasets/cicdataset/cicids2017

Note: column names in the raw files have leading spaces (" Label",
" Flow Duration", etc.) — this script strips those automatically. Also,
some distributions of these CSVs omit Source IP / Destination IP / Flow ID
(they were anonymized out of the "MachineLearningCVE" release used for ML
benchmarking). This script falls back to synthetic placeholder IPs when
those columns aren't present, and prints a warning when it does.

USAGE
-----
    python src/prep_dataset.py --input data/CICIDS2017/GeneratedLabelledFlows/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --output results/cicids_portscan.csv --sample 200

    # Combine multiple days/files, capping total rows:
    python src/prep_dataset.py --input data/CICIDS2017//GeneratedLabelledFlows/*.csv --output results/cicids_combined.csv --sample 500
"""

import argparse
import csv
import glob
import random
import sys
from pathlib import Path

import pandas as pd

PLACEHOLDER_NOTE = "monitoring-agent: nominal"


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = df.columns.str.strip()
    return df


def get_col(df: pd.DataFrame, *candidates, default=None):
    """Return the first matching column's values, or a default Series."""
    for c in candidates:
        if c in df.columns:
            return df[c]
    return pd.Series([default] * len(df), index=df.index)


def build_log_line(row) -> str:
    src_ip = row.get("_src_ip", "10.0.0.x")
    dst_ip = row.get("_dst_ip", "10.0.0.y")
    protocol = row.get("_protocol", "?")
    duration_s = row.get("_duration_s", 0.0)
    fwd_packets = row.get("_fwd_packets", 0)
    label = row.get("_label", "Unknown")

    return (
        f"Connection from {src_ip} to {dst_ip}, protocol {protocol}, "
        f"duration {duration_s:.2f}s, {int(fwd_packets)} fwd packets, "
        f"flagged as {label}."
    )


def load_and_normalize(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="cp1252", low_memory=False)
    df = normalize_columns(df)

    out = pd.DataFrame()
    out["_label"] = get_col(df, "Label", default="Unknown")

    has_ips = "Source IP" in df.columns and "Destination IP" in df.columns
    if has_ips:
        out["_src_ip"] = df["Source IP"]
        out["_dst_ip"] = df["Destination IP"]
    else:
        # This CSV variant doesn't include IPs (common for the "MachineLearningCVE" anonymized release). 
        # Synthesize placeholders so the log line is still readable; flag it once per file.
        print(
            f"  [warn] {Path(path).name}: no Source/Destination IP columns found — "
            "using synthetic placeholder IPs."
        )
        out["_src_ip"] = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(len(df))]
        out["_dst_ip"] = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(len(df))]

    protocol_raw = get_col(df, "Protocol", default=None)
    protocol_map = {"6": "TCP", "17": "UDP", "1": "ICMP", 6: "TCP", 17: "UDP", 1: "ICMP"}
    out["_protocol"] = protocol_raw.map(lambda v: protocol_map.get(v, str(v)))

    duration_us = get_col(df, "Flow Duration", default=0)
    out["_duration_s"] = pd.to_numeric(duration_us, errors="coerce").fillna(0) / 1_000_000.0

    out["_fwd_packets"] = pd.to_numeric(
        get_col(df, "Total Fwd Packets", default=0), errors="coerce"
    ).fillna(0)

    out["_source_file"] = Path(path).name
    return out


def run(input_patterns, output_path, sample, seed):
    random.seed(seed)

    paths = []
    for pattern in input_patterns:
        paths.extend(glob.glob(pattern))
    if not paths:
        sys.exit(f"ERROR: no files matched input pattern(s): {input_patterns}")

    print(f"Loading {len(paths)} file(s)...")
    frames = [load_and_normalize(p) for p in paths]
    combined = pd.concat(frames, ignore_index=True)
    print(f"Loaded {len(combined)} total rows.")

    if sample:
        combined = combined.sample(n=min(sample, len(combined)), random_state=seed).reset_index(drop=True)
        print(f"Random sample: {len(combined)} rows.")

    combined = combined.sample(frac=1, random_state=seed).reset_index(drop=True)  # shuffle

    combined["_label"] = (
        combined["_label"]
        .fillna("BENIGN")
        .astype(str)
        .str.strip()
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.writer(f_out)
        writer.writerow(["log_id", "log_line", "notes_field", "source_flow_label", "source_file"])
        for i, row in combined.iterrows():
            log_line = build_log_line(row)
            writer.writerow([
                i + 1,
                log_line,
                PLACEHOLDER_NOTE,  # <-- Phase 3 injects payloads here
                row["_label"],
                row["_source_file"],
            ])

    print(f"\nWrote {len(combined)} rows to {output_file}")
    print("Label distribution:")
    print(combined["_label"].value_counts().to_string())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prep CICIDS2017 CSVs into log-line format with an injectable notes field")
    parser.add_argument("--input", nargs="+", required=True, help="Path(s)/glob(s) to raw CICIDS2017 CSV(s)")
    parser.add_argument("--output", default="data/cicids_prepped.csv", help="Output CSV path")
    parser.add_argument("--sample", type=int, default=None, help="Optional: cap total rows via random sampling")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling/shuffling")
    args = parser.parse_args()

    run(args.input, args.output, args.sample, args.seed)
