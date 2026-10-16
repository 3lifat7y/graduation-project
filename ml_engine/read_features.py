#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Feature Sampler & Generator (read_features.py)
Generates 'features_by_label.json' from CSV test sets or CIC-DDoS2019 datasets
for traffic simulation with 'send_traffic.py' and 'api.py'.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd

def get_project_root() -> Path:
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / ".git").exists() or (p / "requirements.txt").exists() or (p / "api.py").exists():
            return p
        p = p.parent
    return Path(__file__).resolve().parent.parent

BASE_DIR = get_project_root()
NEW_DATASET_TEST_SET = BASE_DIR / "final_output_new_dataset" / "datasets" / "test_set.csv"
V2_TEST_SET = BASE_DIR / "final_output_optimized_v2" / "datasets" / "test_set.csv"
TOP3_TEST_SET = BASE_DIR / "final_output_top3" / "datasets" / "test_set.csv"
OPTIMIZED_TEST_SET = BASE_DIR / "final_output_optimized" / "datasets" / "test_set.csv"
LEGACY_TEST_SET = BASE_DIR / "final output" / "test_set_01-12.csv"

if NEW_DATASET_TEST_SET.exists():
    DATA_FILE = str(NEW_DATASET_TEST_SET)
elif V2_TEST_SET.exists():
    DATA_FILE = str(V2_TEST_SET)
elif TOP3_TEST_SET.exists():
    DATA_FILE = str(TOP3_TEST_SET)
elif OPTIMIZED_TEST_SET.exists():
    DATA_FILE = str(OPTIMIZED_TEST_SET)
else:
    DATA_FILE = str(LEGACY_TEST_SET)
OUTPUT_JSON = str(BASE_DIR / "features_by_label.json")
ROWS_TO_READ = None
SAMPLE_PER_LABEL = 1000

# Standard classification column names in intrusion and DDoS datasets
KNOWN_LABEL_COLUMNS = [
    'label',
    'attack',
    'attack_type',
    'attack type',
    'class',
    'classification',
    'target',
    'category',
    'type'
]

# Standard attack categories across CIC-IDS2017 and CIC-DDoS2019
CIC_DDOS_ATTACK_KEYWORDS = [
    'benign', 'drdos', 'dns', 'ldap', 'mssql', 'netbios',
    'ntp', 'snmp', 'ssdp', 'udp', 'syn', 'tftp', 'webddos',
    'bot', 'patator', 'ddos', 'dos', 'hulk', 'goldeneye',
    'slowloris', 'slowhttptest', 'heartbleed', 'infiltration',
    'portscan', 'web attack', 'xss', 'sql injection'
]



def read_data_file(data_file: str, rows_to_read: Optional[int] = None) -> pd.DataFrame:
    """Reads a CSV file and strips leading/trailing whitespace from column names."""
    print(f"Loading {data_file}...")
    if not os.path.exists(data_file):
        raise FileNotFoundError(f"Dataset file not found: {data_file}")

    df = pd.read_csv(data_file, nrows=rows_to_read, low_memory=False)
    # Strip whitespace from column headers to eliminate ' Label' issues
    df.columns = df.columns.str.strip()
    print(f"Loaded {len(df):,} rows with {len(df.columns)} columns")
    return df


def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """Replaces infinite values and imputes missing numeric values."""
    df = df.replace([float('inf'), float('-inf')], float('nan')).fillna(0)
    print("Handled missing values and infinities")
    return df


def find_label_column(df: pd.DataFrame, explicit_column: Optional[str] = None) -> Tuple[Optional[str], List[str]]:
    """
    Identifies the label column reliably with whitespace stripping and case insensitivity.
    Returns:
        (detected_column_name, available_columns_list)
    """
    available_cols = list(df.columns)

    if explicit_column:
        for col in available_cols:
            if col.lower() == explicit_column.strip().lower():
                return col, available_cols
        return None, available_cols

    # 1. Exact normalized matches with known names (e.g. 'Label', 'Attack', 'Class')
    for target in KNOWN_LABEL_COLUMNS:
        target_norm = target.lower().replace('_', '').replace(' ', '')
        for col in available_cols:
            col_norm = col.lower().replace('_', '').replace(' ', '')
            if col_norm == target_norm:
                return col, available_cols

    # 2. Substring match for 'label' or 'attack' (avoiding ambiguous matches)
    for col in available_cols:
        col_lower = col.lower()
        if 'label' in col_lower or 'attack' in col_lower:
            return col, available_cols

    return None, available_cols


def validate_dataset_and_labels(df: pd.DataFrame, label_col: Optional[str], file_path: str) -> str:
    """
    Validates that:
    1. A valid label column exists.
    2. The dataset has actual feature columns (more than 1 column total).
    3. The label column content is meaningful.
    """
    available_cols = list(df.columns)

    if not label_col or label_col not in df.columns:
        err_msg = [
            "=" * 80,
            f"[ERROR] No valid Label column found in dataset: {file_path}",
            f"- Available columns ({len(available_cols)}): {available_cols[:20]}{' ...' if len(available_cols) > 20 else ''}",
            f"- Supported label column names: {KNOWN_LABEL_COLUMNS}",
            "",
            "Reason:",
            "None of the available columns match standard attack/label column conventions.",
            "If your dataset uses a custom column for labels, specify it via --label <column_name>.",
            "=" * 80
        ]
        raise ValueError("\n".join(err_msg))

    feature_cols = [c for c in df.columns if c != label_col]
    if len(feature_cols) == 0:
        unique_vals = list(df[label_col].dropna().unique()[:10])
        err_msg = [
            "=" * 80,
            f"[ERROR] Dataset contains NO feature columns: {file_path}",
            f"- Available columns: {available_cols}",
            f"- Detected column: '{label_col}' with classes: {unique_vals}",
            "",
            "Reason:",
            f"The file '{Path(file_path).name}' contains only 1 column and has no packet/flow features.",
            "Generating 'features_by_label.json' requires network flow features",
            "(e.g., Flow Duration, Packet Length, Ports, etc.) for traffic simulation.",
            "",
            "How to fix:",
            "1. Run 'python Train.py' to generate the isolated test set at 'final_output_optimized/datasets/test_set.csv'.",
            "2. Or specify an existing dataset CSV containing network features via --input, e.g.:",
            '   python read_features.py --input "01-12/UDPLag.csv" --rows 10000 --sample 500',
            "=" * 80
        ]
        raise ValueError("\n".join(err_msg))

    # Verify if classes resemble CIC-DDoS2019
    unique_classes = [str(x).strip() for x in df[label_col].dropna().unique()[:20]]
    has_ddos = any(any(kw in c.lower() for kw in CIC_DDOS_ATTACK_KEYWORDS) for c in unique_classes)
    if not has_ddos:
        print(f"[WARNING] Classes found in '{label_col}' ({unique_classes[:5]}) do not match typical CIC-DDoS2019 categories.")
        print(f"Standard CIC-DDoS2019 classes: DrDoS_DNS, DrDoS_LDAP, Syn, TFTP, UDP-lag, BENIGN, etc.\n")

    return label_col


def build_features_by_label(
    df: pd.DataFrame,
    explicit_label_col: Optional[str] = None,
    file_path: str = "",
    sample_per_label: int = SAMPLE_PER_LABEL
) -> Dict[str, Any]:
    """Extracts balanced samples per class with native types and attaches 'Label'."""
    raw_label_col, _ = find_label_column(df, explicit_label_col)
    label_col = validate_dataset_and_labels(df, raw_label_col, file_path)

    print(f"Using column '{label_col}' as Label")

    exclude_cols = [label_col]
    feature_cols = [c for c in df.columns if c not in exclude_cols]
    print(f"Number of feature columns identified: {len(feature_cols)}")

    all_data = []
    print("\nCollecting samples and attaching Label to each packet...\n")

    def to_native(v):
        if pd.isna(v):
            return 0.0
        if isinstance(v, (np.integer,)):
            return int(v)
        if isinstance(v, (np.floating,)):
            return float(v)
        if isinstance(v, (np.ndarray,)):
            return v.tolist()
        return v

    unique_labels = df[label_col].unique()
    for label in unique_labels:
        subset = df[df[label_col] == label]
        if sample_per_label > 0:
            n = min(sample_per_label, len(subset))
            subset = subset.sample(n=n, random_state=42)

        records = subset[feature_cols].to_dict(orient='records')
        converted = []
        for r in records:
            nr = {k: to_native(v) for k, v in r.items()}
            nr["Label"] = str(label).strip()
            converted.append(nr)

        all_data.extend(converted)
        print(f"{str(label):20} -> {len(converted):5} samples")

    return {"all_data": all_data}


def save_to_json(data: Dict[str, Any], path: str):
    """Saves dictionary to JSON format."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f"\nSaved {len(data['all_data']):,} packets to: {path}")
    print("Ready to be used with send_traffic.py")


def parse_args():
    p = argparse.ArgumentParser(description='Build features_by_label.json from a CSV test set or dataset')
    p.add_argument('--input', '-i', type=str, help='CSV input file path (overrides DATA_FILE)')
    p.add_argument('--output', '-o', type=str, help='Output JSON file to write (overrides OUTPUT_JSON)')
    p.add_argument('--rows', '-r', type=int, help='Number of rows to read (overrides ROWS_TO_READ)')
    p.add_argument('--sample', '-s', type=int, help='Samples per label (overrides SAMPLE_PER_LABEL)')
    p.add_argument('--label', '-l', type=str, help='Explicit label column name')
    return p.parse_args()


def main(
    input_file: Optional[str] = None,
    output_file: Optional[str] = None,
    rows: Optional[int] = None,
    sample_per_label: Optional[int] = None,
    explicit_label_col: Optional[str] = None
):
    print("=" * 80)
    print("            Generating features_by_label.json with correct Labels")
    print("=" * 80)

    in_file = input_file or DATA_FILE
    out_file = output_file or OUTPUT_JSON
    samples = sample_per_label if sample_per_label is not None else SAMPLE_PER_LABEL

    try:
        df = read_data_file(in_file, rows if rows is not None else ROWS_TO_READ)
        df = handle_missing_values(df)

        result = build_features_by_label(
            df=df,
            explicit_label_col=explicit_label_col,
            file_path=in_file,
            sample_per_label=samples
        )
        save_to_json(result, out_file)

        print("=" * 80)
        print("Done successfully! Run send_traffic.py now - all attack types will be ACTIVE")
        print("=" * 80)

    except ValueError as e:
        print(f"\n{e}\n", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    args = parse_args()
    main(
        input_file=args.input,
        output_file=args.output,
        rows=args.rows,
        sample_per_label=args.sample,
        explicit_label_col=args.label
    )