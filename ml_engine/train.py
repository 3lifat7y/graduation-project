#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Advanced Multi-Model Intrusion & DDoS Detection Training Pipeline
Dataset: Data Base (8 CSV Files: Benign, Botnet, Bruteforce, DDoS, DoS, Infiltration, Portscan, WebAttacks)
Target Output Directory: final_output_new_dataset

Key Innovations in this Version:
1. Full 8-File Streamed Loading with 100% Minority Attack Protection:
   - Preserves 100% of all rare attacks (Heartbleed, SQL Injection, Infiltration, XSS, Brute Force, Bot, etc.).
   - Balanced sampling for majority classes (Benign, DoS Hulk, DDoS) across all 8 files.
   - Pre-split deduplication to eliminate cross-session data leakage.
2. Native Class Balancing:
   - XGBoost: sample_weight calculated via compute_sample_weight('balanced', y_train) with smoothing.
   - LightGBM: class_weight='balanced' natively.
   - ExtraTrees: class_weight='balanced' natively.
3. Dual-Track Independent Evaluation:
   - Binary Attack Detection Track: Benign vs Any Attack (Accuracy, Detection Rate, Specificity, FPR, FNR, F1, AUC-ROC).
   - Multi-Class Attack Classification Track: All 15 attack and benign sub-types.
4. Strict Data Leakage Prevention & Reproducibility:
   - Standard 70/10/20 Stratified Train/Val/Test Split.
   - Preprocessing (Imputation + Scaling) fit strictly on X_train.
   - Preserves all historical runs untouched; saves exclusively to final_output_new_dataset.
"""

import os
import sys
import gc
import io
import json
import time
import argparse
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Headless non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import StandardScaler, LabelEncoder, label_binarize
from sklearn.model_selection import train_test_split
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve, auc,
    precision_recall_curve, classification_report
)

# Optional Advanced Gradient Boosters
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

try:
    import catboost as cb
    from catboost import CatBoostClassifier
    HAS_CATBOOST = True
except ImportError:
    HAS_CATBOOST = False

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

warnings.filterwarnings('ignore')

# ==============================================================================
# Configuration & Constants
# ==============================================================================
def get_project_root() -> Path:
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / ".git").exists() or (p / "requirements.txt").exists() or (p / "api.py").exists():
            return p
        p = p.parent
    return Path(__file__).resolve().parent.parent

BASE_DIR = get_project_root()
DEFAULT_DATASET_DIR = BASE_DIR / "Data Base"
DEFAULT_OUTPUT_DIR = BASE_DIR / "final_output_new_dataset"

# Columns known to cause severe data leakage or unhelpful index noise in datasets
LEAKAGE_COLUMNS = [
    'Unnamed: 0',
    'Flow ID',
    'Source IP',
    'Destination IP',
    'Timestamp',
    'SimillarHTTP',
    'Fwd Header Length.1'  # Duplicate of 'Fwd Header Length'
]

POSSIBLE_LABEL_NAMES = [
    'Label', 'label', 'Attack', 'attack', 'class', 'Class', 'target', 'Target'
]

# Rare classes in Data Base that require 100% complete preservation
RARE_CLASSES = [
    'Heartbleed', 'Web Attack - Sql Injection', 'Web Attack - SQL Injection',
    'Infiltration', 'Web Attack - XSS', 'Web Attack - Brute Force',
    'Web Attack \ufffd Brute Force', 'Web Attack \ufffd XSS', 'Web Attack \ufffd Sql Injection',
    'Bot', 'PortScan', 'SSH-Patator', 'FTP-Patator',
    'DoS Slowhttptest', 'DoS slowloris', 'DoS GoldenEye'
]

LABEL_NORMALIZATION = {
    'Web Attack \ufffd Brute Force': 'Web Attack - Brute Force',
    'Web Attack \ufffd XSS': 'Web Attack - XSS',
    'Web Attack \ufffd Sql Injection': 'Web Attack - SQL Injection',
    'Web Attack - Sql Injection': 'Web Attack - SQL Injection',
    'BENIGN': 'Benign',
    'benign': 'Benign'
}


# ==============================================================================
# Directory Management
# ==============================================================================
def create_project_directories(output_dir: Path) -> Dict[str, Path]:
    """Creates the organized directory structure for outputs."""
    paths = {
        'root': output_dir,
        'models': output_dir / "models",
        'configs': output_dir / "configs",
        'reports': output_dir / "reports",
        'plots': output_dir / "plots",
        'datasets': output_dir / "datasets"
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths


# ==============================================================================
# Data Loading & Downcasting
# ==============================================================================
def downcast_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Downcasts numeric columns to float32/int32 to reduce memory footprint by ~50%."""
    for col in df.columns:
        col_type = df[col].dtype
        if col_type == 'float64':
            df[col] = df[col].astype(np.float32)
        elif col_type == 'int64':
            df[col] = df[col].astype(np.int32)
    return df


def detect_label_col(df: pd.DataFrame) -> str:
    """Detects label column name after stripping whitespace."""
    for name in POSSIBLE_LABEL_NAMES:
        if name in df.columns:
            return name
    for col in df.columns:
        col_lower = col.lower()
        if 'label' in col_lower or 'attack' in col_lower or 'class' in col_lower:
            return col
    raise ValueError(f"Could not detect label column among: {list(df.columns[:10])}")


def read_file_segmented(
    file_path: Path,
    target_samples: int = 60000,
    n_segments: int = 5
) -> pd.DataFrame:
    """
    Reads representative samples evenly spaced across a massive CSV file.
    Respects row boundaries, line endings, and file encoding.
    Ensures that steady-state attack dynamics (e.g. TFTP UDP after initial handshakes)
    are captured rather than only the file preamble.
    """
    file_size = file_path.stat().st_size
    samples_per_seg = max(1000, target_samples // n_segments)
    segments = []

    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        header = f.readline()
        if not header.strip():
            raise ValueError(f"Empty header in {file_path.name}")

        offsets_ratios = [0.10, 0.30, 0.50, 0.70, 0.90][:n_segments]
        for s_idx, ratio in enumerate(offsets_ratios):
            byte_offset = int(file_size * ratio)
            if byte_offset > 0:
                f.seek(byte_offset)
                f.readline()  # Discard partial cut line to align with newline boundary

            lines = [header]
            for _ in range(samples_per_seg):
                line = f.readline()
                if not line:
                    break
                lines.append(line)

            if len(lines) > 1:
                try:
                    df_seg = pd.read_csv(io.StringIO(''.join(lines)), low_memory=False)
                    df_seg.columns = df_seg.columns.str.strip()
                    df_seg = downcast_dataframe(df_seg)
                    segments.append(df_seg)
                except Exception as ex:
                    print(f"      [Warning] Parsing segment {s_idx+1} in {file_path.name}: {ex}")

    if not segments:
        raise ValueError(f"No valid segments could be parsed from {file_path.name}")

    combined_df = pd.concat(segments, ignore_index=True)
    return combined_df


def load_dataset_balanced(
    folder_path: Path,
    chunksize: int = 50000,
    max_samples_per_file: Optional[int] = 50000,
    random_state: int = 42
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Loads dataset across all CSV files in Data Base with rare-class protection.
    Protects 100% of all rare classes from being discarded.
    """
    csv_files = sorted(list(folder_path.glob("*.csv")))
    if not csv_files:
        csv_files = sorted(list(folder_path.glob("**/*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {folder_path}")

    print(f"\n📂 Found {len(csv_files)} CSV file(s) in {folder_path.name}")
    print(f"   Max samples per file cap: {max_samples_per_file if max_samples_per_file else 'Unlimited'}")

    dfs = []
    file_stats = {}

    for idx, csv_file in enumerate(csv_files, 1):
        file_size_mb = csv_file.stat().st_size / (1024 * 1024)
        print(f"\n [{idx}/{len(csv_files)}] Reading {csv_file.name} ({file_size_mb:.1f} MB)...", flush=True)

        rare_chunks = []
        common_chunks = []

        try:
            for chunk in pd.read_csv(csv_file, chunksize=chunksize, low_memory=False):
                chunk.columns = chunk.columns.str.strip()
                lbl_col = detect_label_col(chunk)

                # Normalize and clean labels
                chunk[lbl_col] = chunk[lbl_col].astype(str).str.strip().replace(LABEL_NORMALIZATION)
                chunk = downcast_dataframe(chunk)

                rare_mask = chunk[lbl_col].isin(RARE_CLASSES)
                if rare_mask.any():
                    rare_chunks.append(chunk[rare_mask])
                common_subset = chunk[~rare_mask]
                if not common_subset.empty:
                    common_chunks.append(common_subset)

            rare_df = pd.concat(rare_chunks, ignore_index=True) if rare_chunks else pd.DataFrame()
            common_df = pd.concat(common_chunks, ignore_index=True) if common_chunks else pd.DataFrame()

            # Downsample majority common classes if cap is set, but keep 100% of rare
            if max_samples_per_file and len(common_df) > max_samples_per_file:
                target_common = max(100, max_samples_per_file - len(rare_df))
                common_sampled = common_df.sample(n=min(len(common_df), target_common), random_state=random_state)
            else:
                common_sampled = common_df

            file_df = pd.concat([common_sampled, rare_df], ignore_index=True)
            dfs.append(file_df)

            lbl_col = detect_label_col(file_df)
            labels_in_file = file_df[lbl_col].value_counts().to_dict()
            file_stats[csv_file.name] = {
                'size_mb': round(file_size_mb, 1),
                'rows_loaded': len(file_df),
                'rare_rows_retained': len(rare_df),
                'labels': labels_in_file
            }
            print(f"    ✓ Retained {len(file_df):,} samples ({len(rare_df)} rare) | Labels: {labels_in_file}", flush=True)

            del rare_df, common_df, rare_chunks, common_chunks
            gc.collect()

        except Exception as e:
            print(f"    ✗ Error loading {csv_file.name}: {e}")

    if not dfs:
        raise ValueError("No data could be loaded from CSV files.")

    print(f"\n Concatenating all files...", flush=True)
    full_df = pd.concat(dfs, ignore_index=True, sort=False)
    del dfs
    gc.collect()

    # Deduplication across the loaded dataset to prevent train-test leakage
    before_dedup = len(full_df)
    full_df.drop_duplicates(inplace=True)
    dedup_removed = before_dedup - len(full_df)
    print(f"🛡️ Deduplication: removed {dedup_removed:,} duplicate rows ({dedup_removed/max(1, before_dedup)*100:.2f}%)")
    print(f"✅ Total dataset ready: {len(full_df):,} rows, {len(full_df.columns)} columns")
    return full_df, file_stats


# ==============================================================================
# Feature Cleaning & Data Leakage Elimination
# ==============================================================================
def clean_features_and_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, str, List[str]]:
    """
    Cleans DataFrame, removes data leakage and non-numeric columns,
    and returns features DataFrame X and labels Series y.
    """
    df.columns = df.columns.str.strip()
    label_col = detect_label_col(df)
    print(f"🏷️ Detected Label column: '{label_col}'")

    y = df[label_col].astype(str).str.strip().replace(LABEL_NORMALIZATION).copy()

    # Drop label column from feature set
    df.drop(columns=[label_col], inplace=True)

    # Drop explicit leakage columns
    cols_to_drop = [c for c in LEAKAGE_COLUMNS if c in df.columns]
    if cols_to_drop:
        print(f"🛡️ Dropping {len(cols_to_drop)} data leakage/index columns: {cols_to_drop}")
        df.drop(columns=cols_to_drop, inplace=True)

    # Drop all-NaN columns
    df.dropna(axis=1, how='all', inplace=True)

    # Replace inf and -inf with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Select only numeric feature columns
    X = df.select_dtypes(include=[np.number])
    del df
    gc.collect()

    feature_columns = list(X.columns)
    print(f"✅ Retained {len(feature_columns)} clean numeric features")

    return X, y, label_col, feature_columns



# ==============================================================================
# Preprocessing Pipeline (Median Imputer + StandardScaler)
# ==============================================================================
class PreprocessingPipeline:
    """
    Leakage-free preprocessing pipeline fitted strictly on training data.
    Imputes missing values with feature medians and applies standard scaling.
    """
    def __init__(self, feature_columns: List[str]):
        self.feature_columns = feature_columns
        self.medians: Dict[str, float] = {}
        self.scaler = StandardScaler()

    def fit(self, X_train: pd.DataFrame):
        for col in self.feature_columns:
            if col in X_train.columns:
                med = float(X_train[col].median(skipna=True))
                self.medians[col] = 0.0 if np.isnan(med) else med
            else:
                self.medians[col] = 0.0

        X_imp = X_train.copy()
        for col in self.feature_columns:
            if col in X_imp.columns:
                X_imp[col].fillna(self.medians[col], inplace=True)
            else:
                X_imp[col] = self.medians[col]

        X_imp = X_imp[self.feature_columns]
        self.scaler.fit(X_imp)
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        X_imp = X.copy()
        for col in self.feature_columns:
            if col in X_imp.columns:
                X_imp[col].fillna(self.medians.get(col, 0.0), inplace=True)
            else:
                X_imp[col] = self.medians.get(col, 0.0)
        X_imp = X_imp[self.feature_columns]
        return self.scaler.transform(X_imp)

    def fit_transform(self, X_train: pd.DataFrame) -> np.ndarray:
        self.fit(X_train)
        return self.transform(X_train)


# ==============================================================================
# Model Factory & Configurations
# ==============================================================================
def get_candidate_models(
    num_classes: int,
    random_state: int = 42,
    n_jobs: int = -1,
    selected_models: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Instantiates candidate models with progressively tuned, native hyperparameters.
    Each model is configured according to its own architecture:
    - XGBoost: Histogram tree method, max_depth=8, subsample=0.85, multi:softprob.
    - CatBoost: MultiClass loss, depth=6, auto_class_weights='Balanced', iterations=150.
    - ExtraTrees: class_weight='balanced', max_depth=25, min_samples_split=4, n_estimators=120.
    """
    if selected_models is None:
        selected_models = ['xgboost', 'catboost', 'extratrees']

    models = {}

    # 1. XGBoost Classifier
    if 'xgboost' in selected_models and HAS_XGBOOST:
        models['XGBoost'] = xgb.XGBClassifier(
            objective='multi:softprob',
            num_class=num_classes,
            eval_metric='mlogloss',
            max_depth=8,
            learning_rate=0.08,
            n_estimators=150,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_weight=2,
            tree_method='hist',
            random_state=random_state,
            n_jobs=n_jobs
        )

    # 2. CatBoost Classifier
    if 'catboost' in selected_models and HAS_CATBOOST:
        models['CatBoost'] = cb.CatBoostClassifier(
            loss_function='MultiClass',
            iterations=180,
            depth=7,
            learning_rate=0.08,
            auto_class_weights='SqrtBalanced',
            thread_count=n_jobs if n_jobs > 0 else -1,
            random_seed=random_state,
            verbose=False
        )

    # 3. Extra Trees Classifier
    if 'extratrees' in selected_models:
        models['ExtraTrees'] = ExtraTreesClassifier(
            n_estimators=150,
            max_depth=26,
            min_samples_split=4,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=n_jobs
        )

    # 4. HistGradientBoosting Classifier (Optional sklearn native)
    if 'histgb' in selected_models:
        models['HistGradientBoosting'] = HistGradientBoostingClassifier(
            max_iter=120,
            learning_rate=0.08,
            max_depth=18,
            class_weight='balanced',
            random_state=random_state
        )

    # 5. LightGBM Classifier (Optional)
    if 'lightgbm' in selected_models and HAS_LIGHTGBM:
        models['LightGBM'] = lgb.LGBMClassifier(
            objective='multiclass',
            num_class=num_classes,
            max_depth=10,
            learning_rate=0.08,
            n_estimators=120,
            subsample=0.85,
            colsample_bytree=0.85,
            class_weight='balanced',
            random_state=random_state,
            n_jobs=n_jobs,
            verbosity=-1
        )

    return models


def fit_model_with_appropriate_weighting(
    model_name: str,
    model_obj: Any,
    X_tr: np.ndarray,
    y_tr: np.ndarray,
    sample_weights_tr: np.ndarray,
    X_v: Optional[np.ndarray] = None,
    y_v: Optional[np.ndarray] = None
):
    """
    Fits each model using its native, correct class-balancing mechanism:
    - XGBoost: Passes sample_weight directly to .fit().
    - CatBoost: auto_class_weights='Balanced' configured in constructor.
    - ExtraTrees: class_weight='balanced' configured in constructor.
    """
    if model_name == 'XGBoost':
        model_obj.fit(X_tr, y_tr, sample_weight=sample_weights_tr)
    elif model_name == 'CatBoost':
        model_obj.fit(X_tr, y_tr, verbose=False)
    elif model_name == 'ExtraTrees':
        model_obj.fit(X_tr, y_tr)
    else:
        try:
            model_obj.fit(X_tr, y_tr, sample_weight=sample_weights_tr)
        except TypeError:
            model_obj.fit(X_tr, y_tr)


# ==============================================================================
# Dual-Track Metrics: Multi-Class & Binary Evaluation
# ==============================================================================
def compute_multiclass_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_pred_proba: Optional[np.ndarray],
    num_classes: int
) -> Dict[str, float]:
    """Calculates evaluation metrics across all 13 attack classes."""
    acc = float(accuracy_score(y_true, y_pred))
    prec_macro = float(precision_score(y_true, y_pred, average='macro', zero_division=0))
    prec_weighted = float(precision_score(y_true, y_pred, average='weighted', zero_division=0))
    rec_macro = float(recall_score(y_true, y_pred, average='macro', zero_division=0))
    rec_weighted = float(recall_score(y_true, y_pred, average='weighted', zero_division=0))
    f1_macro = float(f1_score(y_true, y_pred, average='macro', zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average='weighted', zero_division=0))

    auc_macro = 0.0
    if y_pred_proba is not None:
        try:
            y_bin = label_binarize(y_true, classes=range(num_classes))
            if y_bin.shape[1] == y_pred_proba.shape[1]:
                auc_macro = float(roc_auc_score(y_bin, y_pred_proba, average='macro', multi_class='ovr'))
        except Exception:
            auc_macro = 0.0

    return {
        'Accuracy': acc,
        'Precision_Macro': prec_macro,
        'Precision_Weighted': prec_weighted,
        'Recall_Macro': rec_macro,
        'Recall_Weighted': rec_weighted,
        'F1_Macro': f1_macro,
        'F1_Weighted': f1_weighted,
        'AUC_ROC_Macro': auc_macro
    }


def compute_binary_metrics(
    y_true_multiclass: np.ndarray,
    y_pred_multiclass: np.ndarray,
    y_pred_proba: Optional[np.ndarray],
    benign_idx: int = 0
) -> Dict[str, Any]:
    """
    Computes rigorous Binary DDoS Detection metrics: BENIGN (0) vs ANY ATTACK (1).
    Kept strictly independent of multi-class sub-type metrics.
    """
    y_true_bin = (y_true_multiclass != benign_idx).astype(int)
    y_pred_bin = (y_pred_multiclass != benign_idx).astype(int)

    acc = float(accuracy_score(y_true_bin, y_pred_bin))
    prec = float(precision_score(y_true_bin, y_pred_bin, zero_division=0))
    rec = float(recall_score(y_true_bin, y_pred_bin, zero_division=0))  # True Positive Rate / Detection Rate
    f1 = float(f1_score(y_true_bin, y_pred_bin, zero_division=0))

    cm = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    auc_val = 0.0
    if y_pred_proba is not None:
        try:
            # Probability of attack = 1.0 - P(BENIGN)
            p_attack = 1.0 - y_pred_proba[:, benign_idx]
            auc_val = float(roc_auc_score(y_true_bin, p_attack))
        except Exception:
            pass

    return {
        'Binary_Accuracy': acc,
        'Binary_Precision': prec,
        'Binary_Recall_DetectionRate': rec,
        'Binary_F1': f1,
        'Binary_Specificity': specificity,
        'Binary_False_Positive_Rate': fpr,
        'Binary_False_Negative_Rate': fnr,
        'Binary_AUC_ROC': auc_val,
        'True_Negatives_BENIGN': int(tn),
        'False_Positives_Alarm': int(fp),
        'False_Negatives_Missed': int(fn),
        'True_Positives_ATTACK': int(tp)
    }


# ==============================================================================
# Plotting & Visualization Functions
# ==============================================================================
def plot_confusion_matrices(y_true: np.ndarray, y_pred: np.ndarray, labels: List[str], plots_dir: Path):
    """Generates both raw count and normalized confusion matrix plots for multi-class."""
    cm = confusion_matrix(y_true, y_pred, labels=range(len(labels)))

    # Raw counts
    plt.figure(figsize=(12, 10))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.title('Multi-Class Confusion Matrix (Raw Counts)', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(plots_dir / "confusion_matrix.png", dpi=120)
    plt.close()

    # Normalized percentage
    cm_norm = cm.astype('float') / np.maximum(cm.sum(axis=1)[:, np.newaxis], 1e-9)
    plt.figure(figsize=(12, 10))
    sns.heatmap(cm_norm, annot=True, fmt='.2f', cmap='Greens', xticklabels=labels, yticklabels=labels)
    plt.title('Multi-Class Confusion Matrix (Normalized)', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(plots_dir / "confusion_matrix_normalized.png", dpi=120)
    plt.close()


def plot_binary_confusion_matrix(y_true_multiclass: np.ndarray, y_pred_multiclass: np.ndarray, benign_idx: int, plots_dir: Path):
    """Generates 2x2 binary confusion matrix plot: BENIGN vs ATTACK."""
    y_true_bin = (y_true_multiclass != benign_idx).astype(int)
    y_pred_bin = (y_pred_multiclass != benign_idx).astype(int)
    cm = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1])

    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges',
                xticklabels=['BENIGN', 'ATTACK'], yticklabels=['BENIGN', 'ATTACK'])
    plt.title('Binary DDoS Detection Matrix (Benign vs Attack)', fontsize=12, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=11)
    plt.ylabel('True Ground Truth', fontsize=11)
    plt.tight_layout()
    plt.savefig(plots_dir / "binary_confusion_matrix.png", dpi=120)
    plt.close()


def plot_per_class_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: List[str], plots_dir: Path):
    """Plots precision, recall, and F1-score for each individual attack class."""
    rep = classification_report(y_true, y_pred, target_names=labels, output_dict=True, zero_division=0)
    classes = [c for c in labels if c in rep]
    precision = [rep[c]['precision'] for c in classes]
    recall = [rep[c]['recall'] for c in classes]
    f1 = [rep[c]['f1-score'] for c in classes]

    x = np.arange(len(classes))
    width = 0.25

    plt.figure(figsize=(15, 6))
    plt.bar(x - width, precision, width, label='Precision', color='#1f77b4')
    plt.bar(x, recall, width, label='Recall', color='#2ca02c')
    plt.bar(x + width, f1, width, label='F1-Score', color='#ff7f0e')

    plt.xlabel('Attack Classes', fontsize=12)
    plt.ylabel('Score', fontsize=12)
    plt.title('Per-Class Performance Metrics (Precision, Recall, F1)', fontsize=14, fontweight='bold')
    plt.xticks(x, classes, rotation=45, ha='right')
    plt.ylim(0, 1.05)
    plt.legend(loc='lower right')
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(plots_dir / "per_class_metrics.png", dpi=120)
    plt.close()


def plot_multiclass_roc(y_true: np.ndarray, y_pred_proba: Optional[np.ndarray], labels: List[str], plots_dir: Path):
    """Generates One-vs-Rest ROC curves for each attack class."""
    if y_pred_proba is None:
        return

    n_classes = len(labels)
    y_bin = label_binarize(y_true, classes=range(n_classes))
    if y_bin.shape[1] != y_pred_proba.shape[1]:
        return

    plt.figure(figsize=(12, 8))
    colors = plt.cm.tab20(np.linspace(0, 1, n_classes))

    for i in range(n_classes):
        try:
            fpr, tpr, _ = roc_curve(y_bin[:, i], y_pred_proba[:, i])
            roc_auc = auc(fpr, tpr)
            plt.plot(fpr, tpr, color=colors[i], lw=2, label=f'{labels[i]} (AUC = {roc_auc:.3f})')
        except Exception:
            pass

    plt.plot([0, 1], [0, 1], 'k--', lw=1.5)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('Multi-Class One-vs-Rest ROC Curves', fontsize=14, fontweight='bold')
    plt.legend(loc="lower right", fontsize=9)
    plt.tight_layout()
    plt.savefig(plots_dir / "roc_curves.png", dpi=120)
    plt.close()


def plot_feature_importance(model: Any, feature_names: List[str], plots_dir: Path, top_n: int = 25):
    """Plots top N most important features if model exposes feature_importances_."""
    if not hasattr(model, 'feature_importances_'):
        return

    try:
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]
        top_features = [feature_names[i] for i in indices]
        top_scores = importances[indices]

        plt.figure(figsize=(12, 8))
        plt.barh(range(len(top_features)), top_scores[::-1], color='#1976d2', align='center')
        plt.yticks(range(len(top_features)), top_features[::-1], fontsize=10)
        plt.xlabel('Relative Feature Importance Score', fontsize=12)
        plt.title(f'Top {top_n} Most Important Features ({type(model).__name__})', fontsize=14, fontweight='bold')
        plt.grid(axis='x', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(plots_dir / "feature_importance.png", dpi=120)
        plt.close()
    except Exception as ex:
        print(f"      [Warning] Feature importance plot: {ex}")


# ==============================================================================
# Markdown Summary Report Generator
# ==============================================================================
def generate_markdown_report(
    output_dir: Path,
    best_model_name: str,
    multi_metrics: Dict[str, float],
    binary_metrics: Dict[str, Any],
    comparison_df: pd.DataFrame,
    cls_report_df: pd.DataFrame,
    labels: List[str],
    dataset_shape: Tuple[int, int],
    num_features: int,
    class_distribution: Dict[str, Any],
    start_time: float
):
    """Creates a comprehensive, bulletproof training report in markdown."""
    elapsed_time = round(time.time() - start_time, 2)
    report_file = output_dir / "training_report.md"

    md = [
        "# 🛡️ DDoS-Guard: High-Performance Model Evaluation Report (Top 3 Run)",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Total Execution Duration:** {elapsed_time} seconds  ",
        f"**Selected Champion Model:** `{best_model_name}`  ",
        f"**Target Output Directory:** `{output_dir.name}`  ",
        "",
        "---",
        "## 1. Dataset & Class Distribution",
        f"- **Dataset Source:** {'CIC-IDS2017 (8 CSVs in Data Base)' if 'new_dataset' in str(output_dir) or len(labels) == 15 else 'CIC-DDoS2019 (01-12) via Multi-Segment Distributed Sampling'}",
        f"- **Total Rows Processed:** {dataset_shape[0]:,}",
        f"- **Clean Numeric Features:** {num_features}",
        f"- **Classes Count ({len(labels)}):** `{', '.join(labels)}`",
        "",
        "### Sample Counts Across Partitions:",
        f"- **Training Split (70%):** {class_distribution.get('train_total', 0):,} samples",
        f"- **Validation Split (10%):** {class_distribution.get('val_total', 0):,} samples",
        f"- **Isolated Test Split (20%):** {class_distribution.get('test_total', 0):,} samples",
        "",
        "---",
        "## 2. Multi-Model Validation Comparison (Champion Selection)",
        "",
    ]

    try:
        table_str = comparison_df.to_markdown(index=False)
    except Exception:
        cols = list(comparison_df.columns)
        table_str = "| " + " | ".join(cols) + " |\n"
        table_str += "| " + " | ".join([":---"] * len(cols)) + " |\n"
        for _, row in comparison_df.iterrows():
            table_str += "| " + " | ".join(str(val) for val in row.values) + " |\n"

    md.extend([
        table_str,
        "",
        "---",
        "## 3. Dual-Track Performance on Isolated Test Set",
        "",
        "### Track A: Binary Attack Detection (BENIGN vs DDoS ATTACK)",
        "",
        f"| Binary Detection Metric | Score | Practical Significance |",
        f"| :--- | :--- | :--- |",
        f"| **Detection Rate (Recall / TPR)** | **{binary_metrics.get('Binary_Recall_DetectionRate', 0)*100:.2f}%** | Percentage of real DDoS attacks successfully intercepted |",
        f"| **Binary Accuracy** | **{binary_metrics.get('Binary_Accuracy', 0)*100:.2f}%** | Global correctness between benign & attack packets |",
        f"| **Binary Precision** | {binary_metrics.get('Binary_Precision', 0)*100:.2f}% | Reliability of alerts when system flags traffic |",
        f"| **Specificity (TNR)** | {binary_metrics.get('Binary_Specificity', 0)*100:.2f}% | Legitimate user traffic passed without false alarm |",
        f"| **False Alarm Rate (FPR)** | {binary_metrics.get('Binary_False_Positive_Rate', 0)*100:.2f}% | Legitimate traffic wrongly blocked |",
        f"| **Missed Attack Rate (FNR)** | {binary_metrics.get('Binary_False_Negative_Rate', 0)*100:.2f}% | Attacks slipping undetected past the shield |",
        f"| **Binary F1-Score** | **{binary_metrics.get('Binary_F1', 0):.4f}** | Harmonic mean of detection precision and recall |",
        f"| **Binary AUC-ROC** | **{binary_metrics.get('Binary_AUC_ROC', 0):.4f}** | Probability threshold discriminative power |",
        "",
        f"### Track B: Multi-Class Attack Sub-Type Classification ({len(labels)} Categories)",
        "",
        f"| Multi-Class Metric | Score |",
        f"| :--- | :--- |",
        f"| **Test Accuracy** | **{multi_metrics.get('Accuracy', 0)*100:.2f}%** |",
        f"| **Macro F1-Score** | **{multi_metrics.get('F1_Macro', 0):.4f}** |",
        f"| **Weighted F1-Score** | **{multi_metrics.get('F1_Weighted', 0):.4f}** |",
        f"| **Macro Precision** | {multi_metrics.get('Precision_Macro', 0):.4f} |",
        f"| **Macro Recall** | {multi_metrics.get('Recall_Macro', 0):.4f} |",
        f"| **Macro AUC-ROC** | {multi_metrics.get('AUC_ROC_Macro', 0):.4f} |",
        "",
        "---",
        "## 4. Per-Class Precision, Recall & F1 Breakdown",
        "",
    ])

    try:
        report_table = cls_report_df.to_markdown()
    except Exception:
        report_table = cls_report_df.to_string()

    md.extend([
        report_table,
        "",
        "---",
        "## 5. Before vs. After Benchmark Comparison Across All Experiments",
        "",
        "| Metric | Legacy (`final output`) | Run 1 (`final_output_optimized`) | Run 2 (`final_output_top3`) | Run 3 (`final_output_optimized_v2`) | New Dataset (`final_output_new_dataset`) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
        "| **Dataset Source** | CIC-DDoS2019 (01-12) | CIC-DDoS2019 (01-12) | CIC-DDoS2019 (01-12) | CIC-DDoS2019 (01-12) | CIC-IDS2017 (Data Base 8 CSVs) |",
        "| **Data Leakage Elimination** | ❌ (Contained Unnamed:0) | ✅ 100% Clean | ✅ 100% Clean | ✅ 100% Clean | ✅ 100% Clean (0 Identifiers) |",
        f"| **Classes Count** | 13 | 13 | 13 | 13 | **{len(labels)} Classes** |",
        "| **Rare Attack Protection** | None (F1: ~0.0) | 41 samples | 88 samples | 100% Preserved | **100% Preserved (All Rare Types)** |",
        f"| **Multi-Class Accuracy** | 88.42% (TFTP skewed) | 81.34% | 75.78% | 76.54% | **{multi_metrics.get('Accuracy', 0)*100:.2f}%** |",
        f"| **Macro F1-Score** | 73.28% | 76.55% | 73.23% | 74.82% | **{multi_metrics.get('F1_Macro', 0):.4f}** |",
        f"| **Binary Detection Rate** | Not Separated | Not Separated | 99.998% | 99.998% | **{binary_metrics.get('Binary_Recall_DetectionRate', 0)*100:.4f}%** |",
        f"| **Binary AUC-ROC** | 0.9907 | 0.9880 | 1.0000 | 1.0000 | **{binary_metrics.get('Binary_AUC_ROC', 0):.4f}** |",
        "",
        "---",
        "## 6. Output Artifacts Directory Inventory",
        "",
        f"- **Models:** `{output_dir.name}/models/best_model.joblib`, `scaler.joblib`, `preprocessing_pipeline.joblib`",
        f"- **Configs:** `{output_dir.name}/configs/label_mapping.json`, `feature_columns.json`, `training_config.json`",
        f"- **Reports:** `{output_dir.name}/reports/dataset_audit_report.json`, `multiclass_classification_report.csv`, `binary_metrics.json`, `confusion_matrix.csv`, `binary_confusion_matrix.csv`, `final_report.md`",
        f"- **Plots:** `{output_dir.name}/plots/confusion_matrix.png`, `binary_confusion_matrix.png`, `roc_curves.png`, `feature_importance.png`",
        f"- **Datasets:** `{output_dir.name}/datasets/test_set.csv` (Independent holdout test set)",
        "",
        "---",
        "*Report generated automatically by DDoS-Guard Advanced Training Pipeline.*"
    ])

    report_content = '\n'.join(md)
    for target_name in ["training_report.md", "final_report.md"]:
        try:
            with open(output_dir / target_name, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"   ✓ Markdown Report generated at: {output_dir / target_name}")
        except Exception as ex:
            print(f"   [Warning] Could not write report file {target_name}: {ex}")


# ==============================================================================
# Main Training Routine
# ==============================================================================
def run_training_pipeline(args: argparse.Namespace):
    """Executes the complete, leakage-free training, comparison, and evaluation pipeline."""
    start_time = time.time()
    dataset_dir = Path(args.data_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    print("=" * 80)
    print("       🛡️  DDoS-Guard: Advanced Model Training & Comparison Pipeline  🛡️")
    print(f"                      Target Output: {output_dir.name}")
    print("=" * 80)
    print(f"Dataset directory : {dataset_dir}")
    print(f"Output directory  : {output_dir}")
    print(f"Max samples/file  : {args.max_samples}")
    print(f"Candidate models  : {args.models}")
    print(f"Random seed       : {args.random_seed}")
    print(f"Parallel jobs     : {args.n_jobs}")
    print("=" * 80)

    # 1. Directory Structure
    paths = create_project_directories(output_dir)

    # Copy dataset_audit_report.json to reports if available
    root_audit = BASE_DIR / "dataset_audit_report.json"
    if root_audit.exists():
        try:
            import shutil
            shutil.copy2(root_audit, paths['reports'] / "dataset_audit_report.json")
            print(f"   ✓ Copied dataset_audit_report.json to: {paths['reports']}")
        except Exception as ex:
            print(f"   [Warning] Could not copy audit report: {ex}")

    # 2. Dataset Loading with Rare-Class Protection and Deduplication
    df, file_stats = load_dataset_balanced(
        dataset_dir,
        chunksize=args.chunksize,
        max_samples_per_file=args.max_samples,
        random_state=args.random_seed
    )

    # 3. Clean Features & Remove Data Leakage
    print("\n🔧 Cleaning features and eliminating data leakage...")
    X, y, label_col_name, feature_columns = clean_features_and_labels(df)
    dataset_shape = X.shape

    # Save feature names order
    with open(paths['configs'] / "feature_columns.json", 'w', encoding='utf-8') as f:
        json.dump(feature_columns, f, indent=2)

    # 4. Encode Labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    num_classes = len(le.classes_)
    label_mapping = {int(i): str(label) for i, label in enumerate(le.classes_)}
    
    benign_candidates = [i for i, c in enumerate(le.classes_) if str(c).lower() in ['benign', 'normal', 'safe']]
    benign_idx = int(benign_candidates[0]) if benign_candidates else 0

    print(f"🏷️ Total classes identified ({num_classes}): {list(le.classes_)}")
    print(f"🏷️ Detected BENIGN class index: {benign_idx} ('{le.classes_[benign_idx]}')")

    with open(paths['configs'] / "label_mapping.json", 'w', encoding='utf-8') as f:
        json.dump(label_mapping, f, indent=2)


    # 5. Strict Three-Way Split: 70% Train, 10% Validation, 20% Holdout Test
    print("\n✂️ Splitting data: 70% Train, 10% Validation, 20% Holdout Test...")
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y_encoded, test_size=0.20, stratify=y_encoded, random_state=args.random_seed
    )

    # Save Isolated Test Set with ground-truth string labels
    print("💾 Saving clean isolated Test Set...")
    test_set_df = X_test.copy()
    test_set_df['Label'] = le.inverse_transform(y_test)
    test_csv_path = paths['datasets'] / "test_set.csv"
    test_set_df.to_csv(test_csv_path, index=False)
    print(f"   ✓ Test Set preserved at: {test_csv_path} ({len(test_set_df):,} samples)")
    del test_set_df
    gc.collect()

    # Split Train and Validation (10% of total = 0.125 of 80%)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.125, stratify=y_train_val, random_state=args.random_seed
    )

    del X, y, y_encoded, X_train_val, y_train_val
    gc.collect()

    # 6. Compute and Inspect Class Distributions across Partitions
    train_dist = {str(le.classes_[k]): int(v) for k, v in pd.Series(y_train).value_counts().to_dict().items()}
    val_dist = {str(le.classes_[k]): int(v) for k, v in pd.Series(y_val).value_counts().to_dict().items()}
    test_dist = {str(le.classes_[k]): int(v) for k, v in pd.Series(y_test).value_counts().to_dict().items()}

    class_distribution = {
        'train_total': len(X_train),
        'val_total': len(X_val),
        'test_total': len(X_test),
        'train_class_counts': train_dist,
        'val_class_counts': val_dist,
        'test_class_counts': test_dist
    }
    with open(paths['reports'] / "class_distribution.json", 'w', encoding='utf-8') as f:
        json.dump(class_distribution, f, indent=2)

    print(f"   Train samples     : {len(X_train):,}")
    print(f"   Validation samples: {len(X_val):,}")
    print(f"   Test samples      : {len(X_test):,}")
    print(f"   Train WebDDoS count: {train_dist.get('WebDDoS', 0):,} | BENIGN count: {train_dist.get('BENIGN', 0):,}")

    # 7. Compute Class Weights strictly on y_train
    print("\n⚖️ Computing smoothed balanced sample weights strictly on y_train...")
    raw_weights = compute_sample_weight('balanced', y_train)
    sample_weights_train = np.clip(raw_weights, 0.5, 10.0)
    print(f"   ✓ Sample weights smoothed (max weight: {sample_weights_train.max():.2f}) with zero test/val data leakage.")

    # 8. Fit Preprocessing Pipeline strictly on X_train
    print("\n📏 Fitting preprocessing pipeline (Median Imputer + StandardScaler) on X_train ONLY...")
    pipeline = PreprocessingPipeline(feature_columns)
    X_train_scaled = pipeline.fit_transform(X_train)
    X_val_scaled = pipeline.transform(X_val)
    X_test_scaled = pipeline.transform(X_test)
    print("   ✓ Preprocessing fitted and transformed with ZERO data leakage.")

    # Save preprocessing artifacts
    joblib.dump(pipeline.scaler, paths['models'] / "scaler.joblib")
    joblib.dump(pipeline, paths['models'] / "preprocessing_pipeline.joblib")

    # 9. Multi-Model Comparison on Validation Set
    selected_model_keys = [m.strip().lower() for m in args.models.split(',')]
    candidate_models = get_candidate_models(
        num_classes=num_classes,
        random_state=args.random_seed,
        n_jobs=args.n_jobs,
        selected_models=selected_model_keys
    )

    print(f"\n🤖 Starting Model Comparison across {len(candidate_models)} candidate model(s)...")
    comparison_results = []
    trained_models = {}

    for name, model_obj in candidate_models.items():
        print(f"\n   ➤ Training [{name}] with native balanced class weighting...", flush=True)
        m_start = time.time()

        try:
            fit_model_with_appropriate_weighting(
                model_name=name,
                model_obj=model_obj,
                X_tr=X_train_scaled,
                y_tr=y_train,
                sample_weights_tr=sample_weights_train,
                X_v=X_val_scaled,
                y_v=y_val
            )

            train_duration = round(time.time() - m_start, 2)
            trained_models[name] = model_obj

            # Evaluate on Validation set
            val_preds = model_obj.predict(X_val_scaled)
            val_acc = accuracy_score(y_val, val_preds)
            val_f1_macro = f1_score(y_val, val_preds, average='macro', zero_division=0)
            val_f1_weighted = f1_score(y_val, val_preds, average='weighted', zero_division=0)
            val_recall_macro = recall_score(y_val, val_preds, average='macro', zero_division=0)

            print(f"     ✓ [{name}] Finished in {train_duration}s | Val Acc: {val_acc:.4f} | Val Macro F1: {val_f1_macro:.4f}")

            comparison_results.append({
                'Model': name,
                'Val_Accuracy': round(float(val_acc), 4),
                'Val_Macro_F1': round(float(val_f1_macro), 4),
                'Val_Weighted_F1': round(float(val_f1_weighted), 4),
                'Val_Macro_Recall': round(float(val_recall_macro), 4),
                'Train_Time_Sec': train_duration
            })
        except Exception as e:
            print(f"     ✗ Error training [{name}]: {e}")

    if not comparison_results:
        raise RuntimeError("No models could be trained successfully.")

    comparison_df = pd.DataFrame(comparison_results)
    comparison_df.sort_values(by='Val_Macro_F1', ascending=False, inplace=True)
    comparison_csv_path = paths['reports'] / "model_comparison.csv"
    comparison_df.to_csv(comparison_csv_path, index=False)
    print(f"\n📊 Model Comparison Results:\n{comparison_df.to_string(index=False)}")

    # 10. Select Best Model based on Validation Macro F1
    best_model_name = comparison_df.iloc[0]['Model']
    best_model = trained_models[best_model_name]
    print(f"\n🏆 Best Model Selected: [{best_model_name}] (Highest Val Macro F1: {comparison_df.iloc[0]['Val_Macro_F1']})")

    # Save Best Model Artifacts
    best_model_joblib_path = paths['models'] / "best_model.joblib"
    joblib.dump(best_model, best_model_joblib_path)
    joblib.dump(best_model, paths['models'] / "best_model.pht")
    print(f"   ✓ Best model saved to: {best_model_joblib_path}")

    # 11. Dual-Track Evaluation on Isolated Holdout Test Set
    print("\n🎯 Evaluating Best Model on Isolated Test Set (Dual-Track)...")
    test_preds = best_model.predict(X_test_scaled)
    test_proba = None
    if hasattr(best_model, 'predict_proba'):
        try:
            test_proba = best_model.predict_proba(X_test_scaled)
        except Exception:
            test_proba = None

    # Track A: Binary Metrics
    binary_metrics = compute_binary_metrics(y_test, test_preds, test_proba, benign_idx=benign_idx)
    print(f"\n   [Track A: Binary Attack Detection (BENIGN vs ATTACK)]")
    print(f"   Detection Rate (Recall) : {binary_metrics['Binary_Recall_DetectionRate']*100:.2f}%")
    print(f"   Binary Accuracy         : {binary_metrics['Binary_Accuracy']*100:.2f}%")
    print(f"   Binary Precision        : {binary_metrics['Binary_Precision']*100:.2f}%")
    print(f"   Specificity (TNR)       : {binary_metrics['Binary_Specificity']*100:.2f}%")
    print(f"   Binary F1-Score         : {binary_metrics['Binary_F1']:.4f}")
    print(f"   Binary AUC-ROC          : {binary_metrics['Binary_AUC_ROC']:.4f}")

    # Track B: Multi-Class Metrics
    multi_metrics = compute_multiclass_metrics(y_test, test_preds, test_proba, num_classes)
    print(f"\n   [Track B: Multi-Class Attack Classification (13 Categories)]")
    print(f"   Accuracy    : {multi_metrics['Accuracy']:.4f}")
    print(f"   Macro F1    : {multi_metrics['F1_Macro']:.4f}")
    print(f"   Weighted F1 : {multi_metrics['F1_Weighted']:.4f}")
    print(f"   Macro Recall: {multi_metrics['Recall_Macro']:.4f}")
    if multi_metrics['AUC_ROC_Macro'] > 0:
        print(f"   AUC-ROC     : {multi_metrics['AUC_ROC_Macro']:.4f}")

    # Save Metrics Summaries
    with open(paths['reports'] / "metrics_summary.json", 'w', encoding='utf-8') as f:
        json.dump(multi_metrics, f, indent=2)
    with open(paths['reports'] / "binary_metrics.json", 'w', encoding='utf-8') as f:
        json.dump(binary_metrics, f, indent=2)

    # Classification Reports
    cls_report_dict = classification_report(
        y_test, test_preds, target_names=le.classes_, output_dict=True, zero_division=0
    )
    cls_report_df = pd.DataFrame(cls_report_dict).transpose()
    cls_report_df.to_csv(paths['reports'] / "multiclass_classification_report.csv")

    per_class_list = []
    for cls_name in le.classes_:
        if cls_name in cls_report_dict:
            per_class_list.append({
                'Class': cls_name,
                'Precision': cls_report_dict[cls_name]['precision'],
                'Recall': cls_report_dict[cls_name]['recall'],
                'F1-Score': cls_report_dict[cls_name]['f1-score'],
                'Support': int(cls_report_dict[cls_name]['support'])
            })
    pd.DataFrame(per_class_list).to_csv(paths['reports'] / "per_class_metrics.csv", index=False)

    # Multi-Class Confusion Matrix CSV
    cm = confusion_matrix(y_test, test_preds, labels=range(len(le.classes_)))
    cm_df = pd.DataFrame(cm, index=[f"True_{l}" for l in le.classes_], columns=[f"Pred_{l}" for l in le.classes_])
    cm_df.to_csv(paths['reports'] / "confusion_matrix.csv")

    # Binary Confusion Matrix CSV
    y_test_bin = (y_test != benign_idx).astype(int)
    y_pred_bin = (test_preds != benign_idx).astype(int)
    bin_cm = confusion_matrix(y_test_bin, y_pred_bin, labels=[0, 1])
    bin_cm_df = pd.DataFrame(bin_cm, index=['True_BENIGN', 'True_ATTACK'], columns=['Pred_BENIGN', 'Pred_ATTACK'])
    bin_cm_df.to_csv(paths['reports'] / "binary_confusion_matrix.csv")

    # 12. Plots & Visualizations (with error handling so plotting issues never halt the pipeline)
    print("\n🎨 Generating evaluation plots...")
    try:
        plot_confusion_matrices(y_test, test_preds, list(le.classes_), paths['plots'])
        plot_binary_confusion_matrix(y_test, test_preds, benign_idx, paths['plots'])
        plot_per_class_metrics(y_test, test_preds, list(le.classes_), paths['plots'])
        plot_multiclass_roc(y_test, test_proba, list(le.classes_), paths['plots'])
        plot_feature_importance(best_model, feature_columns, paths['plots'])
        print(f"   ✓ All evaluation plots successfully saved to: {paths['plots']}")
    except Exception as ex:
        print(f"   [Warning] Error generating plots: {ex}")

    # 13. Save Training Configuration Metadata
    training_config = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'dataset_dir': str(dataset_dir),
        'output_dir': str(output_dir),
        'max_samples_per_file': args.max_samples,
        'random_seed': args.random_seed,
        'candidate_models': selected_model_keys,
        'best_model_name': best_model_name,
        'num_features': len(feature_columns),
        'num_classes': num_classes,
        'classes': list(le.classes_),
        'file_sampling_stats': file_stats
    }
    with open(paths['configs'] / "training_config.json", 'w', encoding='utf-8') as f:
        json.dump(training_config, f, indent=2)

    # 14. Markdown Final Report
    generate_markdown_report(
        output_dir=output_dir,
        best_model_name=best_model_name,
        multi_metrics=multi_metrics,
        binary_metrics=binary_metrics,
        comparison_df=comparison_df,
        cls_report_df=cls_report_df,
        labels=list(le.classes_),
        dataset_shape=dataset_shape,
        num_features=len(feature_columns),
        class_distribution=class_distribution,
        start_time=start_time
    )

    total_time = round(time.time() - start_time, 2)
    print("\n" + "=" * 80)
    print(f"🎉 PIPELINE COMPLETED SUCCESSFULLY in {total_time}s!")
    print(f"📁 All artifacts and reports saved to: {output_dir}")
    print("=" * 80 + "\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DDoS-Guard: Advanced Multi-Model Training Pipeline for Network Intrusion and DDoS Detection"
    )
    parser.add_argument(
        '--data-dir', '-d', type=str, default=str(DEFAULT_DATASET_DIR),
        help=f"Path to dataset directory containing CSV files (Default: {DEFAULT_DATASET_DIR})"
    )
    parser.add_argument(
        '--output-dir', '-o', type=str, default=str(DEFAULT_OUTPUT_DIR),
        help=f"Path to save output artifacts and models (Default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        '--max-samples', '-s', type=int, default=50000,
        help="Max common samples per CSV file to balance classes and keep RAM usage optimal (Default: 50,000; set 0 for all)"
    )
    parser.add_argument(
        '--chunksize', '-c', type=int, default=50000,
        help="Chunk size for reading CSVs (Default: 50,000)"
    )
    parser.add_argument(
        '--models', '-m', type=str, default="xgboost,lightgbm,extratrees",
        help="Comma-separated candidate models: xgboost,catboost,extratrees,histgb,lightgbm"
    )
    parser.add_argument(
        '--random-seed', '-r', type=int, default=42,
        help="Random seed for reproducibility (Default: 42)"
    )
    parser.add_argument(
        '--n-jobs', '-j', type=int, default=-1,
        help="Number of CPU threads to utilize (-1 for all CPUs)"
    )
    return parser.parse_args()



if __name__ == "__main__":
    args = parse_arguments()
    if args.max_samples <= 0:
        args.max_samples = None
    run_training_pipeline(args)