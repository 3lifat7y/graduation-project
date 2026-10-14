# 🛡️ DDoS-Guard: High-Performance Model Evaluation Report (Top 3 Run)

**Date:** 2026-10-10 00:59:27  
**Total Execution Duration:** 239.55 seconds  
**Selected Champion Model:** `XGBoost`  
**Target Output Directory:** `final_output_new_dataset`  

---
## 1. Dataset & Class Distribution
- **Dataset Source:** CIC-IDS2017 (8 CSVs in Data Base)
- **Total Rows Processed:** 393,635
- **Clean Numeric Features:** 77
- **Classes Count (15):** `Benign, Bot, DDoS, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, FTP-Patator, Heartbleed, Infiltration, PortScan, SSH-Patator, Web Attack - Brute Force, Web Attack - SQL Injection, Web Attack - XSS`

### Sample Counts Across Partitions:
- **Training Split (70%):** 275,544 samples
- **Validation Split (10%):** 39,364 samples
- **Isolated Test Split (20%):** 78,727 samples

---
## 2. Multi-Model Validation Comparison (Champion Selection)

| Model      |   Val_Accuracy |   Val_Macro_F1 |   Val_Weighted_F1 |   Val_Macro_Recall |   Train_Time_Sec |
|:-----------|---------------:|---------------:|------------------:|-------------------:|-----------------:|
| XGBoost    |         0.9967 |         0.8974 |            0.9968 |             0.9156 |            99.58 |
| LightGBM   |         0.9962 |         0.8963 |            0.9964 |             0.917  |            66.48 |
| ExtraTrees |         0.9497 |         0.7359 |            0.9689 |             0.9069 |            20.94 |

---
## 3. Dual-Track Performance on Isolated Test Set

### Track A: Binary Attack Detection (BENIGN vs DDoS ATTACK)

| Binary Detection Metric | Score | Practical Significance |
| :--- | :--- | :--- |
| **Detection Rate (Recall / TPR)** | **99.86%** | Percentage of real DDoS attacks successfully intercepted |
| **Binary Accuracy** | **99.85%** | Global correctness between benign & attack packets |
| **Binary Precision** | 99.34% | Reliability of alerts when system flags traffic |
| **Specificity (TNR)** | 99.85% | Legitimate user traffic passed without false alarm |
| **False Alarm Rate (FPR)** | 0.15% | Legitimate traffic wrongly blocked |
| **Missed Attack Rate (FNR)** | 0.14% | Attacks slipping undetected past the shield |
| **Binary F1-Score** | **0.9960** | Harmonic mean of detection precision and recall |
| **Binary AUC-ROC** | **1.0000** | Probability threshold discriminative power |

### Track B: Multi-Class Attack Sub-Type Classification (15 Categories)

| Multi-Class Metric | Score |
| :--- | :--- |
| **Test Accuracy** | **99.66%** |
| **Macro F1-Score** | **0.9245** |
| **Weighted F1-Score** | **0.9966** |
| **Macro Precision** | 0.9255 |
| **Macro Recall** | 0.9282 |
| **Macro AUC-ROC** | 0.9998 |

---
## 4. Per-Class Precision, Recall & F1 Breakdown

|                            |   precision |   recall |   f1-score |      support |
|:---------------------------|------------:|---------:|-----------:|-------------:|
| Benign                     |    0.999672 | 0.99847  |   0.99907  | 64039        |
| Bot                        |    0.809117 | 0.986111 |   0.888889 |   288        |
| DDoS                       |    0.99948  | 0.999307 |   0.999394 |  5773        |
| DoS GoldenEye              |    0.99854  | 0.997569 |   0.998054 |  2057        |
| DoS Hulk                   |    0.992766 | 0.997763 |   0.995258 |  1788        |
| DoS Slowhttptest           |    0.985769 | 0.993308 |   0.989524 |  1046        |
| DoS slowloris              |    0.996289 | 0.997214 |   0.996752 |  1077        |
| FTP-Patator                |    1        | 0.998314 |   0.999156 |  1186        |
| Heartbleed                 |    1        | 1        |   1        |     2        |
| Infiltration               |    0.875    | 1        |   0.933333 |     7        |
| PortScan                   |    0.969849 | 0.987212 |   0.978454 |   391        |
| SSH-Patator                |    1        | 0.995342 |   0.997665 |   644        |
| Web Attack - Brute Force   |    0.760383 | 0.809524 |   0.784185 |   294        |
| Web Attack - SQL Injection |    1        | 0.75     |   0.857143 |     4        |
| Web Attack - XSS           |    0.495413 | 0.412214 |   0.45     |   131        |
| accuracy                   |    0.996583 | 0.996583 |   0.996583 |     0.996583 |
| macro avg                  |    0.925485 | 0.928156 |   0.924458 | 78727        |
| weighted avg               |    0.996659 | 0.996583 |   0.996578 | 78727        |

---
## 5. Before vs. After Benchmark Comparison Across All Experiments

| Metric | Legacy (`final output`) | Run 1 (`final_output_optimized`) | Run 2 (`final_output_top3`) | Run 3 (`final_output_optimized_v2`) | New Dataset (`final_output_new_dataset`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Dataset Source** | CIC-DDoS2019 (01-12) | CIC-DDoS2019 (01-12) | CIC-DDoS2019 (01-12) | CIC-DDoS2019 (01-12) | CIC-IDS2017 (Data Base 8 CSVs) |
| **Data Leakage Elimination** | ❌ (Contained Unnamed:0) | ✅ 100% Clean | ✅ 100% Clean | ✅ 100% Clean | ✅ 100% Clean (0 Identifiers) |
| **Classes Count** | 13 | 13 | 13 | 13 | **15 Classes** |
| **Rare Attack Protection** | None (F1: ~0.0) | 41 samples | 88 samples | 100% Preserved | **100% Preserved (All Rare Types)** |
| **Multi-Class Accuracy** | 88.42% (TFTP skewed) | 81.34% | 75.78% | 76.54% | **99.66%** |
| **Macro F1-Score** | 73.28% | 76.55% | 73.23% | 74.82% | **0.9245** |
| **Binary Detection Rate** | Not Separated | Not Separated | 99.998% | 99.998% | **99.8570%** |
| **Binary AUC-ROC** | 0.9907 | 0.9880 | 1.0000 | 1.0000 | **1.0000** |

---
## 6. Output Artifacts Directory Inventory

- **Models:** `final_output_new_dataset/models/best_model.joblib`, `scaler.joblib`, `preprocessing_pipeline.joblib`
- **Configs:** `final_output_new_dataset/configs/label_mapping.json`, `feature_columns.json`, `training_config.json`
- **Reports:** `final_output_new_dataset/reports/dataset_audit_report.json`, `multiclass_classification_report.csv`, `binary_metrics.json`, `confusion_matrix.csv`, `binary_confusion_matrix.csv`, `final_report.md`
- **Plots:** `final_output_new_dataset/plots/confusion_matrix.png`, `binary_confusion_matrix.png`, `roc_curves.png`, `feature_importance.png`
- **Datasets:** `final_output_new_dataset/datasets/test_set.csv` (Independent holdout test set)

---
*Report generated automatically by DDoS-Guard Advanced Training Pipeline.*