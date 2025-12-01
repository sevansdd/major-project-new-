#!/usr/bin/env python3
# anomoly_detector.py (anomaly_detector)
"""
Anomaly detector using both heuristics + ML models:

 - Reads: processed_data/preprocessed.csv
 - Uses features like: size, entropy, extension type, etc.
 - Runs:
      * IsolationForest
      * LocalOutlierFactor (LOF)
 - Combines both ML anomaly scores + old deterministic heuristic score
 - Writes: processed_data/anomalies.csv with extra columns:
      iso_score, lof_score, anomaly_score, heuristic_score, total_score, risk
"""

import pathlib
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

ROOT = pathlib.Path.cwd()
IN_CSV = ROOT / "processed_data" / "preprocessed.csv"
OUT_CSV = ROOT / "processed_data" / "anomalies.csv"


def safe_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


def deterministic_risk_score(row):
    """
    Original heuristic, but returns numeric risk_score instead of label.
    This is taken from your previous anomaly_detector.py logic. :contentReference[oaicite:1]{index=1}
    """
    risk_score = 0
    fname = str(row.get("file_name") or "").lower()
    ext = pathlib.Path(fname).suffix.lower()
    ent = safe_float(row.get("entropy") or row.get("ent") or 0)
    size = safe_float(row.get("size") or 0)

    # extension heuristic
    if ext in (".exe", ".dll", ".scr", ".bat"):
        risk_score += 2

    # entropy heuristic
    if ent >= 7.0:
        risk_score += 3
    elif ent >= 6.0:
        risk_score += 1

    # size heuristic
    if size > 200 * 1024 * 1024:  # >200MB
        risk_score += 2
    if size < 1024:  # <1KB
        risk_score += 1

    # placeholder vt/abuse heuristics if present (usually not at this stage, but safe)
    vt_score = safe_float(row.get("vt_score") or row.get("vt") or 0)
    abuse_score = safe_float(row.get("abuse_score") or row.get("abuse") or 0)
    if vt_score >= 10:
        risk_score += 4
    if abuse_score >= 50:
        risk_score += 3

    return risk_score


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Create numeric feature matrix for ML models."""
    # Ensure numeric columns
    df_feat = pd.DataFrame(index=df.index)

    # Size + entropy (from preprocess)
    df_feat["size"] = pd.to_numeric(df.get("size", 0), errors="coerce").fillna(0)
    df_feat["entropy"] = pd.to_numeric(df.get("entropy", 0), errors="coerce").fillna(0)

    # Extension flags
    exts = df.get("file_name", "").astype(str).str.lower().apply(
        lambda x: pathlib.Path(x).suffix.lower()
    )

    # binary features for common risky/benign types
    df_feat["is_exe_like"] = exts.isin([".exe", ".dll", ".scr", ".bat"]).astype(int)
    df_feat["is_doc_like"] = exts.isin([".doc", ".docx", ".pdf"]).astype(int)
    df_feat["is_script_like"] = exts.isin([".js", ".vbs", ".ps1"]).astype(int)
    df_feat["name_length"] = df.get("file_name", "").astype(str).str.len().fillna(0)

    # Optional VT / Abuse (if already present for some reason)
    if "vt_score" in df.columns:
        df_feat["vt_score"] = pd.to_numeric(df["vt_score"], errors="coerce").fillna(0)
    else:
        df_feat["vt_score"] = 0.0

    if "abuse_score" in df.columns:
        df_feat["abuse_score"] = pd.to_numeric(df["abuse_score"], errors="coerce").fillna(0)
    else:
        df_feat["abuse_score"] = 0.0

    return df_feat


def normalize_series(s: pd.Series) -> pd.Series:
    """Min-max normalize to [0,1] (safe for constant series)."""
    s = s.astype(float)
    min_v = s.min()
    max_v = s.max()
    denom = max_v - min_v
    if denom <= 1e-9:
        # all same value → all zeros
        return pd.Series(0.0, index=s.index)
    return (s - min_v) / denom


def assign_risk_labels(total_score: pd.Series) -> pd.Series:
    """
    Map combined total_score to risk labels using quantiles.
      - top ~5% → malicious
      - next ~10–15% → suspicious
      - rest → clean
    For very small datasets we fall back to fixed thresholds.
    """
    n = len(total_score)
    if n == 0:
        return pd.Series([], dtype=str)

    if n >= 20:
        mal_thr = total_score.quantile(0.95)
        sus_thr = total_score.quantile(0.80)
    else:
        # small dataset: use simpler fixed thresholds
        mal_thr = total_score.max() * 0.8
        sus_thr = total_score.max() * 0.4

    def label(val):
        if val >= mal_thr:
            return "malicious"
        elif val >= sus_thr:
            return "suspicious"
        else:
            return "clean"

    return total_score.apply(label)


def main():
    if not IN_CSV.exists():
        print("No preprocessed CSV at", IN_CSV)
        return

    df = pd.read_csv(IN_CSV)
    if df.empty:
        print("preprocessed.csv is empty, nothing to score.")
        df["risk"] = []
        df.to_csv(OUT_CSV, index=False)
        return

    print(f"Loaded {len(df)} rows from {IN_CSV}")

    # ------------------------------------------------------------------
    # 1) Build feature matrix
    # ------------------------------------------------------------------
    X = build_feature_matrix(df)

    # If we have too few samples, we may skip LOF to avoid errors
    n_samples = len(X)
    if n_samples < 2:
        # Degenerate case: just mark everything clean
        df["iso_score"] = 0.0
        df["lof_score"] = 0.0
        df["anomaly_score"] = 0.0
        df["heuristic_score"] = df.apply(deterministic_risk_score, axis=1)
        df["heuristic_score_norm"] = normalize_series(df["heuristic_score"])
        df["total_score"] = df["heuristic_score_norm"]
        df["risk"] = assign_risk_labels(df["total_score"])
        df.to_csv(OUT_CSV, index=False)
        print(f"Wrote {len(df)} anomaly rows to {OUT_CSV} (degenerate small dataset).")
        return

    # ------------------------------------------------------------------
    # 2) Isolation Forest
    # ------------------------------------------------------------------
    try:
        iso = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,
        )
        iso.fit(X)
        # decision_function → higher = more normal. We invert to get anomaly score.
        iso_scores = -iso.decision_function(X)
    except Exception as e:
        print("IsolationForest failed:", e)
        iso_scores = np.zeros(n_samples)

    # ------------------------------------------------------------------
    # 3) Local Outlier Factor
    # ------------------------------------------------------------------
    try:
        # n_neighbors must be < n_samples
        n_neighbors = min(20, max(2, n_samples - 1))
        lof = LocalOutlierFactor(
            n_neighbors=n_neighbors,
            contamination="auto",
        )
        lof_labels = lof.fit_predict(X)  # we don't really use labels
        # negative_outlier_factor_: smaller = more anomalous → invert
        lof_scores = -lof.negative_outlier_factor_
    except Exception as e:
        print("LocalOutlierFactor failed:", e)
        lof_scores = np.zeros(n_samples)

    # ------------------------------------------------------------------
    # 4) Combine ML scores + deterministic heuristic
    # ------------------------------------------------------------------
    df["iso_score"] = iso_scores
    df["lof_score"] = lof_scores

    # Normalize ML scores to [0,1]
    iso_norm = normalize_series(df["iso_score"])
    lof_norm = normalize_series(df["lof_score"])

    # Combined ML anomaly score (0–1)
    df["anomaly_score"] = 0.5 * iso_norm + 0.5 * lof_norm

    # Deterministic heuristic score (same logic as old code but numeric)
    df["heuristic_score"] = df.apply(deterministic_risk_score, axis=1)
    df["heuristic_score_norm"] = normalize_series(df["heuristic_score"])

    # Final total score: weighted combination
    # You can tune these weights if needed.
    alpha = 0.6  # weight for ML anomaly score
    beta = 0.4   # weight for heuristic score
    df["total_score"] = alpha * df["anomaly_score"] + beta * df["heuristic_score_norm"]

    # ------------------------------------------------------------------
    # 5) Assign final risk labels
    # ------------------------------------------------------------------
    df["risk"] = assign_risk_labels(df["total_score"])

    # ------------------------------------------------------------------
    # 6) Write anomalies.csv
    # ------------------------------------------------------------------
    df.to_csv(OUT_CSV, index=False, encoding="utf-8")
    print(f"Wrote {len(df)} anomaly rows to {OUT_CSV}")


if __name__ == "__main__":
    main()
