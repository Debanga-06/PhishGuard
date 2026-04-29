"""
train.py — Train and evaluate phishing URL detection models.

Trains Logistic Regression, Random Forest, and XGBoost,
compares performance, saves the best model, and generates
evaluation visualizations.

Usage:
    python train.py              # uses/generates default dataset
    python train.py --csv path/to/dataset.csv
"""

import sys
import os
import argparse
import time
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report, roc_curve
)
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

DATASET_PATH  = os.path.join(BASE_DIR, "dataset", "phishing_urls.csv")
MODELS_DIR    = os.path.join(BASE_DIR, "models")
BEST_MODEL    = os.path.join(MODELS_DIR, "best_model.pkl")
SCALER_PATH   = os.path.join(MODELS_DIR, "scaler.pkl")
META_PATH     = os.path.join(MODELS_DIR, "model_meta.pkl")
REPORTS_DIR   = os.path.join(BASE_DIR, "models", "reports")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

from utils.feature_extractor import extract_features, features_to_vector, FEATURE_NAMES


# ── Feature extraction ─────────────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    print(f"  Extracting features from {len(df)} URLs...")
    rows = []
    for i, url in enumerate(df["url"]):
        if i % 1000 == 0 and i > 0:
            print(f"    {i}/{len(df)} processed...")
        try:
            feat = extract_features(str(url))
            rows.append(features_to_vector(feat))
        except Exception:
            rows.append([0.0] * len(FEATURE_NAMES))
    return np.array(rows, dtype=np.float32)


# ── Model definitions ──────────────────────────────────────────────────────────

def get_models() -> dict:
    return {
        "Logistic Regression": LogisticRegression(
            C=1.0, max_iter=1000, class_weight="balanced", random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=None, min_samples_leaf=2,
            class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            use_label_encoder=False, eval_metric="logloss",
            random_state=42, n_jobs=-1, verbosity=0
        ),
    }


# ── Evaluation ─────────────────────────────────────────────────────────────────

def evaluate_model(name: str, model, X_test, y_test) -> dict:
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    return {
        "name":      name,
        "accuracy":  accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall":    recall_score(y_test, y_pred),
        "f1":        f1_score(y_test, y_pred),
        "auc":       roc_auc_score(y_test, y_proba),
        "y_pred":    y_pred,
        "y_proba":   y_proba,
    }


def print_results(results: list):
    header = f"\n{'Model':<22} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8} {'AUC-ROC':>9}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r['name']:<22} {r['accuracy']:>9.4f} {r['precision']:>10.4f} "
            f"{r['recall']:>8.4f} {r['f1']:>8.4f} {r['auc']:>9.4f}"
        )


# ── Visualization ──────────────────────────────────────────────────────────────

def _style():
    plt.rcParams.update({
        "font.family": "monospace",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.facecolor": "#0d1117",
        "axes.facecolor": "#161b22",
        "text.color": "#c9d1d9",
        "axes.labelcolor": "#c9d1d9",
        "xtick.color": "#c9d1d9",
        "ytick.color": "#c9d1d9",
        "axes.edgecolor": "#30363d",
        "grid.color": "#21262d",
    })


def plot_confusion_matrices(results: list, y_test):
    _style()
    fig, axes = plt.subplots(1, len(results), figsize=(5 * len(results), 4))
    if len(results) == 1:
        axes = [axes]
    colors = ["#58a6ff", "#f78166", "#3fb950"]

    for ax, res, color in zip(axes, results, colors):
        cm = confusion_matrix(y_test, res["y_pred"])
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                    xticklabels=["Legit", "Phish"],
                    yticklabels=["Legit", "Phish"],
                    linewidths=0.5, linecolor="#30363d")
        ax.set_title(res["name"], color=color, fontsize=11, pad=10)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")

    plt.suptitle("Confusion Matrices", color="#e6edf3", fontsize=14, y=1.02)
    plt.tight_layout()
    path = os.path.join(REPORTS_DIR, "confusion_matrices.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()
    print(f"  Saved → {path}")


def plot_roc_curves(results: list, y_test):
    _style()
    fig, ax = plt.subplots(figsize=(7, 5))
    colors = ["#58a6ff", "#f78166", "#3fb950"]

    for res, color in zip(results, colors):
        fpr, tpr, _ = roc_curve(y_test, res["y_proba"])
        ax.plot(fpr, tpr, color=color, lw=2,
                label=f"{res['name']} (AUC={res['auc']:.3f})")

    ax.plot([0, 1], [0, 1], "--", color="#8b949e", lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — Model Comparison", color="#e6edf3")
    ax.legend(facecolor="#161b22", edgecolor="#30363d")
    ax.grid(True, alpha=0.3)

    path = os.path.join(REPORTS_DIR, "roc_curves.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()
    print(f"  Saved → {path}")


def plot_metrics_comparison(results: list):
    _style()
    metrics = ["accuracy", "precision", "recall", "f1", "auc"]
    labels  = ["Accuracy", "Precision", "Recall", "F1", "AUC-ROC"]
    x = np.arange(len(metrics))
    width = 0.25
    colors = ["#58a6ff", "#f78166", "#3fb950"]

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, (res, color) in enumerate(zip(results, colors)):
        vals = [res[m] for m in metrics]
        bars = ax.bar(x + i * width, vals, width, label=res["name"],
                      color=color, alpha=0.85, edgecolor="#30363d")
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=7, color="#c9d1d9")

    ax.set_xticks(x + width)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.12)
    ax.set_title("Model Metrics Comparison", color="#e6edf3", fontsize=13)
    ax.legend(facecolor="#161b22", edgecolor="#30363d")
    ax.grid(axis="y", alpha=0.3)

    path = os.path.join(REPORTS_DIR, "metrics_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()
    print(f"  Saved → {path}")


def plot_feature_importance(best_model, model_name: str):
    _style()
    importances = None

    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
    elif hasattr(best_model, "coef_"):
        importances = np.abs(best_model.coef_[0])

    if importances is None:
        return

    idx = np.argsort(importances)[::-1][:15]
    top_names  = [FEATURE_NAMES[i] for i in idx]
    top_values = importances[idx]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(top_names[::-1], top_values[::-1], color="#58a6ff", alpha=0.85)
    ax.set_xlabel("Importance Score")
    ax.set_title(f"Top 15 Feature Importances — {model_name}", color="#e6edf3", fontsize=12)
    ax.grid(axis="x", alpha=0.3)

    path = os.path.join(REPORTS_DIR, "feature_importance.png")
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()
    print(f"  Saved → {path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train phishing URL detector")
    parser.add_argument("--csv", default=DATASET_PATH, help="Path to labeled CSV")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    # ── Generate dataset if missing ───────────────────────────────────────────
    if not os.path.exists(args.csv):
        print("Dataset not found. Generating synthetic dataset...")
        from dataset.generate_dataset import generate_dataset
        generate_dataset()

    # ── Load data ─────────────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print("  PHISHING URL DETECTION — MODEL TRAINING")
    print(f"{'='*55}")
    print(f"\n[1/6] Loading dataset: {args.csv}")
    df = pd.read_csv(args.csv)
    print(f"      Rows: {len(df)} | Phishing: {df['label'].sum()} | Legit: {(df['label']==0).sum()}")

    # ── Feature engineering ───────────────────────────────────────────────────
    print("\n[2/6] Extracting features...")
    t0 = time.time()
    X = build_feature_matrix(df)
    y = df["label"].values.astype(int)
    print(f"      Done in {time.time()-t0:.1f}s | Feature matrix: {X.shape}")

    # ── Split ─────────────────────────────────────────────────────────────────
    print(f"\n[3/6] Splitting data ({int((1-args.test_size)*100)}/{int(args.test_size*100)})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    # ── Scale (for LR) ────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    joblib.dump(scaler, SCALER_PATH)
    print(f"      Scaler saved → {SCALER_PATH}")

    # ── Train & evaluate ──────────────────────────────────────────────────────
    print("\n[4/6] Training & evaluating models...\n")
    models   = get_models()
    results  = []
    trained  = {}

    for name, model in models.items():
        print(f"  ▸ {name}...")
        t0 = time.time()

        # LR uses scaled features
        Xtr = X_train_sc if name == "Logistic Regression" else X_train
        Xte = X_test_sc  if name == "Logistic Regression" else X_test

        model.fit(Xtr, y_train)
        elapsed = time.time() - t0

        res = evaluate_model(name, model, Xte, y_test)
        res["train_time"] = elapsed
        results.append(res)
        trained[name] = model

        print(f"    Accuracy={res['accuracy']:.4f}  F1={res['f1']:.4f}  AUC={res['auc']:.4f}  ({elapsed:.1f}s)")

    # ── Pick best model by F1 ─────────────────────────────────────────────────
    print("\n[5/6] Comparing models...")
    print_results(results)

    best = max(results, key=lambda r: r["f1"])
    best_model = trained[best["name"]]
    best_uses_scaler = (best["name"] == "Logistic Regression")

    print(f"\n  🏆 Best model: {best['name']}  (F1={best['f1']:.4f})")

    # Save
    meta = {
        "model_name": best["name"],
        "uses_scaler": best_uses_scaler,
        "feature_names": FEATURE_NAMES,
        "metrics": {k: v for k, v in best.items() if k not in ("y_pred", "y_proba")},
    }
    joblib.dump(best_model, BEST_MODEL)
    joblib.dump(meta, META_PATH)
    print(f"  Saved → {BEST_MODEL}")
    print(f"  Saved → {META_PATH}")

    # Also save individual models
    for name, m in trained.items():
        fname = name.lower().replace(" ", "_") + ".pkl"
        joblib.dump(m, os.path.join(MODELS_DIR, fname))

    # ── Visualizations ────────────────────────────────────────────────────────
    print("\n[6/6] Generating evaluation plots...")
    # Use scaled test for LR confusion matrix
    results_for_plots = []
    for res in results:
        name = res["name"]
        Xte = X_test_sc if name == "Logistic Regression" else X_test
        y_pred  = trained[name].predict(Xte)
        y_proba = trained[name].predict_proba(Xte)[:, 1]
        results_for_plots.append({**res, "y_pred": y_pred, "y_proba": y_proba})

    plot_confusion_matrices(results_for_plots, y_test)
    plot_roc_curves(results_for_plots, y_test)
    plot_metrics_comparison(results)
    plot_feature_importance(best_model, best["name"])

    print(f"\n{'='*55}")
    print("  TRAINING COMPLETE")
    print(f"{'='*55}")
    print(f"\n  Model : {best['name']}")
    print(f"  F1    : {best['f1']:.4f}")
    print(f"  AUC   : {best['auc']:.4f}")
    print(f"\n  Run the app with:")
    print(f"    python app.py           ← Flask Web App")
    print(f"    python predict.py <url> ← CLI prediction\n")


if __name__ == "__main__":
    main()