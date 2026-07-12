from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_DATA = PROJECT_ROOT / "sample_data"
EXPORTS_DIR = PROJECT_ROOT / "generated" / "exports"
LABELS_PATH = SAMPLE_DATA / "dependency_labels.csv"
APPLICATIONS_PATH = SAMPLE_DATA / "applications.json"


def load_application_map(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as handle:
        apps = json.load(handle)

    app_map = {}
    for app in apps:
        app_id = str(app.get("app_id", "")).strip()
        name = str(app.get("name", "")).strip()
        if app_id:
            app_map[app_id] = name
        if name:
            app_map[name] = name
    return app_map


def load_ground_truth(path: Path, app_map: dict[str, str]) -> pd.DataFrame:
    raw_bytes = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = raw_bytes.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise UnicodeDecodeError("utf-8", raw_bytes, 0, 1, f"Unable to decode {path}")

    labels = pd.read_csv(pd.io.common.StringIO(text))
    labels = labels.rename(columns={"application_id": "application"})
    labels["application"] = labels["application"].astype(str).str.strip()
    labels["application"] = labels["application"].map(lambda value: app_map.get(value, value))
    labels["library"] = labels["library"].astype(str).str.strip()
    labels["version"] = labels["version"].astype(str).str.strip()
    labels["expected"] = labels["is_risky"].astype(bool).astype(int)
    return labels[["application", "library", "version", "expected", "risk_type", "severity", "explanation"]]


def find_latest_dependency_risk_csv(exports_dir: Path) -> Path:
    files = sorted(exports_dir.glob("supplyshield_dependency_risk_portfolio_*.csv"))
    if not files:
        raise FileNotFoundError(f"No dependency risk CSV found in {exports_dir}")
    return files[-1]


def load_backend_output(path: Path) -> pd.DataFrame:
    raw_bytes = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = raw_bytes.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise UnicodeDecodeError("utf-8", raw_bytes, 0, 1, f"Unable to decode {path}")

    output = pd.read_csv(pd.io.common.StringIO(text))
    output.columns = [str(col).replace("\ufeff", "").strip() for col in output.columns]
    output["application"] = output["application"].astype(str).str.strip()
    output["library"] = output["library"].astype(str).str.strip()
    output["version"] = output["version"].astype(str).str.strip()

    output["predicted_risky"] = 0

    vulnerability_columns = [
        "vulnerability_score",
        "license_score",
        "maintenance_score",
        "final_risk_score",
    ]
    for col in vulnerability_columns:
        if col in output.columns:
            output[col] = pd.to_numeric(output[col], errors="coerce")

    if "vulnerability_score" in output.columns:
        output["has_vulnerability"] = output["vulnerability_score"].fillna(0) > 0
    else:
        output["has_vulnerability"] = False

    if "license_score" in output.columns:
        output["has_license_conflict"] = output["license_score"].fillna(0) >= 75
    else:
        output["has_license_conflict"] = False

    if "maintenance_score" in output.columns:
        output["has_unmaintained"] = output["maintenance_score"].fillna(0) >= 100
    else:
        output["has_unmaintained"] = False

    output["predicted_risky"] = (
        output["has_vulnerability"].astype(int)
        | output["has_license_conflict"].astype(int)
        | output["has_unmaintained"].astype(int)
    ).astype(int)

    output["reason"] = output.get("explanation", pd.Series(["" for _ in range(len(output))]))
    return output[["application", "library", "version", "predicted_risky", "reason"]]


def merge_datasets(labels: pd.DataFrame, backend: pd.DataFrame) -> pd.DataFrame:
    merged = labels.merge(
        backend,
        on=["application", "library", "version"],
        how="inner",
        suffixes=("_expected", "_predicted"),
    )
    return merged


def compute_metrics(expected: pd.Series, predicted: pd.Series) -> dict[str, Any]:
    tp = int(((expected == 1) & (predicted == 1)).sum())
    tn = int(((expected == 0) & (predicted == 0)).sum())
    fp = int(((expected == 0) & (predicted == 1)).sum())
    fn = int(((expected == 1) & (predicted == 0)).sum())

    accuracy = (tp + tn) / len(expected) if len(expected) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "fpr": fpr,
        "fnr": fnr,
    }


def write_mismatches(path: Path, merged: pd.DataFrame) -> None:
    mismatches = merged.loc[merged["expected"] != merged["predicted_risky"]]
    if mismatches.empty:
        mismatches = pd.DataFrame(columns=["application", "library", "version", "expected", "predicted", "reason"])
    else:
        mismatches = mismatches[["application", "library", "version", "expected", "predicted_risky", "reason"]].copy()
        mismatches = mismatches.rename(columns={"predicted_risky": "predicted"})

    mismatches.to_csv(path, index=False)


def main() -> None:
    app_map = load_application_map(APPLICATIONS_PATH)
    labels = load_ground_truth(LABELS_PATH, app_map)
    backend_path = find_latest_dependency_risk_csv(EXPORTS_DIR)
    backend_output = load_backend_output(backend_path)

    merged = merge_datasets(labels, backend_output)
    if merged.empty:
        raise RuntimeError("No matched dependencies were found between labels and backend output")

    metrics = compute_metrics(merged["expected"], merged["predicted_risky"])

    mismatch_path = EXPORTS_DIR / "mismatches.csv"
    write_mismatches(mismatch_path, merged)

    print(f"Matched dependencies: {len(merged)}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1 Score: {metrics['f1']:.4f}")
    print(f"Confusion Matrix: TP={metrics['tp']}, TN={metrics['tn']}, FP={metrics['fp']}, FN={metrics['fn']}")
    print(f"False Positive Rate: {metrics['fpr']:.4f}")
    print(f"False Negative Rate: {metrics['fnr']:.4f}")
    print(f"Mismatches saved to: {mismatch_path}")


if __name__ == "__main__":
    main()
