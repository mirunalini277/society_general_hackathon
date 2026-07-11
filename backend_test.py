"""End-to-end integration test runner for the SupplyShield backend pipeline.

Run from the project root with ``python backend_test.py``. The script uses the
repository's sample datasets and produces portfolio audit artifacts on success.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Callable, TypeVar

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_DATA = PROJECT_ROOT / "sample_data"
REPORT_DIRECTORY = PROJECT_ROOT / "generated" / "reports"
EXPORT_DIRECTORY = PROJECT_ROOT / "generated" / "exports"

_T = TypeVar("_T")
_SUCCESS_MARK = "✓" if (sys.stdout.encoding or "").lower().startswith("utf") else "OK"


class _Color:
    """Minimal ANSI terminal color support with automatic non-TTY fallback."""

    enabled = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    reset = "\033[0m"
    green = "\033[92m"
    red = "\033[91m"
    yellow = "\033[93m"
    cyan = "\033[96m"
    bold = "\033[1m"

    @classmethod
    def apply(cls, text: str, color: str) -> str:
        """Wrap text in an ANSI color sequence when terminal colors are enabled."""
        return f"{color}{text}{cls.reset}" if cls.enabled else text


@dataclass(slots=True)
class PipelineData:
    """In-memory artifacts passed sequentially between backend pipeline stages."""

    applications: pd.DataFrame
    dependencies: pd.DataFrame
    vulnerabilities: pd.DataFrame
    license_rules: list[dict[str, Any]]
    labels: pd.DataFrame
    validation_summary: Any | None = None
    graph: Any | None = None
    vulnerability_findings: list[Any] | None = None
    vulnerability_summary: Any | None = None
    license_findings: list[Any] | None = None
    license_summary: Any | None = None
    maintenance_findings: list[Any] | None = None
    maintenance_summary: Any | None = None
    dependency_risks: list[Any] | None = None
    risk_summary: Any | None = None
    ai_summary: str | None = None
    pdf_path: Path | None = None
    csv_paths: tuple[Path, ...] | None = None


def main() -> int:
    """Execute the complete SupplyShield backend test pipeline."""
    logging.basicConfig(level=logging.ERROR, format="%(levelname)s %(name)s: %(message)s")
    _banner()
    try:
        data = _stage("Loading datasets", _load_datasets)
        data.dependencies = _stage("SBOM parsed", _parse_sbom)
        data.validation_summary = _stage("Validation", lambda: _validate(data))
        data.graph = _stage("Dependency Graph", lambda: _build_graph(data))
        _stage("Vulnerability Analysis", lambda: _run_vulnerability_analysis(data))
        _stage("License Analysis", lambda: _run_license_analysis(data))
        _stage("Maintenance Analysis", lambda: _run_maintenance_analysis(data))
        _stage("Risk Engine", lambda: _run_risk_engine(data))
        data.ai_summary = _stage("AI Explanation", lambda: _run_ai_explainer(data))
        data.pdf_path = _stage("PDF Report", lambda: _generate_pdf(data))
        data.csv_paths = _stage("CSV Export", lambda: _generate_csv(data))
    except _PipelineFailure as failure:
        _failure_report(failure.stage, failure.error)
        return 1

    _success_report(data)
    return 0


def _load_datasets() -> PipelineData:
    """Load all sample data sources required by the SupplyShield pipeline."""
    _require_files(
        "applications.json",
        "sbom_dependencies.csv",
        "vulnerability_db.json",
        "license_rules.json",
        "dependency_labels.csv",
    )
    return PipelineData(
        applications=pd.DataFrame(_load_json("applications.json")),
        dependencies=pd.DataFrame(),
        vulnerabilities=pd.DataFrame(_load_json("vulnerability_db.json")),
        license_rules=_load_json("license_rules.json"),
        labels=pd.read_csv(SAMPLE_DATA / "dependency_labels.csv"),
    )


def _parse_sbom() -> pd.DataFrame:
    """Parse the sample dependency SBOM through the production parser module."""
    from modules.parser import parse_sbom

    return parse_sbom(SAMPLE_DATA / "sbom_dependencies.csv").dependencies


def _validate(data: PipelineData) -> Any:
    """Run structured validation and retain all reported quality findings."""
    from modules.validator import validate_all

    summary = validate_all(
        data.applications,
        data.dependencies,
        data.vulnerabilities,
        data.license_rules,
        data.labels,
    )
    if not summary.is_valid:
        print(
            _Color.apply(
                f"  Validation completed with {len(summary.errors)} data-quality warning(s).",
                _Color.yellow,
            )
        )
    return summary


def _build_graph(data: PipelineData) -> Any:
    """Build the NetworkX dependency graph from parsed dependency records."""
    from modules.graph_builder import build_dependency_graph

    return build_dependency_graph(data.dependencies)


def _run_vulnerability_analysis(data: PipelineData) -> None:
    """Run vulnerability matching and calculate severity/patch summary counts."""
    from modules.vulnerability_checker import check_vulnerabilities, summarize_vulnerabilities

    data.vulnerability_findings = check_vulnerabilities(
        data.dependencies,
        SAMPLE_DATA / "vulnerability_db.json",
    )
    data.vulnerability_summary = summarize_vulnerabilities(data.vulnerability_findings)


def _run_license_analysis(data: PipelineData) -> None:
    """Run application-policy license compatibility assessment."""
    from modules.license_checker import check_licenses, summarize_licenses

    data.license_findings = check_licenses(
        data.dependencies,
        rules_path=SAMPLE_DATA / "license_rules.json",
    )
    data.license_summary = summarize_licenses(data.license_findings)


def _run_maintenance_analysis(data: PipelineData) -> None:
    """Assess maintenance status with a deterministic integration-test date."""
    from modules.maintenance_checker import analyze_maintenance, summarize_maintenance

    data.maintenance_findings = analyze_maintenance(
        data.dependencies,
        as_of=date.today(),
    )
    data.maintenance_summary = summarize_maintenance(data.maintenance_findings)


def _run_risk_engine(data: PipelineData) -> None:
    """Calculate dependency/application risk and portfolio ranking from checker outputs."""
    from modules.risk_engine import analyze_risk

    data.dependency_risks, data.risk_summary = analyze_risk(
        data.dependencies,
        _required(data.vulnerability_findings, "vulnerability findings"),
        _required(data.license_findings, "license findings"),
        _required(data.maintenance_findings, "maintenance findings"),
    )


def _run_ai_explainer(data: PipelineData) -> str:
    """Generate a safe Gemini-backed or deterministic executive explanation."""
    from modules.ai_explainer import AIRiskExplainer

    return AIRiskExplainer().generate_executive_summary(
        _required(data.risk_summary, "risk summary")
    )


def _generate_pdf(data: PipelineData) -> Path:
    """Generate the required portfolio PDF audit report."""
    from modules.report_generator import generate_pdf_report

    return generate_pdf_report(
        _required(data.risk_summary, "risk summary"),
        _required(data.dependency_risks, "dependency risks"),
        _required(data.vulnerability_findings, "vulnerability findings"),
        _required(data.license_findings, "license findings"),
        _required(data.maintenance_findings, "maintenance findings"),
        output_directory=REPORT_DIRECTORY,
    )


def _generate_csv(data: PipelineData) -> tuple[Path, ...]:
    """Generate the required portfolio CSV audit exports."""
    from modules.report_generator import generate_csv_reports

    return generate_csv_reports(
        _required(data.risk_summary, "risk summary"),
        _required(data.dependency_risks, "dependency risks"),
        _required(data.vulnerability_findings, "vulnerability findings"),
        _required(data.license_findings, "license findings"),
        _required(data.maintenance_findings, "maintenance findings"),
        output_directory=EXPORT_DIRECTORY,
    )


def _stage(name: str, operation: Callable[[], _T]) -> _T:
    """Execute one named stage and standardize success/failure console output."""
    try:
        result = operation()
    except Exception as exc:
        raise _PipelineFailure(name, exc) from exc
    print(f"{name:.<40} {_Color.apply(_SUCCESS_MARK, _Color.green)}")
    return result


def _success_report(data: PipelineData) -> None:
    """Print the requested enterprise backend-test summary after all stages pass."""
    vulnerability_summary = _required(data.vulnerability_summary, "vulnerability summary")
    license_summary = _required(data.license_summary, "license summary")
    maintenance_summary = _required(data.maintenance_summary, "maintenance summary")
    risk_summary = _required(data.risk_summary, "risk summary")
    vulnerabilities = _required(data.vulnerability_findings, "vulnerability findings")
    licenses = _required(data.license_findings, "license findings")
    maintenance = _required(data.maintenance_findings, "maintenance findings")

    _rule()
    print(_Color.apply("DATASET SUMMARY", _Color.bold))
    _key_value("Applications", len(risk_summary.applications))
    _key_value("Dependencies", len(data.dependencies))
    _key_value("Critical Vulnerabilities", vulnerability_summary.critical)
    _key_value("High Vulnerabilities", vulnerability_summary.high)
    _key_value("Medium Vulnerabilities", vulnerability_summary.medium)
    _key_value("Low Vulnerabilities", vulnerability_summary.low)
    _key_value("License Issues", license_summary.incompatible)
    _key_value("Unknown Licenses", license_summary.unknown)
    _key_value("Outdated Libraries", maintenance_summary.outdated)
    _key_value("Unmaintained Libraries", maintenance_summary.unmaintained)
    _key_value("Highest Risk Application", risk_summary.highest_risk_application or "N/A")
    _key_value("Average Risk Score", f"{risk_summary.average_risk:.2f}")

    _rule()
    print(_Color.apply("TOP 5 RISKIEST APPLICATIONS", _Color.bold))
    for item in risk_summary.applications[:5]:
        print(f"{item.rank}. {item.application} | Score: {item.overall_risk_score:.2f} | Level: {_risk(item.overall_risk_level)}")

    _rule()
    print(_Color.apply("TOP 10 CRITICAL VULNERABILITIES", _Color.bold))
    critical = [
        item for item in vulnerabilities
        if item.severity.casefold() == "critical" or item.cvss >= 9.0
    ]
    _print_rows(
        ["CVE", "Library", "Version", "CVSS", "Severity", "Patch Available"],
        [
            [item.cve_id, item.library, item.version, f"{item.cvss:.1f}", "Critical", str(item.patch_available)]
            for item in sorted(critical, key=lambda finding: finding.cvss, reverse=True)[:10]
        ],
    )

    _rule()
    print(_Color.apply("TOP LICENSE ISSUES", _Color.bold))
    issues = [item for item in licenses if item.compatibility_status != "Compatible"]
    _print_rows(
        ["Application", "Library", "License", "Reason"],
        [[item.application, item.library, item.license, item.reason] for item in issues[:10]],
    )

    _rule()
    print(_Color.apply("TOP OUTDATED LIBRARIES", _Color.bold))
    outdated = [
        item for item in maintenance
        if item.maintenance_status in {"Outdated", "Unmaintained"}
    ]
    _print_rows(
        ["Application", "Library", "Years Old", "Risk"],
        [
            [item.application, item.library, f"{item.age_years or 0:.2f}", item.risk_level]
            for item in sorted(outdated, key=lambda finding: finding.age_days or 0, reverse=True)[:10]
        ],
    )

    _rule()
    print(_Color.apply("FILES GENERATED", _Color.bold))
    _key_value("Portfolio PDF", str(_required(data.pdf_path, "PDF report")))
    _key_value("CSV Exports", len(_required(data.csv_paths, "CSV exports")))
    _key_value("Output Folder", str(REPORT_DIRECTORY.parent))
    _rule()
    print(_Color.apply("FINAL STATUS", _Color.bold))
    print(_Color.apply("BACKEND TEST PASSED", _Color.green + _Color.bold))
    print("=" * 60)


def _failure_report(stage: str, error: Exception) -> None:
    """Print the mandated fail-fast message with stage and root exception details."""
    _rule()
    print(_Color.apply("FAILED AT:", _Color.red + _Color.bold))
    print(stage)
    print(_Color.apply("Reason:", _Color.red + _Color.bold))
    print(f"{type(error).__name__}: {error}")
    print("=" * 60)


def _banner() -> None:
    """Print the SupplyShield backend-test banner."""
    print("=" * 60)
    print(_Color.apply("                SUPPLYSHIELD BACKEND TEST", _Color.cyan + _Color.bold))
    print("=" * 60)


def _rule() -> None:
    """Print a standard report separator."""
    print("-" * 60)


def _key_value(label: str, value: Any) -> None:
    """Print a neatly aligned console key/value row."""
    print(f"{label:<28}: {value}")


def _print_rows(headers: list[str], rows: list[list[str]]) -> None:
    """Print an adaptive, readable ASCII table without external dependencies."""
    if not rows:
        print("No findings in scope.")
        return
    limited_rows = [[_shorten(cell, 42) for cell in row] for row in rows]
    widths = [max(len(header), *(len(row[index]) for row in limited_rows)) for index, header in enumerate(headers)]
    print(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in limited_rows:
        print(" | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))


def _shorten(value: Any, limit: int) -> str:
    """Truncate long console cells while preserving readable table layout."""
    text = str(value)
    return text if len(text) <= limit else f"{text[:limit - 3]}..."


def _risk(level: str) -> str:
    """Apply terminal risk coloring to a final application risk level."""
    colors = {
        "Critical": _Color.red,
        "High": _Color.red,
        "Medium": _Color.yellow,
        "Low": _Color.green,
    }
    return _Color.apply(level, colors.get(level, ""))


def _load_json(filename: str) -> list[dict[str, Any]]:
    """Load a sample JSON array with clear path-aware errors."""
    with (SAMPLE_DATA / filename).open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError(f"{filename} must contain a JSON array.")
    return payload


def _require_files(*filenames: str) -> None:
    """Ensure every required sample dataset is present before pipeline execution."""
    missing = [name for name in filenames if not (SAMPLE_DATA / name).is_file()]
    if missing:
        raise FileNotFoundError(f"Missing sample datasets: {', '.join(missing)}")


def _required(value: _T | None, name: str) -> _T:
    """Assert an earlier pipeline stage produced its expected artifact."""
    if value is None:
        raise RuntimeError(f"Required {name} were not produced by an earlier stage.")
    return value


class _PipelineFailure(Exception):
    """Internal wrapper preserving the failed module stage and original exception."""

    def __init__(self, stage: str, error: Exception) -> None:
        super().__init__(str(error))
        self.stage = stage
        self.error = error


if __name__ == "__main__":
    raise SystemExit(main())
