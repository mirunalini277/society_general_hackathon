"""Shared Streamlit presentation helpers and backend orchestration for SupplyShield."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
from typing import Any, Mapping

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from modules.graph_builder import build_dependency_graph
from modules.license_checker import check_licenses, summarize_licenses
from modules.maintenance_checker import analyze_maintenance, summarize_maintenance
from modules.parser import parse_sbom
from modules.risk_engine import analyze_risk
from modules.validator import validate_all
from modules.vulnerability_checker import check_vulnerabilities, summarize_vulnerabilities

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DATA = ROOT / "sample_data"
RISK_COLORS = {"Critical": "#DC2626", "High": "#EA580C", "Medium": "#D97706", "Low": "#16A34A"}
CHART_TEMPLATE = "plotly_white"


@dataclass(slots=True)
class AnalysisBundle:
    """Typed collection of output objects produced by the SupplyShield backend."""

    applications: pd.DataFrame
    dependencies: pd.DataFrame
    vulnerabilities: pd.DataFrame
    license_rules: list[dict[str, Any]]
    labels: pd.DataFrame
    validation: Any
    graph: Any
    vulnerability_findings: list[Any]
    vulnerability_summary: Any
    license_findings: list[Any]
    license_summary: Any
    maintenance_findings: list[Any]
    maintenance_summary: Any
    dependency_risks: list[Any]
    risk_summary: Any


def run_analysis(files: Mapping[str, Any] | None = None) -> AnalysisBundle:
    """Run the existing backend pipeline against uploaded files or sample data."""
    applications = _json_frame(files, "applications.json")
    vulnerabilities = _json_frame(files, "vulnerability_db.json")
    license_rules = _json_records(files, "license_rules.json")
    labels = pd.read_csv(SAMPLE_DATA / "dependency_labels.csv")
    dependencies = parse_sbom(_source(files, "sbom_dependencies.csv"), "sbom_dependencies.csv").dependencies
    validation = validate_all(applications, dependencies, vulnerabilities, license_rules, labels)
    graph = build_dependency_graph(dependencies)
    vulnerability_findings = check_vulnerabilities(
        dependencies, _materialize_upload(files, "vulnerability_db.json")
    )
    license_findings = check_licenses(
        dependencies, rules_path=_materialize_upload(files, "license_rules.json")
    )
    maintenance_findings = analyze_maintenance(dependencies, as_of=date.today())
    dependency_risks, risk_summary = analyze_risk(
        dependencies,
        vulnerability_findings,
        license_findings,
        maintenance_findings,
    )
    return AnalysisBundle(
        applications=applications,
        dependencies=dependencies,
        vulnerabilities=vulnerabilities,
        license_rules=license_rules,
        labels=labels,
        validation=validation,
        graph=graph,
        vulnerability_findings=vulnerability_findings,
        vulnerability_summary=summarize_vulnerabilities(vulnerability_findings),
        license_findings=license_findings,
        license_summary=summarize_licenses(license_findings),
        maintenance_findings=maintenance_findings,
        maintenance_summary=summarize_maintenance(maintenance_findings),
        dependency_risks=dependency_risks,
        risk_summary=risk_summary,
    )


def application_frame(bundle: AnalysisBundle) -> pd.DataFrame:
    """Return application risks in a UI-friendly dataframe."""
    return pd.DataFrame([item.as_dict() for item in bundle.risk_summary.applications])


def finding_frame(items: list[Any]) -> pd.DataFrame:
    """Convert backend finding dataclasses to a dataframe without duplicating logic."""
    return pd.DataFrame([item.as_dict() if hasattr(item, "as_dict") else vars(item) for item in items])


def risk_badge(level: str) -> str:
    """Return a styled risk status label for Streamlit HTML rendering."""
    color = RISK_COLORS.get(level, "#475569")
    return f"<span class='risk-badge' style='background:{color}18;color:{color}'>{level}</span>"


def chart_layout(figure: go.Figure, height: int = 300) -> go.Figure:
    """Apply the shared restrained enterprise chart presentation."""
    figure.update_layout(
        template=CHART_TEMPLATE,
        height=height,
        margin=dict(l=10, r=10, t=42, b=10),
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(family="Inter, Arial, sans-serif", color="#334155"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
    )
    figure.update_xaxes(showgrid=False, linecolor="#E2E8F0")
    figure.update_yaxes(gridcolor="#E2E8F0", zeroline=False)
    return figure


def risk_comparison_chart(bundle: AnalysisBundle) -> go.Figure:
    """Build the application score comparison chart from calculated application risks."""
    frame = application_frame(bundle).sort_values("overall_risk_score")
    figure = px.bar(
        frame,
        x="overall_risk_score",
        y="application",
        orientation="h",
        color="overall_risk_level",
        color_discrete_map=RISK_COLORS,
        labels={"overall_risk_score": "Risk score", "application": ""},
    )
    return chart_layout(figure, 330)


def severity_chart(bundle: AnalysisBundle) -> go.Figure:
    """Build the vulnerability severity distribution chart."""
    counts = finding_frame(bundle.vulnerability_findings).assign(
        severity=lambda frame: frame["severity"].str.title()
    )["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0).reset_index()
    counts.columns = ["severity", "count"]
    return chart_layout(px.bar(counts, x="severity", y="count", color="severity", color_discrete_map=RISK_COLORS, labels={"count": "Findings", "severity": ""}))


def health_score(bundle: AnalysisBundle) -> float:
    """Return a presentation-only inverse of the calculated average risk score."""
    return round(max(0.0, 100.0 - bundle.risk_summary.average_risk), 1)


def _source(files: Mapping[str, Any] | None, filename: str) -> Any:
    """Return upload-like content when supplied, otherwise a sample data path."""
    return files[filename] if files and files.get(filename) is not None else SAMPLE_DATA / filename


def _materialize_upload(files: Mapping[str, Any] | None, filename: str) -> Path:
    """Return stable sample paths; uploads are copied to a temporary project cache file."""
    source = _source(files, filename)
    if isinstance(source, Path):
        return source
    cache_dir = ROOT / "generated" / "uploads"
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / filename
    path.write_bytes(source.getvalue())
    return path


def _json_frame(files: Mapping[str, Any] | None, filename: str) -> pd.DataFrame:
    """Load uploaded or sample JSON records into a dataframe."""
    return pd.DataFrame(_json_records(files, filename))


def _json_records(files: Mapping[str, Any] | None, filename: str) -> list[dict[str, Any]]:
    """Load a JSON array without adding new parsing behavior to backend modules."""
    source = _source(files, filename)
    content = source.read_text(encoding="utf-8") if isinstance(source, Path) else source.getvalue().decode("utf-8")
    payload = json.loads(content)
    if not isinstance(payload, list):
        raise ValueError(f"{filename} must contain a JSON array.")
    return payload
