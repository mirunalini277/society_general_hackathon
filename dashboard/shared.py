"""Shared Streamlit presentation helpers and backend orchestration for SupplyShield."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from io import StringIO
import json
from pathlib import Path
from typing import Any, Mapping

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from modules.graph_builder import build_dependency_graph
from modules.license_checker import check_licenses, summarize_licenses
from modules.maintenance_checker import analyze_maintenance, summarize_maintenance
from modules.parser import (
    normalize_application_frame,
    normalize_label_frame,
    normalize_license_records,
    normalize_vulnerability_records,
    parse_sbom,
)
from modules.risk_engine import analyze_risk
from modules.validator import validate_all
from modules.vulnerability_checker import check_vulnerabilities, summarize_vulnerabilities

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DATA = ROOT / "sample_data"
RISK_COLORS = {"Critical": "#DC2626", "High": "#EA580C", "Medium": "#D97706", "Low": "#16A34A"}
CHART_TEMPLATE = "plotly_dark"


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
    # Match backend_test.py: validate only canonical, encoding-safe dataset forms.
    applications = normalize_application_frame(_json_frame(files, "applications.json"))
    vulnerabilities = pd.DataFrame(
        normalize_vulnerability_records(_json_records(files, "vulnerability_db.json"))
    )
    license_rules = normalize_license_records(_json_records(files, "license_rules.json"))
    labels = normalize_label_frame(_read_csv_source(None, "dependency_labels.csv"))
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


def application_selector(bundle: AnalysisBundle, *, key: str = "application_scope") -> str | None:
    """Render the shared application scope control and return ``None`` for all."""
    applications = application_frame(bundle)["application"].sort_values().tolist()
    options = ["All Applications", *applications]
    current = st.session_state.get("selected_application", "All Applications")
    index = options.index(current) if current in options else 0
    selected = st.selectbox("Application", options, index=index, key=key)
    st.session_state["selected_application"] = selected
    return None if selected == "All Applications" else selected


def scope_frame(frame: pd.DataFrame, application: str | None) -> pd.DataFrame:
    """Return a copy restricted to an exact application scope when selected."""
    if application is None or "application" not in frame:
        return frame.copy()
    return frame[frame["application"] == application].copy()


def finding_frame(items: list[Any]) -> pd.DataFrame:
    """Convert backend finding dataclasses to a dataframe without duplicating logic."""
    return pd.DataFrame([item.as_dict() if hasattr(item, "as_dict") else vars(item) for item in items])


def risk_badge(level: str) -> str:
    """Return a styled risk status label for Streamlit HTML rendering."""
    color = RISK_COLORS.get(level, "#475569")
    return f"<span class='risk-badge' style='background:{color}18;color:{color}'>{level}</span>"


def application_metadata(bundle: AnalysisBundle, application: str) -> dict[str, str]:
    """Return owner and criticality metadata from the application inventory."""
    frame = bundle.applications
    name_column = next(
        (column for column in ("application_name", "name", "application") if column in frame.columns),
        None,
    )
    if name_column is None:
        return {"owner": "—", "criticality": "—"}
    row = frame[frame[name_column] == application]
    if row.empty:
        return {"owner": "—", "criticality": "—"}
    record = row.iloc[0]
    owner = record.get("business_owner") or record.get("owner") or "—"
    criticality = record.get("criticality") or record.get("business_criticality") or "—"
    return {"owner": str(owner), "criticality": str(criticality)}


def application_risk_record(bundle: AnalysisBundle, application: str) -> Any | None:
    """Return the backend application risk object for one application."""
    for item in bundle.risk_summary.applications:
        if item.application == application:
            return item
    return None


def risk_score_breakdown(bundle: AnalysisBundle, application: str) -> dict[str, float]:
    """Aggregate dependency component scores into an application-level breakdown."""
    risks = [item for item in bundle.dependency_risks if item.application == application]
    if not risks:
        return {"vulnerabilities": 0.0, "licenses": 0.0, "maintenance": 0.0, "dependency_depth": 0.0}
    return {
        "vulnerabilities": round(sum(item.vulnerability_score for item in risks) / len(risks), 1),
        "licenses": round(sum(item.license_score for item in risks) / len(risks), 1),
        "maintenance": round(sum(item.maintenance_score for item in risks) / len(risks), 1),
        "dependency_depth": round(sum(item.dependency_depth_score for item in risks) / len(risks), 1),
    }


def critical_cve_count(bundle: AnalysisBundle, application: str | None = None) -> int:
    """Count critical vulnerability findings for one or all applications."""
    frame = scope_frame(finding_frame(bundle.vulnerability_findings), application)
    if frame.empty:
        return 0
    return int(((frame["cvss"] >= 9.0) | (frame["severity"].str.casefold() == "critical")).sum())


def navigate_to(page: str, application: str | None = None) -> None:
    """Set navigation state and rerun to the requested investigation view."""
    if application is not None:
        st.session_state["selected_application"] = application
    st.session_state["current_page"] = page
    st.session_state["navigation_target"] = page
    st.rerun()


def incident_search(bundle: AnalysisBundle, query: str) -> list[dict[str, Any]]:
    """Return normalized search matches for library, CVE, or application lookup."""
    term = query.casefold().strip()
    if not term:
        return []
    findings_by_dependency: dict[tuple[str, str, str], list[Any]] = {}
    for finding in bundle.vulnerability_findings:
        findings_by_dependency.setdefault((finding.application, finding.library, finding.version), []).append(finding)
    dependency_types: dict[tuple[str, str, str], str] = {}
    for _, row in bundle.dependencies.iterrows():
        dependency_types[(row["application"], row["library"], row["version"])] = str(row.get("dependency_type", "Unknown"))

    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for risk in bundle.dependency_risks:
        key = (risk.application, risk.library, risk.version)
        findings = findings_by_dependency.get(key, [])
        cves = [finding.cve_id for finding in findings]
        app_match = term in risk.application.casefold()
        library_match = term in risk.library.casefold()
        cve_match = any(term in cve.casefold() for cve in cves)
        if not (app_match or library_match or cve_match):
            continue
        if key in seen:
            continue
        seen.add(key)
        dep_type = dependency_types.get(key, "Unknown")
        matches.append(
            {
                "application": risk.application,
                "library": risk.library,
                "version": risk.version,
                "risk_level": risk.final_risk_level,
                "risk_score": risk.final_risk_score,
                "dependency_type": dep_type,
                "cves": cves,
                "patch_available": any(finding.patch_available for finding in findings),
                "has_findings": bool(findings),
            }
        )
    for app_risk in bundle.risk_summary.applications:
        if term not in app_risk.application.casefold():
            continue
        if any(item["application"] == app_risk.application for item in matches):
            continue
        matches.append(
            {
                "application": app_risk.application,
                "library": "—",
                "version": "—",
                "risk_level": app_risk.overall_risk_level,
                "risk_score": app_risk.overall_risk_score,
                "dependency_type": "Application",
                "cves": [],
                "patch_available": False,
                "has_findings": False,
            }
        )
    return sorted(matches, key=lambda item: (-item["risk_score"], item["application"].casefold()))


def render_investigate_button(application: str, key_suffix: str) -> bool:
    """Render a compact investigate action. Returns True when clicked."""
    return st.button("Investigate", key=f"investigate_app_{key_suffix}", type="primary", use_container_width=True)


def render_search_result_card(match: dict[str, Any], index: int) -> bool:
    """Render one investigation result card. Returns True when Investigate is clicked."""
    cves = ", ".join(match["cves"]) if match["cves"] else "No matched CVE"
    patch = "Patch available" if match["patch_available"] else ("No patch" if match["has_findings"] else "N/A")
    st.markdown(
        "<div class='result-card'>"
        f"<div class='result-card-header'><span class='result-app'>{match['application']}</span>"
        f"{risk_badge(match['risk_level'])}</div>"
        f"<div class='result-card-body'>"
        f"<div><span class='result-label'>Library</span><span class='result-value'>{match['library']} {match['version']}</span></div>"
        f"<div><span class='result-label'>Exposure</span><span class='result-value'>{match['dependency_type']} · {match['risk_score']:.1f} risk</span></div>"
        f"<div><span class='result-label'>CVEs</span><span class='result-value'>{cves}</span></div>"
        f"<div><span class='result-label'>Patch</span><span class='result-value'>{patch}</span></div>"
        "</div></div>",
        unsafe_allow_html=True,
    )
    return st.button("Investigate", key=f"investigate_{index}_{match['application']}_{match['library']}", type="primary", use_container_width=True)


def render_vulnerability_card(row: Mapping[str, Any], index: int) -> None:
    """Render one professional vulnerability finding card."""
    patch = "Available" if row.get("patch_available") else "Unavailable"
    severity = str(row.get("severity", "")).title()
    color = RISK_COLORS.get(severity, "#475569")
    st.markdown(
        "<div class='vuln-card'>"
        f"<div class='vuln-card-top'><div><div class='vuln-library'>{row['library']} <span class='vuln-version'>{row['version']}</span></div>"
        f"<div class='vuln-cve'>{row['cve_id']}</div></div>"
        f"<span class='severity-pill' style='background:{color}22;color:{color};border-color:{color}55'>{severity}</span></div>"
        f"<div class='vuln-card-grid'>"
        f"<div><span class='result-label'>CVSS</span><span class='result-value'>{float(row['cvss']):.1f}</span></div>"
        f"<div><span class='result-label'>Patch</span><span class='result-value'>{patch}</span></div>"
        f"<div><span class='result-label'>Application</span><span class='result-value'>{row['application']}</span></div>"
        f"</div>"
        f"<div class='vuln-recommendation'>{row.get('description') or 'Review exposure and apply the recommended patch or mitigation.'}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def render_license_card(row: Mapping[str, Any]) -> None:
    """Render one license compliance action card."""
    status = str(row.get("compatibility_status", "Unknown"))
    color = {"Compatible": "#16A34A", "Incompatible": "#DC2626", "Unknown": "#D97706", "Missing": "#DC2626"}.get(status, "#475569")
    st.markdown(
        "<div class='action-card'>"
        f"<div class='action-card-top'><div class='action-title'>{row['library']} {row['version']}</div>"
        f"<span class='severity-pill' style='background:{color}22;color:{color};border-color:{color}55'>{status}</span></div>"
        f"<div class='action-meta'>{row['application']} · {row.get('license', 'Unknown')}</div>"
        f"<div class='action-body'>{row.get('reason', '')}</div>"
        f"<div class='action-rec'><strong>Recommended action:</strong> {row.get('recommendation', 'Review license policy.')}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def render_maintenance_card(row: Mapping[str, Any]) -> None:
    """Render one maintenance lifecycle action card."""
    status = str(row.get("maintenance_status", "Unknown"))
    color = {"Actively Maintained": "#16A34A", "Moderately Outdated": "#D97706", "Outdated": "#EA580C", "Unmaintained": "#DC2626"}.get(status, "#475569")
    years = row.get("age_years")
    age = f"{float(years):.1f} years old" if years is not None and years == years else "Age unknown"
    st.markdown(
        "<div class='action-card'>"
        f"<div class='action-card-top'><div class='action-title'>{row['library']} {row['version']}</div>"
        f"<span class='severity-pill' style='background:{color}22;color:{color};border-color:{color}55'>{status}</span></div>"
        f"<div class='action-meta'>{row['application']} · {age}</div>"
        f"<div class='action-rec'><strong>Recommendation:</strong> {row.get('recommendation', 'Evaluate upgrade path.')}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def chart_layout(figure: go.Figure, height: int = 300) -> go.Figure:
    """Apply the shared restrained enterprise chart presentation."""
    figure.update_layout(
        template=CHART_TEMPLATE,
        height=height,
        margin=dict(l=10, r=10, t=42, b=10),
        paper_bgcolor="#12161B",
        plot_bgcolor="#12161B",
        font=dict(family="Inter, Arial, sans-serif", color="#E5E7EB"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
    )
    figure.update_xaxes(showgrid=False, linecolor="#374151", tickfont=dict(color="#9CA3AF"))
    figure.update_yaxes(gridcolor="#252B33", zeroline=False, tickfont=dict(color="#9CA3AF"))
    return figure


def risk_comparison_chart(bundle: AnalysisBundle, application: str | None = None) -> go.Figure:
    """Build the application score comparison chart from calculated application risks."""
    frame = scope_frame(application_frame(bundle), application).sort_values("overall_risk_score")
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


def severity_chart(bundle: AnalysisBundle, application: str | None = None) -> go.Figure:
    """Build the vulnerability severity distribution chart."""
    counts = scope_frame(finding_frame(bundle.vulnerability_findings), application).assign(
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


def _read_csv_source(files: Mapping[str, Any] | None, filename: str) -> pd.DataFrame:
    """Read CSV using backend_test.py's encoding fallback sequence."""
    source = _source(files, filename)
    raw_bytes = source.read_bytes() if isinstance(source, Path) else source.getvalue()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return pd.read_csv(StringIO(raw_bytes.decode(encoding)))
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("utf-8", raw_bytes, 0, 1, f"Unable to decode {filename}.")
