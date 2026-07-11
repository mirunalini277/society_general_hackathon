"""SupplyShield enterprise Streamlit application entry point."""

from __future__ import annotations

from pathlib import Path
import platform

import streamlit as st

from dashboard import application, dependency_graph, licenses, maintenance, overview, reports, vulnerabilities
from dashboard.shared import ROOT, run_analysis


def _load_css() -> None:
    """Apply the local enterprise design system stylesheet."""
    css_path = ROOT / "assets" / "css" / "supplyshield.css"
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def _run_with_sources(sources: dict[str, object] | None) -> None:
    """Run analysis and retain typed backend outputs for page navigation."""
    with st.spinner("Running SupplyShield analysis across the software supply chain..."):
        st.session_state["bundle"] = run_analysis(sources)
    st.toast("Analysis complete. Supply chain findings are ready.", icon="✅")


def _sidebar() -> tuple[str, dict[str, object] | None]:
    """Render product identity, navigation, and the required dataset upload controls."""
    with st.sidebar:
        icon = ROOT / "assets" / "icons" / "shield.png"
        if icon.exists():
            st.image(str(icon), width=46)
        st.markdown("<div class='brand-title'>SupplyShield</div><div class='brand-subtitle'>Software Supply Chain Risk Analyzer</div>", unsafe_allow_html=True)
        st.divider()
        page = st.radio("Navigation", ["Dashboard", "Applications", "Dependency Graph", "Vulnerabilities", "License Analysis", "Maintenance", "Reports", "Settings"], label_visibility="collapsed")
        st.divider()
        st.caption("DATA SOURCES")
        uploads = {
            "applications.json": st.file_uploader("applications.json", type=["json"], key="apps_upload"),
            "sbom_dependencies.csv": st.file_uploader("sbom_dependencies.csv", type=["csv"], key="sbom_upload"),
            "vulnerability_db.json": st.file_uploader("vulnerability_db.json", type=["json"], key="vuln_upload"),
            "license_rules.json": st.file_uploader("license_rules.json", type=["json"], key="license_upload"),
        }
        if st.button("Analyze supply chain", type="primary", use_container_width=True):
            if any(uploads.values()) and not all(uploads.values()):
                st.error("Upload all four datasets or clear all uploads to use sample data.")
            else:
                _run_with_sources(uploads if all(uploads.values()) else None)
        st.caption("No uploads? SupplyShield automatically analyzes the included sample data.")
    return page, uploads


def _settings(bundle: object) -> None:
    """Render lightweight deployment and dataset information."""
    st.title("Settings")
    st.caption("Runtime and analysis configuration")
    first, second, third = st.columns(3)
    first.metric("Application Version", "1.0.0")
    second.metric("Python Version", platform.python_version())
    third.metric("Backend Status", "Operational")
    st.subheader("Analysis Runtime")
    st.write("Loaded Model: Gemini Flash Latest with deterministic fallback")
    st.write(f"Dataset Statistics: {len(bundle.risk_summary.applications)} applications, {len(bundle.dependencies)} dependencies")
    st.toggle("Dark Mode", value=False, disabled=True, help="Theme selection is reserved for a managed deployment preference.")


def main() -> None:
    """Start the Streamlit frontend and route pages to shared analysis outputs."""
    st.set_page_config(page_title="SupplyShield", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    _load_css()
    page, _ = _sidebar()
    if "bundle" not in st.session_state:
        try:
            _run_with_sources(None)
        except Exception as exc:
            st.error(f"SupplyShield could not load the sample datasets: {exc}")
            st.stop()
    bundle = st.session_state["bundle"]
    renderers = {
        "Dashboard": overview.render,
        "Applications": application.render,
        "Dependency Graph": dependency_graph.render,
        "Vulnerabilities": vulnerabilities.render,
        "License Analysis": licenses.render,
        "Maintenance": maintenance.render,
        "Reports": reports.render,
        "Settings": _settings,
    }
    try:
        renderers[page](bundle)
    except Exception as exc:
        st.error(f"Unable to render {page}: {exc}")


if __name__ == "__main__":
    main()
