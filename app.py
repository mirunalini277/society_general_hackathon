"""SupplyShield incident-response workspace for software supply chain security."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from dashboard import application, dependency_graph, licenses, maintenance, vulnerabilities
from dashboard.shared import (
    ROOT,
    application_frame,
    critical_cve_count,
    incident_search,
    navigate_to,
    render_investigate_button,
    render_search_result_card,
    risk_badge,
    run_analysis,
)


def _load_css() -> None:
    css_path = ROOT / "assets" / "css" / "supplyshield.css"
    if css_path.exists():
        st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def _run_with_sources(sources: dict[str, object] | None) -> None:
    with st.spinner("Analyzing the software supply chain..."):
        st.session_state["bundle"] = run_analysis(sources)
    st.success("Analysis complete. Search for a library or CVE to begin investigation.")


def _sidebar(bundle: object | None) -> str:
    """Render incident-response navigation without a standalone graph page."""
    with st.sidebar:
        icon = ROOT / "assets" / "icons" / "shield.png"
        if icon.exists():
            st.image(str(icon), width=42)
        st.markdown(
            "<div class='brand-title'>SupplyShield</div>"
            "<div class='brand-subtitle'>Supply chain incident response</div>",
            unsafe_allow_html=True,
        )
        st.divider()
        pages = ["Home", "Application", "Vulnerabilities", "License", "Maintenance", "Dependency Graph"]
        icons = {
            "Home": "⌂",
            "Application": "▤",
            "Vulnerabilities": "!",
            "License": "§",
            "Maintenance": "◷",
            "Dependency Graph": "⌘",
        }
        current_page = st.session_state.get("current_page", "Home")
        if current_page not in pages:
            current_page = "Home"
            st.session_state["current_page"] = current_page
        target_page = st.session_state.pop("navigation_target", None)
        if target_page in pages:
            st.session_state["navigation_widget"] = target_page
        elif "navigation_widget" not in st.session_state:
            st.session_state["navigation_widget"] = current_page
        page = st.radio(
            "Navigation",
            pages,
            format_func=lambda item: f"{icons[item]}  {item}",
            label_visibility="collapsed",
            key="navigation_widget",
        )
        st.session_state["current_page"] = page
        st.divider()
        if bundle is None:
            st.caption("Upload an SBOM or use the sample dataset from Home to begin.")
        else:
            selected = st.session_state.get("selected_application")
            scope = selected or "Portfolio"
            st.caption(f"ACTIVE INVESTIGATION\n\n{scope}")
            if selected and st.button("Back to portfolio", use_container_width=True):
                st.session_state.pop("selected_application", None)
                st.session_state["navigation_target"] = "Home"
                st.rerun()
            if st.button("New analysis", use_container_width=True):
                st.session_state.pop("bundle", None)
                st.session_state.pop("selected_application", None)
                st.session_state["navigation_target"] = "Home"
                st.rerun()
    return page


def _home() -> None:
    """Render intake, incident search, and top-risk application cards."""
    st.markdown("<div class='page-kicker'>Software supply chain incident response</div>", unsafe_allow_html=True)
    st.title("SupplyShield")
    st.markdown(
        "<p class='hero-subtitle'>Investigate supply chain exposure the moment a vulnerability is announced.</p>",
        unsafe_allow_html=True,
    )

    upload_col, action_col = st.columns((3, 1))
    with upload_col:
        uploads = {
            "applications.json": st.file_uploader("Application inventory", type=["json"], key="apps_upload"),
            "sbom_dependencies.csv": st.file_uploader("Dependency SBOM", type=["csv"], key="sbom_upload"),
            "vulnerability_db.json": st.file_uploader("Vulnerability database", type=["json"], key="vuln_upload"),
            "license_rules.json": st.file_uploader("License policy", type=["json"], key="license_upload"),
        }
    with action_col:
        st.markdown("<div class='section-header'>Start investigation</div>", unsafe_allow_html=True)
        if st.button("Use Sample Dataset", use_container_width=True):
            _run_with_sources(None)
        if st.button("Analyze", type="primary", use_container_width=True):
            if not all(uploads.values()):
                st.error("Upload all four source files, or use the sample dataset.")
            else:
                _run_with_sources(uploads)

    bundle = st.session_state.get("bundle")
    if bundle is None:
        st.markdown("<div class='empty-state'>Upload your SBOM or load the sample dataset to begin an investigation.</div>", unsafe_allow_html=True)
        return

    st.markdown("<div class='section-header section-header-large'>Incident Search</div>", unsafe_allow_html=True)
    st.markdown(
        "<p class='search-hint'>Search by library name, CVE, or application — e.g. <code>neo4j</code>, <code>log4j</code>, <code>CVE-2025-1001</code>, <code>CustomerPortal</code></p>",
        unsafe_allow_html=True,
    )
    query = st.text_input(
        "Incident Search",
        placeholder="Search library, CVE, or application…",
        label_visibility="collapsed",
        key="home_incident_search",
    )

    matches = incident_search(bundle, query)
    if query.strip():
        st.markdown("<div class='section-header'>Search Results</div>", unsafe_allow_html=True)
        if not matches:
            st.info("No applications or dependencies match that search.")
        else:
            st.caption(f"{len({item['application'] for item in matches})} application(s) affected")
            for index, match in enumerate(matches):
                if render_search_result_card(match, index):
                    navigate_to("Application", match["application"])

    st.markdown("<div class='section-header'>Top Risk Applications</div>", unsafe_allow_html=True)
    apps = application_frame(bundle).sort_values("overall_risk_score", ascending=False)
    if apps.empty:
        st.info("No application risk data available.")
        return
    columns = st.columns(min(3, len(apps)))
    for index, (_, row) in enumerate(apps.iterrows()):
        with columns[index % len(columns)]:
            st.markdown(
                "<div class='app-risk-card'>"
                f"<div class='app-risk-name'>{row['application']}</div>"
                f"<div class='app-risk-score'>{row['overall_risk_score']:.1f}</div>"
                f"<div class='app-risk-level'>{risk_badge(row['overall_risk_level'])}</div>"
                "<div class='app-risk-stats'>"
                f"<span>{critical_cve_count(bundle, row['application'])} critical CVEs</span>"
                f"<span>{int(row['license_issues'])} license issues</span>"
                f"<span>{int(row['outdated_libraries'])} maintenance issues</span>"
                "</div></div>",
                unsafe_allow_html=True,
            )
            if render_investigate_button(row["application"], str(index)):
                navigate_to("Application", row["application"])


def main() -> None:
    st.set_page_config(page_title="SupplyShield", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    _load_css()
    bundle = st.session_state.get("bundle")
    page = _sidebar(bundle)
    if page == "Home":
        _home()
        return
    if bundle is None:
        st.info("Start an analysis from Home before opening investigation views.")
        return
    renderers = {
        "Application": application.render,
        "Vulnerabilities": vulnerabilities.render,
        "License": licenses.render,
        "Maintenance": maintenance.render,
        "Dependency Graph": dependency_graph.render,
    }
    try:
        renderers[page](bundle)
    except Exception as exc:
        st.error(f"Unable to render {page}: {exc}")


if __name__ == "__main__":
    main()
