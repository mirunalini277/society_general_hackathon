"""Application risk inventory and details page."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import AnalysisBundle, application_frame, finding_frame
from modules.ai_explainer import AIRiskExplainer
from modules.report_generator import generate_pdf_report


def render(bundle: AnalysisBundle) -> None:
    """Render searchable application risk inventory and selected application detail."""
    st.markdown("<div class='page-kicker'>Application inventory</div>", unsafe_allow_html=True)
    st.title("Applications")
    frame = application_frame(bundle)
    search, level = st.columns((2, 1))
    query = search.text_input("Search applications", placeholder="Search by application name")
    selected_level = level.selectbox("Risk level", ["All", "Critical", "High", "Medium", "Low"])
    filtered = frame.copy()
    if query:
        filtered = filtered[filtered["application"].str.contains(query, case=False, na=False)]
    if selected_level != "All":
        filtered = filtered[filtered["overall_risk_level"] == selected_level]
    display = filtered[["application", "overall_risk_score", "overall_risk_level", "total_dependencies", "vulnerable_dependencies", "license_issues", "outdated_libraries"]].rename(columns={"application": "Application", "overall_risk_score": "Risk Score", "overall_risk_level": "Risk Level", "total_dependencies": "Dependencies", "vulnerable_dependencies": "Critical Findings", "license_issues": "License Issues", "outdated_libraries": "Maintenance Issues"})
    st.dataframe(display, use_container_width=True, hide_index=True, column_config={"Risk Score": st.column_config.NumberColumn(format="%.2f")})
    if filtered.empty:
        return
    chosen = st.selectbox("View application details", filtered["application"].tolist())
    application = next(item for item in bundle.risk_summary.applications if item.application == chosen)
    st.markdown("<div class='section-header'>Application details</div>", unsafe_allow_html=True)
    cards = st.columns(5)
    cards[0].metric("Risk Score", f"{application.overall_risk_score:.2f}")
    cards[1].metric("Risk Level", application.overall_risk_level)
    cards[2].metric("Dependencies", application.total_dependencies)
    cards[3].metric("Critical CVEs", application.vulnerable_dependencies)
    cards[4].metric("License Issues", application.license_issues)
    details, actions = st.columns((2, 1))
    with details:
        if st.button("Generate AI executive summary", use_container_width=True):
            st.info(AIRiskExplainer().generate_application_summary(application))
        else:
            st.caption("Generate an enterprise-ready summary using Gemini or the built-in deterministic fallback.")
    with actions:
        if st.button("Generate PDF Report", type="primary", use_container_width=True):
            path = generate_pdf_report(bundle.risk_summary, bundle.dependency_risks, bundle.vulnerability_findings, bundle.license_findings, bundle.maintenance_findings, application=chosen)
            st.success(f"Application PDF generated: {path.name}")
        if st.button("Open Dependency Graph", use_container_width=True):
            st.session_state["graph_application"] = chosen
            st.info("Open Dependency Graph from the sidebar to inspect this application.")
    app_dependencies = [risk.as_dict() for risk in bundle.dependency_risks if risk.application == chosen]
    st.dataframe(finding_frame([type("Item", (), {"as_dict": lambda self, row=row: row})() for row in app_dependencies]), use_container_width=True, hide_index=True)
