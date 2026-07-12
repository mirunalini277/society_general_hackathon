"""Executive application investigation dashboard."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import (
    AnalysisBundle,
    application_metadata,
    application_risk_record,
    finding_frame,
    navigate_to,
    risk_badge,
    risk_score_breakdown,
)
from modules.ai_explainer import AIRiskExplainer
from modules.report_generator import generate_pdf_report


def render(bundle: AnalysisBundle) -> None:
    """Render the executive overview for one investigated application."""
    selected = st.session_state.get("selected_application")
    if not selected:
        st.markdown("<div class='page-kicker'>Application investigation</div>", unsafe_allow_html=True)
        st.title("Select an application")
        st.caption("Search for a library or CVE on Home, then click Investigate on an affected application.")
        apps = [item.application for item in bundle.risk_summary.applications]
        choice = st.selectbox("Application", apps, key="application_picker")
        if st.button("Open investigation", type="primary"):
            navigate_to("Application", choice)
        return

    app_risk = application_risk_record(bundle, selected)
    if app_risk is None:
        st.error(f"No risk data found for {selected}.")
        return

    meta = application_metadata(bundle, selected)
    breakdown = risk_score_breakdown(bundle, selected)

    st.markdown("<div class='page-kicker'>Application investigation</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='exec-header'><div><h1 class='exec-title'>{selected}</h1>"
        f"<div class='exec-meta'>Owner {meta['owner']} · Business criticality {meta['criticality']}</div></div>"
        f"<div class='exec-risk'><div class='exec-risk-score'>{app_risk.overall_risk_score:.1f}</div>"
        f"<div class='exec-risk-level'>{risk_badge(app_risk.overall_risk_level)}</div></div></div>",
        unsafe_allow_html=True,
    )

    st.markdown("<div class='section-header'>Risk Score Breakdown</div>", unsafe_allow_html=True)
    cols = st.columns(4)
    labels = [
        ("Vulnerabilities", breakdown["vulnerabilities"]),
        ("Licenses", breakdown["licenses"]),
        ("Maintenance", breakdown["maintenance"]),
        ("Dependency Depth", breakdown["dependency_depth"]),
    ]
    for column, (label, value) in zip(cols, labels):
        with column:
            st.markdown(
                f"<div class='breakdown-card'><div class='breakdown-label'>{label}</div>"
                f"<div class='breakdown-value'>{value:.1f}</div></div>",
                unsafe_allow_html=True,
            )

    st.markdown("<div class='section-header'>Investigation Areas</div>", unsafe_allow_html=True)
    kpi_cols = st.columns(4)
    kpis = [
        ("Dependencies", str(app_risk.total_dependencies), "dependency"),
        ("Vulnerabilities", str(app_risk.vulnerable_dependencies), "Vulnerabilities"),
        ("License Issues", str(app_risk.license_issues), "License"),
        ("Maintenance Issues", str(app_risk.outdated_libraries), "Maintenance"),
    ]
    for column, (label, value, target) in zip(kpi_cols, kpis):
        with column:
            st.markdown(
                f"<div class='kpi-card kpi-card-clickable'><div class='kpi-label'>{label}</div>"
                f"<div class='kpi-value'>{value}</div></div>",
                unsafe_allow_html=True,
            )
            if st.button(f"Open {label}", key=f"kpi_{target}", use_container_width=True):
                if target == "dependency":
                    st.session_state["app_show_dependencies"] = True
                    st.rerun()
                else:
                    navigate_to(target, selected)

    if st.session_state.get("app_show_dependencies"):
        st.markdown("<div class='section-header'>Dependencies</div>", unsafe_allow_html=True)
        dependencies = finding_frame([risk for risk in bundle.dependency_risks if risk.application == selected])
        if dependencies.empty:
            st.info("No dependencies found for this application.")
        else:
            dep_lookup = {
                (row["application"], row["library"], row["version"]): row.get("dependency_type", "Unknown")
                for _, row in bundle.dependencies.iterrows()
            }
            for _, row in dependencies.sort_values("final_risk_score", ascending=False).iterrows():
                dep_type = dep_lookup.get((selected, row["library"], row["version"]), "Unknown")
                st.markdown(
                    "<div class='result-card'>"
                    f"<div class='result-card-header'><span class='result-app'>{row['library']} {row['version']}</span>"
                    f"{risk_badge(row['final_risk_level'])}</div>"
                    f"<div class='result-card-body'><div><span class='result-label'>Exposure</span>"
                    f"<span class='result-value'>{dep_type} · {row['final_risk_score']:.1f} risk</span></div></div></div>",
                    unsafe_allow_html=True,
                )

    st.markdown("<div class='section-header'>Executive AI Summary</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='summary-panel'>{app_risk.explanation}</div>", unsafe_allow_html=True)
    ai_key = f"ai_summary_{selected}"
    if st.button("Generate AI executive summary", use_container_width=False):
        with st.spinner("Preparing executive summary..."):
            st.session_state[ai_key] = AIRiskExplainer().generate_application_summary(app_risk)
    if ai_key in st.session_state:
        st.markdown(f"<div class='summary-panel summary-panel-ai'>{st.session_state[ai_key]}</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-header'>Export Investigation Report</div>", unsafe_allow_html=True)
    export_cols = st.columns(2)
    with export_cols[0]:
        if st.button("Generate PDF Report", type="primary", use_container_width=True):
            with st.spinner("Generating application report..."):
                path = generate_pdf_report(
                    bundle.risk_summary,
                    bundle.dependency_risks,
                    bundle.vulnerability_findings,
                    bundle.license_findings,
                    bundle.maintenance_findings,
                    application=selected,
                )
            st.session_state[f"pdf_path_{selected}"] = path
            st.success(f"Report generated: {path.name}")
        pdf_path = st.session_state.get(f"pdf_path_{selected}")
        if pdf_path is not None and pdf_path.exists():
            st.download_button(
                "Download PDF",
                data=pdf_path.read_bytes(),
                file_name=pdf_path.name,
                mime="application/pdf",
                use_container_width=True,
            )
    with export_cols[1]:
        dependencies = finding_frame([risk for risk in bundle.dependency_risks if risk.application == selected])
        st.download_button(
            "Download CSV",
            data=dependencies.to_csv(index=False).encode("utf-8"),
            file_name=f"supplyshield_{selected}_dependencies.csv",
            mime="text/csv",
            use_container_width=True,
        )
