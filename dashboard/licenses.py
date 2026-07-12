"""License compliance investigation page."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import AnalysisBundle, application_selector, finding_frame, scope_frame


def render(bundle: AnalysisBundle) -> None:
    """Render license compatibility issues and recommended remediation actions."""
    st.markdown("<div class='page-kicker'>Open-source governance</div>", unsafe_allow_html=True)
    st.title("License Issues")
    st.caption("Focus on compatibility conflicts, unknown licenses, and copyleft exposure.")

    selected_application = application_selector(bundle, key="license_application_scope")
    frame = scope_frame(finding_frame(bundle.license_findings), selected_application)
    frame = frame[frame["compatibility_status"] != "Compatible"] if not frame.empty else frame

    filter_cols = st.columns((2, 1, 1, 1))
    with filter_cols[0]:
        term = st.text_input("Search", placeholder="Application, library, or license", label_visibility="collapsed", key="license_search")
    with filter_cols[1]:
        selected = st.selectbox("Compatibility", ["All", "Incompatible", "Unknown", "Missing"], key="license_status")
    with filter_cols[2]:
        gpl_filter = st.selectbox("GPL", ["All", "GPL only", "Exclude GPL"], key="license_gpl")
    with filter_cols[3]:
        agpl_filter = st.selectbox("AGPL", ["All", "AGPL only", "Exclude AGPL"], key="license_agpl")

    if term:
        mask = frame[["application", "library", "license"]].astype(str).apply(
            lambda column: column.str.contains(term, case=False, na=False)
        ).any(axis=1)
        frame = frame[mask]
    if selected != "All":
        frame = frame[frame["compatibility_status"] == selected]
    if gpl_filter == "GPL only":
        frame = frame[frame["license"].astype(str).str.contains("GPL", case=False, na=False) & ~frame["license"].astype(str).str.contains("AGPL", case=False, na=False)]
    elif gpl_filter == "Exclude GPL":
        frame = frame[~frame["license"].astype(str).str.contains("GPL", case=False, na=False)]
    if agpl_filter == "AGPL only":
        frame = frame[frame["license"].astype(str).str.contains("AGPL", case=False, na=False)]
    elif agpl_filter == "Exclude AGPL":
        frame = frame[~frame["license"].astype(str).str.contains("AGPL", case=False, na=False)]

    summary_cols = st.columns(4)
    with summary_cols[0]:
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>Issues in scope</div><div class='kpi-value'>{len(frame)}</div></div>", unsafe_allow_html=True)
    with summary_cols[1]:
        unknown = (frame["compatibility_status"] == "Unknown").sum() if not frame.empty else 0
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>Unknown licenses</div><div class='kpi-value'>{unknown}</div></div>", unsafe_allow_html=True)
    with summary_cols[2]:
        gpl = frame["license"].astype(str).str.contains("GPL", case=False, na=False).sum() if not frame.empty else 0
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>GPL exposure</div><div class='kpi-value'>{gpl}</div></div>", unsafe_allow_html=True)
    with summary_cols[3]:
        agpl = frame["license"].astype(str).str.contains("AGPL", case=False, na=False).sum() if not frame.empty else 0
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>AGPL exposure</div><div class='kpi-value'>{agpl}</div></div>", unsafe_allow_html=True)

    st.markdown("<div class='section-header'>License compliance findings</div>", unsafe_allow_html=True)
    if frame.empty:
        st.info("No license issues match the current filters.")
        return
    display = frame[["library", "version", "license", "compatibility_status", "severity", "recommendation"]].rename(
        columns={
            "library": "Library",
            "version": "Version",
            "license": "License",
            "compatibility_status": "Compatibility",
            "severity": "Risk",
            "recommendation": "Recommendation",
        }
    )
    st.dataframe(display.sort_values(["Risk", "Library"]), use_container_width=True, hide_index=True)
