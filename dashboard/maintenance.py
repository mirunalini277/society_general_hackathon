"""Dependency maintenance health investigation page."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import AnalysisBundle, application_selector, finding_frame, scope_frame


def render(bundle: AnalysisBundle) -> None:
    """Render outdated and unsupported dependency lifecycle findings."""
    st.markdown("<div class='page-kicker'>Lifecycle management</div>", unsafe_allow_html=True)
    st.title("Maintenance Issues")
    st.caption("Focus on outdated packages, unsupported libraries, and upgrade recommendations.")

    selected_application = application_selector(bundle, key="maintenance_application_scope")
    frame = scope_frame(finding_frame(bundle.maintenance_findings), selected_application)
    frame = frame[frame["maintenance_status"] != "Actively Maintained"] if not frame.empty else frame

    filter_cols = st.columns((2, 1, 1))
    with filter_cols[0]:
        term = st.text_input("Search", placeholder="Application or library", label_visibility="collapsed", key="maintenance_search")
    with filter_cols[1]:
        selected_status = st.selectbox(
            "Status",
            ["All", "Moderately Outdated", "Outdated", "Unmaintained"],
            key="maintenance_status",
        )
    with filter_cols[2]:
        selected_risk = st.selectbox("Risk level", ["All", "Critical", "High", "Medium", "Low"], key="maintenance_risk")

    if term:
        mask = frame[["application", "library"]].astype(str).apply(
            lambda column: column.str.contains(term, case=False, na=False)
        ).any(axis=1)
        frame = frame[mask]
    if selected_status != "All":
        frame = frame[frame["maintenance_status"] == selected_status]
    if selected_risk != "All":
        frame = frame[frame["risk_level"] == selected_risk]

    summary_cols = st.columns(4)
    with summary_cols[0]:
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>Issues in scope</div><div class='kpi-value'>{len(frame)}</div></div>", unsafe_allow_html=True)
    with summary_cols[1]:
        outdated = (frame["maintenance_status"] == "Outdated").sum() if not frame.empty else 0
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>Outdated packages</div><div class='kpi-value'>{outdated}</div></div>", unsafe_allow_html=True)
    with summary_cols[2]:
        unsupported = (frame["maintenance_status"] == "Unmaintained").sum() if not frame.empty else 0
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>Unsupported libraries</div><div class='kpi-value'>{unsupported}</div></div>", unsafe_allow_html=True)
    with summary_cols[3]:
        old = (frame["age_years"] >= 3).sum() if not frame.empty and "age_years" in frame.columns else 0
        st.markdown(f"<div class='kpi-card'><div class='kpi-label'>3+ years old</div><div class='kpi-value'>{old}</div></div>", unsafe_allow_html=True)

    st.markdown("<div class='section-header'>Maintenance findings</div>", unsafe_allow_html=True)
    if frame.empty:
        st.info("No maintenance issues match the current filters.")
        return
    display = frame[["library", "version", "age_years", "maintenance_status", "risk_level", "recommendation"]].rename(
        columns={
            "library": "Package",
            "version": "Version",
            "age_years": "Age (Years)",
            "maintenance_status": "Status",
            "risk_level": "Risk",
            "recommendation": "Recommendation",
        }
    )
    st.dataframe(
        display.sort_values("Age (Years)", ascending=False, na_position="last"),
        use_container_width=True,
        hide_index=True,
        column_config={"Age (Years)": st.column_config.NumberColumn(format="%.1f")},
    )
