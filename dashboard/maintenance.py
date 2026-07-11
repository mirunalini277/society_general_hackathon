"""Dependency maintenance health page."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import AnalysisBundle, finding_frame


def render(bundle: AnalysisBundle) -> None:
    """Render maintenance evidence, age, status, and upgrade recommendations."""
    st.markdown("<div class='page-kicker'>Lifecycle management</div>", unsafe_allow_html=True)
    st.title("Maintenance")
    frame = finding_frame(bundle.maintenance_findings)
    query, status, risk = st.columns((2, 1, 1))
    term = query.text_input("Search application or library")
    selected_status = status.selectbox("Maintenance status", ["All", "Actively Maintained", "Moderately Outdated", "Outdated", "Unmaintained"])
    selected_risk = risk.selectbox("Risk level", ["All", "Critical", "High", "Medium", "Low"])
    if term:
        mask = frame[["application", "library"]].astype(str).apply(lambda column: column.str.contains(term, case=False, na=False)).any(axis=1)
        frame = frame[mask]
    if selected_status != "All": frame = frame[frame["maintenance_status"] == selected_status]
    if selected_risk != "All": frame = frame[frame["risk_level"] == selected_risk]
    st.dataframe(frame[["application", "library", "version", "last_updated", "age_years", "maintenance_status", "risk_level", "recommendation"]].sort_values("age_years", ascending=False), use_container_width=True, hide_index=True, column_config={"age_years": st.column_config.NumberColumn("Years Old", format="%.2f")})
