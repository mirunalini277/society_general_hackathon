"""License compliance analysis page."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import AnalysisBundle, finding_frame


def render(bundle: AnalysisBundle) -> None:
    """Render license compatibility decisions and recommended remediation."""
    st.markdown("<div class='page-kicker'>Open-source governance</div>", unsafe_allow_html=True)
    st.title("License analysis")
    frame = finding_frame(bundle.license_findings)
    query, status = st.columns((2, 1))
    term = query.text_input("Search application, library, or license")
    selected = status.selectbox("Compatibility", ["All", "Compatible", "Incompatible", "Unknown", "Missing"])
    if term:
        mask = frame[["application", "library", "license"]].astype(str).apply(lambda column: column.str.contains(term, case=False, na=False)).any(axis=1)
        frame = frame[mask]
    if selected != "All":
        frame = frame[frame["compatibility_status"] == selected]
    st.dataframe(frame[["application", "library", "version", "license", "compatibility_status", "severity", "reason", "recommendation"]], use_container_width=True, hide_index=True)
