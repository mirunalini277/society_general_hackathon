"""Vulnerability investigation page."""

from __future__ import annotations

import streamlit as st

from dashboard.shared import AnalysisBundle, finding_frame


def render(bundle: AnalysisBundle) -> None:
    """Render searchable and filterable matched vulnerability findings."""
    st.markdown("<div class='page-kicker'>Exposure management</div>", unsafe_allow_html=True)
    st.title("Vulnerabilities")
    frame = finding_frame(bundle.vulnerability_findings)
    query, severity, patch = st.columns((2, 1, 1))
    term = query.text_input("Search CVE, library, or application")
    selected = severity.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
    patch_filter = patch.selectbox("Patch", ["All", "Available", "Unavailable"])
    if term:
        mask = frame[["application", "library", "cve_id"]].astype(str).apply(lambda column: column.str.contains(term, case=False, na=False)).any(axis=1)
        frame = frame[mask]
    if selected != "All":
        if selected == "Critical":
            frame = frame[(frame["severity"].str.title() == "Critical") | (frame["cvss"] >= 9.0)]
        else:
            frame = frame[frame["severity"].str.title() == selected]
    if patch_filter != "All":
        frame = frame[frame["patch_available"] == (patch_filter == "Available")]
    columns = ["application", "library", "version", "cve_id", "cvss", "severity", "patch_available", "exploitability", "description"]
    st.dataframe(frame[columns].sort_values(["cvss", "application"], ascending=[False, True]), use_container_width=True, hide_index=True, column_config={"cvss": st.column_config.NumberColumn("CVSS", format="%.1f"), "patch_available": "Patch Available"})
