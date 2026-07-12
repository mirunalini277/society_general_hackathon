"""Vulnerability investigation page with embedded dependency graph."""

from __future__ import annotations

import streamlit as st
from dashboard.shared import (
    AnalysisBundle,
    application_selector,
    finding_frame,
    render_vulnerability_card,
    scope_frame,
)


def render(bundle: AnalysisBundle) -> None:
    """Render filterable vulnerability cards and the dependency graph."""
    st.markdown("<div class='page-kicker'>Security investigation</div>", unsafe_allow_html=True)
    st.title("Vulnerabilities")
    st.caption("Investigate matched CVEs, assess patch readiness, and trace dependency exposure.")

    selected_application = application_selector(bundle, key="vulnerability_application_scope")
    frame = scope_frame(finding_frame(bundle.vulnerability_findings), selected_application)

    filter_cols = st.columns((2, 1, 1, 1))
    with filter_cols[0]:
        term = st.text_input("Search", placeholder="CVE, library, or application", label_visibility="collapsed", key="vuln_search")
    with filter_cols[1]:
        selected = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], key="vuln_severity")
    with filter_cols[2]:
        patch_filter = st.selectbox("Patch", ["All", "Available", "Unavailable"], key="vuln_patch")
    with filter_cols[3]:
        libraries = ["All", *sorted(frame["library"].dropna().unique().tolist())] if not frame.empty else ["All"]
        library_filter = st.selectbox("Library", libraries, key="vuln_library")

    if term:
        mask = frame[["application", "library", "cve_id"]].astype(str).apply(
            lambda column: column.str.contains(term, case=False, na=False)
        ).any(axis=1)
        frame = frame[mask]
    if selected != "All":
        if selected == "Critical":
            frame = frame[(frame["severity"].str.title() == "Critical") | (frame["cvss"] >= 9.0)]
        else:
            frame = frame[frame["severity"].str.title() == selected]
    if patch_filter != "All":
        frame = frame[frame["patch_available"] == (patch_filter == "Available")]
    if library_filter != "All":
        frame = frame[frame["library"] == library_filter]

    st.caption(f"{len(frame):,} vulnerability finding(s) in scope")
    if frame.empty:
        st.info("No vulnerability findings match the current filters.")
    else:
        for index, row in enumerate(frame.sort_values(["cvss", "application"], ascending=[False, True]).to_dict("records")):
            render_vulnerability_card(row, index)
