"""Executive dashboard page for SupplyShield."""

from __future__ import annotations

from collections import Counter

import plotly.express as px
import streamlit as st

from dashboard.shared import AnalysisBundle, RISK_COLORS, application_frame, application_selector, chart_layout, finding_frame, health_score, risk_comparison_chart, scope_frame, severity_chart


def _card(label: str, value: str, detail: str = "") -> None:
    """Render one enterprise KPI card."""
    st.markdown(f"<div class='kpi-card'><div class='kpi-label'>{label}</div><div class='kpi-value'>{value}</div><div class='kpi-meta'>{detail}</div></div>", unsafe_allow_html=True)


def render(bundle: AnalysisBundle) -> None:
    """Render the portfolio dashboard from calculated backend outputs."""
    applications = application_frame(bundle)
    st.markdown("<div class='page-kicker'>Portfolio security posture</div>", unsafe_allow_html=True)
    st.title("Supply chain risk dashboard")
    st.caption("Enterprise visibility across vulnerabilities, licensing, maintenance, and dependency exposure.")
    selected_application = application_selector(bundle, key="overview_application_scope")
    applications = scope_frame(applications, selected_application)
    vulnerabilities = scope_frame(finding_frame(bundle.vulnerability_findings), selected_application)
    licenses = scope_frame(finding_frame(bundle.license_findings), selected_application)
    maintenance_frame = scope_frame(finding_frame(bundle.maintenance_findings), selected_application)
    dependencies = scope_frame(bundle.dependencies, selected_application)
    critical = sum((vulnerabilities["cvss"] >= 9.0) | (vulnerabilities["severity"].str.casefold() == "critical"))
    cards = st.columns(6)
    with cards[0]: _card("Applications", str(len(applications)), "In active portfolio")
    with cards[1]: _card("Dependencies", str(len(dependencies)), "SBOM instances")
    with cards[2]: _card("Critical findings", str(critical), "CVSS 9.0+ or Critical")
    with cards[3]: _card("License issues", str((licenses["compatibility_status"] != "Compatible").sum()), "Requires policy action")
    with cards[4]: _card("Unmaintained", str((maintenance_frame["maintenance_status"] == "Unmaintained").sum()), "Unsupported components")
    average = applications["overall_risk_score"].mean() if len(applications) else 0
    with cards[5]: _card("Average risk", f"{average:.1f}", f"Health score {100 - average:.1f}/100")

    st.markdown("<div class='section-header'>Risk intelligence</div>", unsafe_allow_html=True)
    left, right = st.columns((1.25, 1))
    with left:
        st.plotly_chart(risk_comparison_chart(bundle, selected_application), use_container_width=True)
    with right:
        distribution = applications["overall_risk_level"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0).reset_index()
        distribution.columns = ["risk", "applications"]
        figure = px.pie(distribution, names="risk", values="applications", hole=.66, color="risk", color_discrete_map=RISK_COLORS)
        st.plotly_chart(chart_layout(figure, 330), use_container_width=True)

    first, second, third = st.columns(3)
    with first:
        st.plotly_chart(severity_chart(bundle, selected_application), use_container_width=True)
    with second:
        top = vulnerabilities.groupby("library", as_index=False).size().nlargest(8, "size").sort_values("size")
        st.plotly_chart(chart_layout(px.bar(top, x="size", y="library", orientation="h", labels={"size": "Findings", "library": ""}), 300), use_container_width=True)
    with third:
        maintenance = Counter(maintenance_frame["maintenance_status"])
        statuses = list(maintenance)
        figure = px.bar(x=statuses, y=[maintenance[item] for item in statuses], color=statuses, color_discrete_map={"Actively Maintained": "#16A34A", "Moderately Outdated": "#D97706", "Outdated": "#EA580C", "Unmaintained": "#DC2626"}, labels={"x": "", "y": "Dependencies"})
        st.plotly_chart(chart_layout(figure, 300), use_container_width=True)

    st.markdown("<div class='section-header'>License distribution</div>", unsafe_allow_html=True)
    counts = licenses["compatibility_status"].value_counts().reset_index()
    counts.columns = ["status", "count"]
    st.plotly_chart(chart_layout(px.bar(counts, x="status", y="count", color="status", color_discrete_map={"Compatible": "#16A34A", "Incompatible": "#DC2626", "Unknown": "#D97706", "Missing": "#DC2626"}, labels={"status": "", "count": "Libraries"}), 280), use_container_width=True)
