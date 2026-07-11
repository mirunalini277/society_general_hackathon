"""Audit-ready PDF and CSV report generation for SupplyShield risk analysis."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
import csv
from html import escape
import logging
from pathlib import Path
import re
from typing import Any, Iterable, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen.canvas import Canvas

from .license_checker import LicenseFinding
from .maintenance_checker import MaintenanceFinding
from .risk_engine import ApplicationRisk, DependencyRisk, RiskSummary
from .vulnerability_checker import VulnerabilityMatch

LOGGER = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_REPORT_DIRECTORY = _PROJECT_ROOT / "generated" / "reports"
_DEFAULT_EXPORT_DIRECTORY = _PROJECT_ROOT / "generated" / "exports"
_RISK_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#CA8A04"),
    "Low": colors.HexColor("#16A34A"),
}
_DARK = colors.HexColor("#0F172A")
_SLATE = colors.HexColor("#334155")
_LIGHT = colors.HexColor("#F1F5F9")
_BORDER = colors.HexColor("#CBD5E1")

__all__ = [
    "ReportGenerationError",
    "ReportArtifacts",
    "generate_pdf_report",
    "generate_csv_reports",
    "generate_reports",
]


class ReportGenerationError(RuntimeError):
    """Raised when a SupplyShield report cannot be written successfully."""


@dataclass(frozen=True, slots=True)
class ReportArtifacts:
    """Paths produced by a portfolio or single-application report generation run."""

    pdf_path: Path
    csv_paths: tuple[Path, ...]


class _NumberedCanvas(Canvas):
    """Canvas that adds a consistent footer and page numbering after document build."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        """Capture each page state for later footer rendering."""
        self._page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        """Draw all captured pages with final page number totals."""
        page_count = len(self._page_states)
        for state in self._page_states:
            self.__dict__.update(state)
            self.setStrokeColor(_BORDER)
            self.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
            self.setFillColor(_SLATE)
            self.setFont("Helvetica", 8)
            self.drawString(18 * mm, 9 * mm, "SupplyShield - Software Supply Chain Risk Analysis")
            page_label = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(A4[0] - 18 * mm, 9 * mm, page_label)
            super().showPage()
        super().save()


def generate_pdf_report(
    risk_summary: RiskSummary,
    dependency_risks: Iterable[DependencyRisk],
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
    *,
    application: str | None = None,
    output_directory: str | Path = _DEFAULT_REPORT_DIRECTORY,
) -> Path:
    """Generate a professional portfolio or single-application PDF audit report.

    Args:
        risk_summary: Portfolio summary returned by the risk engine.
        dependency_risks: Dependency-level risk assessments.
        vulnerability_findings: Vulnerability checker output.
        license_findings: License checker output.
        maintenance_findings: Maintenance checker output.
        application: Optional application name for a focused report.
        output_directory: Destination directory; defaults to ``generated/reports``.

    Returns:
        Path to the generated PDF report.

    Raises:
        ReportGenerationError: If ReportLab cannot generate or write the PDF.
    """
    scope = _scope_data(
        risk_summary,
        dependency_risks,
        vulnerability_findings,
        license_findings,
        maintenance_findings,
        application,
    )
    filename = _report_filename("supplyshield", application, "pdf")
    destination = _prepare_directory(output_directory) / filename
    styles = _styles()
    story = _build_pdf_story(scope, styles, application)

    try:
        document = BaseDocTemplate(
            str(destination),
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=20 * mm,
            title="SupplyShield Software Supply Chain Risk Analysis",
            author="SupplyShield",
        )
        document.addPageTemplates(PageTemplate(id="audit", frames=[document_frame(document)]))
        document.build(story, canvasmaker=_NumberedCanvas)
    except (OSError, ValueError, TypeError) as exc:
        LOGGER.exception("Unable to generate PDF report at %s.", destination)
        raise ReportGenerationError(f"Unable to generate PDF report: {exc}") from exc
    LOGGER.info("Generated PDF report: %s", destination)
    return destination


def generate_csv_reports(
    risk_summary: RiskSummary,
    dependency_risks: Iterable[DependencyRisk],
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
    *,
    application: str | None = None,
    output_directory: str | Path = _DEFAULT_EXPORT_DIRECTORY,
) -> tuple[Path, ...]:
    """Export scoped application, dependency, vulnerability, license, and maintenance CSVs."""
    scope = _scope_data(
        risk_summary,
        dependency_risks,
        vulnerability_findings,
        license_findings,
        maintenance_findings,
        application,
    )
    directory = _prepare_directory(output_directory)
    exports = {
        "application_risk": [_application_row(item) for item in scope["applications"]],
        "dependency_risk": [_dependency_row(item) for item in scope["dependencies"]],
        "vulnerabilities": [_vulnerability_row(item) for item in scope["vulnerabilities"]],
        "license_compliance": [_license_row(item) for item in scope["licenses"]],
        "maintenance_health": [_maintenance_row(item) for item in scope["maintenance"]],
    }
    paths: list[Path] = []
    try:
        for label, rows in exports.items():
            path = directory / _report_filename(f"supplyshield_{label}", application, "csv")
            _write_csv(path, rows)
            paths.append(path)
    except OSError as exc:
        LOGGER.exception("Unable to generate CSV exports in %s.", directory)
        raise ReportGenerationError(f"Unable to generate CSV report: {exc}") from exc
    LOGGER.info("Generated %d CSV report exports in %s.", len(paths), directory)
    return tuple(paths)


def generate_reports(
    risk_summary: RiskSummary,
    dependency_risks: Iterable[DependencyRisk],
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
    *,
    application: str | None = None,
    report_directory: str | Path = _DEFAULT_REPORT_DIRECTORY,
    export_directory: str | Path = _DEFAULT_EXPORT_DIRECTORY,
) -> ReportArtifacts:
    """Generate both PDF and CSV audit artifacts for a portfolio or application."""
    dependency_list = list(dependency_risks)
    vulnerability_list = list(vulnerability_findings)
    license_list = list(license_findings)
    maintenance_list = list(maintenance_findings)
    return ReportArtifacts(
        pdf_path=generate_pdf_report(
            risk_summary,
            dependency_list,
            vulnerability_list,
            license_list,
            maintenance_list,
            application=application,
            output_directory=report_directory,
        ),
        csv_paths=generate_csv_reports(
            risk_summary,
            dependency_list,
            vulnerability_list,
            license_list,
            maintenance_list,
            application=application,
            output_directory=export_directory,
        ),
    )


def document_frame(document: BaseDocTemplate) -> Any:
    """Create the printable content frame while reserving a page footer area."""
    from reportlab.platypus import Frame

    return Frame(
        document.leftMargin,
        document.bottomMargin,
        document.width,
        document.height,
        id="content",
    )


def _scope_data(
    risk_summary: RiskSummary,
    dependency_risks: Iterable[DependencyRisk],
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
    application: str | None,
) -> dict[str, list[Any]]:
    """Materialize and optionally restrict all report inputs to one application."""
    target = application.casefold().strip() if application else None

    def in_scope(item: Any) -> bool:
        return target is None or item.application.casefold() == target

    applications = [item for item in risk_summary.applications if in_scope(item)]
    if target is not None and not applications:
        raise ReportGenerationError(f"Application '{application}' is not present in risk results.")
    return {
        "applications": applications,
        "dependencies": [item for item in dependency_risks if in_scope(item)],
        "vulnerabilities": [item for item in vulnerability_findings if in_scope(item)],
        "licenses": [item for item in license_findings if in_scope(item)],
        "maintenance": [item for item in maintenance_findings if in_scope(item)],
    }


def _build_pdf_story(
    scope: dict[str, list[Any]], styles: dict[str, ParagraphStyle], application: str | None
) -> list[Any]:
    """Compose all required audit-report sections into ReportLab flowables."""
    applications: list[ApplicationRisk] = scope["applications"]
    dependencies: list[DependencyRisk] = scope["dependencies"]
    vulnerabilities: list[VulnerabilityMatch] = scope["vulnerabilities"]
    licenses: list[LicenseFinding] = scope["licenses"]
    maintenance: list[MaintenanceFinding] = scope["maintenance"]
    report_type = "Application Audit Report" if application else "Enterprise Portfolio Report"
    created = datetime.now().strftime("%d %b %Y, %H:%M")
    story: list[Any] = [
        Paragraph("SupplyShield", styles["brand"]),
        Paragraph(report_type, styles["title"]),
        Paragraph(f"Generated {created} | Audit-ready software supply chain analysis", styles["subtitle"]),
        Spacer(1, 8 * mm),
        _section("Executive Summary", styles),
        Paragraph(_executive_summary(applications, dependencies), styles["body"]),
        _section("Portfolio Risk Summary", styles),
        _metric_table(applications, dependencies),
        _section("Application Risk Ranking", styles),
        _application_table(applications, styles),
        _section("Critical Vulnerabilities", styles),
        _vulnerability_table(_critical_vulnerabilities(vulnerabilities), styles),
        _section("License Compliance Issues", styles),
        _license_table([item for item in licenses if item.compatibility_status != "Compatible"], styles),
        _section("Maintenance Health", styles),
        _maintenance_table(maintenance, styles),
        PageBreak(),
        _section("Risk Distribution", styles),
        _risk_distribution_table(applications, styles),
        _section("Recommended Remediation", styles),
        *_remediation_paragraphs(applications, vulnerabilities, licenses, maintenance, styles),
    ]
    return story


def _styles() -> dict[str, ParagraphStyle]:
    """Create a compact professional typography system for audit reports."""
    base = getSampleStyleSheet()
    return {
        "brand": ParagraphStyle("Brand", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=23, leading=26, textColor=_DARK, spaceAfter=2),
        "title": ParagraphStyle("Title", parent=base["Heading2"], fontName="Helvetica", fontSize=14, leading=18, textColor=_SLATE, spaceAfter=3),
        "subtitle": ParagraphStyle("Subtitle", parent=base["Normal"], fontSize=8.5, leading=11, textColor=_SLATE),
        "section": ParagraphStyle("Section", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=_DARK, spaceBefore=13, spaceAfter=6),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontSize=9, leading=13, textColor=_SLATE, alignment=TA_LEFT),
        "table": ParagraphStyle("Table", parent=base["BodyText"], fontSize=7.2, leading=9, textColor=_DARK),
        "table_center": ParagraphStyle("TableCenter", parent=base["BodyText"], fontSize=7.2, leading=9, textColor=_DARK, alignment=TA_CENTER),
        "empty": ParagraphStyle("Empty", parent=base["BodyText"], fontSize=8.5, leading=11, textColor=_SLATE, leftIndent=4),
    }


def _section(title: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    """Create a consistently styled report section heading."""
    return Paragraph(title, styles["section"])


def _executive_summary(applications: Sequence[ApplicationRisk], dependencies: Sequence[DependencyRisk]) -> str:
    """Build concise evidence-based narrative for the executive summary section."""
    if not applications:
        return "No in-scope application risk records were provided for this report."
    highest = max(applications, key=lambda item: item.overall_risk_score)
    critical_dependencies = sum(item.final_risk_level == "Critical" for item in dependencies)
    return (
        f"SupplyShield assessed <b>{len(applications)}</b> application(s) and "
        f"<b>{len(dependencies)}</b> dependency instance(s). The highest in-scope risk is "
        f"<b>{escape(highest.application)}</b> at <b>{highest.overall_risk_score:.2f}</b> "
        f"({highest.overall_risk_level}). The scope contains <b>{critical_dependencies}</b> "
        "critical dependency-risk assessment(s)."
    )


def _metric_table(applications: Sequence[ApplicationRisk], dependencies: Sequence[DependencyRisk]) -> Table:
    """Render key portfolio metrics in a compact audit-summary table."""
    highest = max((item.overall_risk_score for item in applications), default=0.0)
    metrics = [
        ["Applications", str(len(applications)), "Dependencies", str(len(dependencies))],
        ["Highest risk", f"{highest:.2f}", "Critical apps", str(sum(item.overall_risk_level == "Critical" for item in applications))],
    ]
    table = Table(metrics, colWidths=[32 * mm, 22 * mm, 32 * mm, 22 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.35, _BORDER),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (-1, -1), _DARK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _application_table(items: Sequence[ApplicationRisk], styles: dict[str, ParagraphStyle]) -> Any:
    """Create the application ranking table with risk-level color coding."""
    rows = [["Rank", "Application", "Dependencies", "Vulnerable", "License issues", "Outdated", "Score", "Level"]]
    for item in items:
        rows.append([
            str(item.rank), _paragraph(item.application, styles["table"]), str(item.total_dependencies),
            str(item.vulnerable_dependencies), str(item.license_issues), str(item.outdated_libraries),
            f"{item.overall_risk_score:.2f}", _risk_paragraph(item.overall_risk_level, styles),
        ])
    return _table_or_empty(rows, [10, 36, 19, 18, 20, 17, 15, 17], styles)


def _vulnerability_table(items: Sequence[VulnerabilityMatch], styles: dict[str, ParagraphStyle]) -> Any:
    """Create a table of critical CVEs, with a clear empty-state when absent."""
    rows = [["Application", "Library", "Version", "CVE", "CVSS", "Severity", "Patch"]]
    for item in items:
        rows.append([
            _paragraph(item.application, styles["table"]), _paragraph(item.library, styles["table"]),
            _paragraph(item.version, styles["table"]), _paragraph(item.cve_id, styles["table"]),
            f"{item.cvss:.1f}", _risk_paragraph(_severity_level(item), styles),
            "Available" if item.patch_available else "Unavailable",
        ])
    return _table_or_empty(rows, [34, 28, 17, 29, 13, 20, 22], styles, "No critical vulnerabilities in scope.")


def _license_table(items: Sequence[LicenseFinding], styles: dict[str, ParagraphStyle]) -> Any:
    """Create a license exception table including decision reason and action."""
    rows = [["Application", "Library", "License", "Status", "Severity", "Recommendation"]]
    for item in items:
        rows.append([
            _paragraph(item.application, styles["table"]), _paragraph(item.library, styles["table"]),
            _paragraph(item.license, styles["table"]), _risk_paragraph(item.compatibility_status, styles),
            _risk_paragraph(item.severity, styles), _paragraph(item.recommendation, styles["table"]),
        ])
    return _table_or_empty(rows, [30, 25, 22, 19, 18, 49], styles, "No license compliance issues in scope.")


def _maintenance_table(items: Sequence[MaintenanceFinding], styles: dict[str, ParagraphStyle]) -> Any:
    """Summarize maintenance evidence by status for the report scope."""
    counts = Counter(item.maintenance_status for item in items)
    rows = [["Maintenance Status", "Dependencies", "Risk Level", "Recommended Action"]]
    recommendations = {
        "Actively Maintained": "Continue monitoring releases and advisories.",
        "Moderately Outdated": "Schedule upgrade review.",
        "Outdated": "Prioritize upgrade or supported replacement.",
        "Unmaintained": "Replace, isolate, or formally approve an exception.",
    }
    for status in ("Actively Maintained", "Moderately Outdated", "Outdated", "Unmaintained"):
        risk = {"Actively Maintained": "Low", "Moderately Outdated": "Medium", "Outdated": "High", "Unmaintained": "Critical"}[status]
        rows.append([status, str(counts.get(status, 0)), _risk_paragraph(risk, styles), recommendations[status]])
    return _table_or_empty(rows, [40, 25, 27, 71], styles)


def _risk_distribution_table(items: Sequence[ApplicationRisk], styles: dict[str, ParagraphStyle]) -> Any:
    """Render the application risk-level distribution as a color-coded table."""
    counts = Counter(item.overall_risk_level for item in items)
    rows = [["Risk Level", "Applications"]]
    for level in ("Critical", "High", "Medium", "Low"):
        rows.append([_risk_paragraph(level, styles), str(counts.get(level, 0))])
    return _table_or_empty(rows, [50, 40], styles)


def _remediation_paragraphs(
    applications: Sequence[ApplicationRisk],
    vulnerabilities: Sequence[VulnerabilityMatch],
    licenses: Sequence[LicenseFinding],
    maintenance: Sequence[MaintenanceFinding],
    styles: dict[str, ParagraphStyle],
) -> list[Paragraph]:
    """Generate evidence-led remediation priorities from supplied findings."""
    critical_vulnerabilities = _critical_vulnerabilities(vulnerabilities)
    license_issues = [item for item in licenses if item.compatibility_status != "Compatible"]
    unmaintained = [item for item in maintenance if item.maintenance_status == "Unmaintained"]
    priorities = [
        f"1. Address <b>{len(critical_vulnerabilities)}</b> critical vulnerability finding(s) first; apply available patches or replace affected components.",
        f"2. Resolve <b>{len(license_issues)}</b> license compliance exception(s) through replacement, legal review, or approved policy exception.",
        f"3. Remediate <b>{len(unmaintained)}</b> unmaintained dependency instance(s) by upgrading, replacing, or isolating them.",
    ]
    if applications:
        highest = max(applications, key=lambda item: item.overall_risk_score)
        priorities.append(
            f"4. Prioritize the highest-risk application, <b>{escape(highest.application)}</b>, in the remediation plan."
        )
    return [Paragraph(priority, styles["body"]) for priority in priorities]


def _table_or_empty(
    rows: list[list[Any]],
    widths_mm: Sequence[float],
    styles: dict[str, ParagraphStyle],
    empty_message: str = "No findings in scope.",
) -> Any:
    """Return a polished table, or a concise empty-state paragraph when no rows exist."""
    if len(rows) == 1:
        return Paragraph(empty_message, styles["empty"])
    table = Table(rows, colWidths=[width * mm for width in widths_mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.2),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.3, _BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _critical_vulnerabilities(items: Sequence[VulnerabilityMatch]) -> list[VulnerabilityMatch]:
    """Select explicit Critical findings and CVSS 9.0+ vulnerabilities for audit review."""
    return [item for item in items if item.severity.casefold() == "critical" or item.cvss >= 9.0]


def _severity_level(item: VulnerabilityMatch) -> str:
    """Use CVSS 9.0+ as Critical where a source severity label is understated."""
    return "Critical" if item.cvss >= 9.0 else item.severity.title()


def _risk_paragraph(value: str, styles: dict[str, ParagraphStyle]) -> Paragraph:
    """Create a risk label with the prescribed color coding when applicable."""
    color = _RISK_COLORS.get(value.title(), _SLATE)
    return Paragraph(f'<font color="#{color.hexval()[2:]}"><b>{escape(value)}</b></font>', styles["table_center"])


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    """Create escaped table text that wraps safely in narrow PDF columns."""
    return Paragraph(escape(str(value)), style)


def _prepare_directory(directory: str | Path) -> Path:
    """Create and return a report destination directory with clear error handling."""
    path = Path(directory)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportGenerationError(f"Unable to create report directory '{path}': {exc}") from exc
    return path


def _report_filename(prefix: str, application: str | None, extension: str) -> str:
    """Build a stable, filesystem-safe timestamped report filename."""
    scope = _safe_name(application) if application else "portfolio"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{scope}_{timestamp}.{extension}"


def _safe_name(value: str | None) -> str:
    """Normalize user-provided application names for safe report filenames."""
    return re.sub(r"[^a-z0-9]+", "_", (value or "application").casefold()).strip("_") or "application"


def _write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    """Write a UTF-8 BOM CSV with a useful header even when scope has no rows."""
    headers = list(rows[0]) if rows else ["status"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        if rows:
            writer.writerows(rows)
        else:
            writer.writerow({"status": "No findings in scope"})


def _application_row(item: ApplicationRisk) -> dict[str, Any]:
    """Flatten application risk for CSV export."""
    return item.as_dict()


def _dependency_row(item: DependencyRisk) -> dict[str, Any]:
    """Flatten dependency risk and four component explanations for CSV export."""
    return {
        "application": item.application,
        "dependency_id": item.dependency_id,
        "library": item.library,
        "version": item.version,
        "vulnerability_score": item.vulnerability_score,
        "license_score": item.license_score,
        "maintenance_score": item.maintenance_score,
        "dependency_depth_score": item.dependency_depth_score,
        "final_risk_score": item.final_risk_score,
        "final_risk_level": item.final_risk_level,
        "explanation": item.explanation,
    }


def _vulnerability_row(item: VulnerabilityMatch) -> dict[str, Any]:
    """Flatten a vulnerability finding for CSV export."""
    return asdict(item)


def _license_row(item: LicenseFinding) -> dict[str, Any]:
    """Flatten a license finding for CSV export."""
    return item.as_dict()


def _maintenance_row(item: MaintenanceFinding) -> dict[str, Any]:
    """Flatten a maintenance finding for CSV export."""
    return item.as_dict()
