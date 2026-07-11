"""Dependency maintenance-health analysis based on SBOM update timestamps."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date, datetime
import logging
from typing import Any, Iterable

import pandas as pd

LOGGER = logging.getLogger(__name__)

_REQUIRED_COLUMNS = frozenset({"application", "library", "version", "last_updated"})
_STATUS_RISKS = {
    "Actively Maintained": "Low",
    "Moderately Outdated": "Medium",
    "Outdated": "High",
    "Unmaintained": "Critical",
}

__all__ = [
    "MaintenanceDataError",
    "MaintenanceThresholds",
    "MaintenanceFinding",
    "MaintenanceSummary",
    "analyze_maintenance",
    "filter_maintenance_findings",
    "summarize_maintenance",
]


class MaintenanceDataError(ValueError):
    """Raised when maintenance input data or configuration is invalid."""


@dataclass(frozen=True, slots=True)
class MaintenanceThresholds:
    """Configurable maximum ages in days for maintenance status boundaries.

    A dependency older than ``outdated_max_days`` is classified as
    ``Unmaintained``. Thresholds must be non-negative and ordered from most to
    least recent.
    """

    actively_maintained_max_days: int = 365
    moderately_outdated_max_days: int = 730
    outdated_max_days: int = 1095

    def __post_init__(self) -> None:
        """Validate ordering and range invariants for status boundaries."""
        values = (
            self.actively_maintained_max_days,
            self.moderately_outdated_max_days,
            self.outdated_max_days,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            raise MaintenanceDataError("Maintenance thresholds must be integer day counts.")
        if any(value < 0 for value in values):
            raise MaintenanceDataError("Maintenance thresholds cannot be negative.")
        if values != tuple(sorted(values)):
            raise MaintenanceDataError("Maintenance thresholds must be in ascending order.")


@dataclass(frozen=True, slots=True)
class MaintenanceFinding:
    """Maintenance health assessment for one dependency instance."""

    application: str
    library: str
    version: str
    last_updated: date | None
    age_days: int | None
    age_months: float | None
    age_years: float | None
    maintenance_status: str
    risk_level: str
    recommendation: str

    def as_dict(self) -> dict[str, Any]:
        """Serialize the assessment for dashboard and report consumers."""
        data = asdict(self)
        data["last_updated"] = self.last_updated.isoformat() if self.last_updated else None
        return data


@dataclass(frozen=True, slots=True)
class MaintenanceSummary:
    """Aggregate counts for maintenance status across dependency findings."""

    total_dependencies: int
    actively_maintained: int
    moderately_outdated: int
    outdated: int
    unmaintained: int

    def as_dict(self) -> dict[str, int]:
        """Return summary values in dashboard-ready form."""
        return asdict(self)


def analyze_maintenance(
    dependencies: pd.DataFrame,
    thresholds: MaintenanceThresholds | None = None,
    as_of: date | datetime | pd.Timestamp | None = None,
) -> list[MaintenanceFinding]:
    """Assess maintenance status for every dependency in a parsed SBOM.

    Missing or invalid ``last_updated`` values are retained as ``Unmaintained``
    findings instead of causing partial results.  This makes absence of
    lifecycle evidence visible as a high-priority supply-chain risk.

    Args:
        dependencies: Dependency dataframe containing the required SBOM fields.
        thresholds: Optional status-age configuration.
        as_of: Reference date for deterministic analysis. Defaults to today.
    """
    _validate_dependencies(dependencies)
    configuration = thresholds or MaintenanceThresholds()
    reference_date = _normalize_reference_date(as_of)
    findings = [
        _analyze_row(row, configuration, reference_date)
        for row in dependencies.to_dict(orient="records")
    ]
    LOGGER.info(
        "Analyzed maintenance health for %d dependencies as of %s.",
        len(findings),
        reference_date.isoformat(),
    )
    return findings


def filter_maintenance_findings(
    findings: Iterable[MaintenanceFinding],
    *,
    application: str | None = None,
    maintenance_status: str | None = None,
    risk_level: str | None = None,
) -> list[MaintenanceFinding]:
    """Filter maintenance findings by application, status, and risk level."""
    application_query = application.casefold().strip() if application else None
    status_query = maintenance_status.casefold().strip() if maintenance_status else None
    risk_query = risk_level.casefold().strip() if risk_level else None
    return [
        finding
        for finding in findings
        if (application_query is None or application_query in finding.application.casefold())
        and (
            status_query is None
            or status_query == finding.maintenance_status.casefold()
        )
        and (risk_query is None or risk_query == finding.risk_level.casefold())
    ]


def summarize_maintenance(findings: Iterable[MaintenanceFinding]) -> MaintenanceSummary:
    """Calculate total and maintenance-status counts for provided findings."""
    findings_list = list(findings)
    status_counts = {
        status: sum(finding.maintenance_status == status for finding in findings_list)
        for status in _STATUS_RISKS
    }
    return MaintenanceSummary(
        total_dependencies=len(findings_list),
        actively_maintained=status_counts["Actively Maintained"],
        moderately_outdated=status_counts["Moderately Outdated"],
        outdated=status_counts["Outdated"],
        unmaintained=status_counts["Unmaintained"],
    )


def _analyze_row(
    row: dict[str, Any],
    thresholds: MaintenanceThresholds,
    reference_date: date,
) -> MaintenanceFinding:
    """Evaluate one dependency record without mutating source data."""
    application = _text(row["application"])
    library = _text(row["library"])
    version = _text(row["version"])
    updated_date = _parse_last_updated(row["last_updated"], application, library)
    if updated_date is None:
        return _finding(
            application=application,
            library=library,
            version=version,
            last_updated=None,
            age_days=None,
            status="Unmaintained",
            recommendation="Obtain a verified release-maintenance date or replace the dependency.",
        )

    age_days = max(0, (reference_date - updated_date).days)
    status = _maintenance_status(age_days, thresholds)
    return _finding(
        application=application,
        library=library,
        version=version,
        last_updated=updated_date,
        age_days=age_days,
        status=status,
        recommendation=_recommendation(status),
    )


def _finding(
    *,
    application: str,
    library: str,
    version: str,
    last_updated: date | None,
    age_days: int | None,
    status: str,
    recommendation: str,
) -> MaintenanceFinding:
    """Build a maintenance finding and derive uniform age/risk attributes."""
    return MaintenanceFinding(
        application=application,
        library=library,
        version=version,
        last_updated=last_updated,
        age_days=age_days,
        age_months=round(age_days / 30.4375, 1) if age_days is not None else None,
        age_years=round(age_days / 365.2425, 2) if age_days is not None else None,
        maintenance_status=status,
        risk_level=_STATUS_RISKS[status],
        recommendation=recommendation,
    )


def _maintenance_status(age_days: int, thresholds: MaintenanceThresholds) -> str:
    """Classify an age using the supplied, ordered threshold configuration."""
    if age_days <= thresholds.actively_maintained_max_days:
        return "Actively Maintained"
    if age_days <= thresholds.moderately_outdated_max_days:
        return "Moderately Outdated"
    if age_days <= thresholds.outdated_max_days:
        return "Outdated"
    return "Unmaintained"


def _recommendation(status: str) -> str:
    """Return the remediation action appropriate for a maintenance category."""
    recommendations = {
        "Actively Maintained": "Continue monitoring releases and security advisories.",
        "Moderately Outdated": "Plan an upgrade review and confirm active upstream support.",
        "Outdated": "Prioritize an upgrade or identify a supported replacement.",
        "Unmaintained": "Replace or isolate the dependency and obtain an approved exception.",
    }
    return recommendations[status]


def _parse_last_updated(value: Any, application: str, library: str) -> date | None:
    """Convert one update value to a date, logging invalid lifecycle evidence."""
    if value is None or pd.isna(value) or (isinstance(value, str) and not value.strip()):
        LOGGER.warning("Missing last_updated value for %s / %s.", application, library)
        return None
    converted = pd.to_datetime(value, errors="coerce")
    if pd.isna(converted):
        LOGGER.warning("Invalid last_updated value for %s / %s: %r.", application, library, value)
        return None
    return converted.date()


def _normalize_reference_date(value: date | datetime | pd.Timestamp | None) -> date:
    """Normalize optional caller reference time to a date used in age calculations."""
    if value is None:
        return date.today()
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            raise MaintenanceDataError("as_of must be a valid date.")
        return value.date()
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    raise MaintenanceDataError("as_of must be a date, datetime, pandas Timestamp, or None.")


def _validate_dependencies(dependencies: pd.DataFrame) -> None:
    """Validate the minimum dataframe contract required for maintenance analysis."""
    if not isinstance(dependencies, pd.DataFrame):
        raise TypeError("dependencies must be a pandas DataFrame.")
    missing_columns = _REQUIRED_COLUMNS.difference(dependencies.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise MaintenanceDataError(f"Dependencies are missing required columns: {missing}.")


def _text(value: Any) -> str:
    """Normalize an SBOM scalar to a safe display string."""
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()
