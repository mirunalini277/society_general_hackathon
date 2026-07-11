"""Transparent software supply-chain risk scoring services.

Scores use only the four required assessment components: vulnerability
severity, dependency depth, license compatibility, and maintenance status.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
from statistics import fmean
from typing import Any, Iterable, Mapping, Sequence, TypeVar

import pandas as pd

from .license_checker import LicenseFinding
from .maintenance_checker import MaintenanceFinding
from .vulnerability_checker import VulnerabilityMatch

LOGGER = logging.getLogger(__name__)

_REQUIRED_COLUMNS = frozenset(
    {"application", "dependency_id", "library", "version", "dependency_type"}
)
_LICENSE_SCORES = {
    "Compatible": 0.0,
    "Unknown": 75.0,
    "Missing": 100.0,
    "Incompatible": 100.0,
}
_MAINTENANCE_SCORES = {
    "Actively Maintained": 0.0,
    "Moderately Outdated": 40.0,
    "Outdated": 70.0,
    "Unmaintained": 100.0,
}
_DEPTH_SCORES = {"Direct": 25.0, "Transitive": 50.0}
_Finding = TypeVar("_Finding", LicenseFinding, MaintenanceFinding)

__all__ = [
    "RiskDataError",
    "RiskWeights",
    "RiskComponent",
    "DependencyRisk",
    "ApplicationRisk",
    "RiskSummary",
    "calculate_dependency_risks",
    "calculate_application_risks",
    "build_risk_summary",
    "analyze_risk",
    "filter_dependency_risks",
    "filter_application_risks",
]


class RiskDataError(ValueError):
    """Raised when risk-analysis inputs do not meet the required contract."""


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """Transparent weights for the four mandated risk components.

    The defaults prioritize exploitable vulnerability severity (45%), followed
    by license compatibility (25%), maintenance status (20%), and dependency
    depth (10%). Weights must sum to one so scores remain on a 0–100 scale.
    """

    vulnerability: float = 0.45
    license: float = 0.25
    maintenance: float = 0.20
    dependency_depth: float = 0.10

    def __post_init__(self) -> None:
        """Enforce a valid, transparent weighting configuration."""
        values = (
            self.vulnerability,
            self.license,
            self.maintenance,
            self.dependency_depth,
        )
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) for value in values):
            raise RiskDataError("Risk weights must be numeric.")
        if any(value < 0 for value in values):
            raise RiskDataError("Risk weights cannot be negative.")
        if abs(sum(values) - 1.0) > 1e-9:
            raise RiskDataError("Risk weights must sum to 1.0.")


@dataclass(frozen=True, slots=True)
class RiskComponent:
    """One transparent component of a dependency risk score."""

    name: str
    score: float
    weight: float
    weighted_score: float
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the component."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DependencyRisk:
    """Complete four-component risk evaluation for one dependency instance."""

    application: str
    dependency_id: str
    library: str
    version: str
    vulnerability_score: float
    license_score: float
    maintenance_score: float
    dependency_depth_score: float
    final_risk_score: float
    final_risk_level: str
    components: tuple[RiskComponent, ...]
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of the dependency assessment."""
        data = asdict(self)
        data["components"] = [component.as_dict() for component in self.components]
        return data


@dataclass(frozen=True, slots=True)
class ApplicationRisk:
    """Aggregated dependency risk assessment for one application."""

    application: str
    total_dependencies: int
    vulnerable_dependencies: int
    license_issues: int
    outdated_libraries: int
    overall_risk_score: float
    overall_risk_level: str
    rank: int
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of application risk."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RiskSummary:
    """Portfolio-level application risk summary and ordered ranking."""

    highest_risk_application: str | None
    average_risk: float
    critical_applications: int
    high_applications: int
    medium_applications: int
    low_applications: int
    applications: tuple[ApplicationRisk, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of portfolio risk."""
        data = asdict(self)
        data["applications"] = [application.as_dict() for application in self.applications]
        return data


def calculate_dependency_risks(
    dependencies: pd.DataFrame,
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
    weights: RiskWeights | None = None,
) -> list[DependencyRisk]:
    """Calculate transparent risk scores for all dependency rows.

    The function consumes the typed outputs from the vulnerability, license,
    and maintenance checker modules.  The vulnerability component is the
    highest CVSS observed for the dependency, scaled from CVSS 0–10 to 0–100.
    """
    _validate_dependencies(dependencies)
    configuration = weights or RiskWeights()
    vulnerabilities = _vulnerability_index(vulnerability_findings)
    licenses = _finding_index(license_findings)
    maintenance = _finding_index(maintenance_findings)

    risks = [
        _score_dependency(row, vulnerabilities, licenses, maintenance, configuration)
        for row in dependencies.to_dict(orient="records")
    ]
    LOGGER.info("Calculated risk scores for %d dependencies.", len(risks))
    return risks


def calculate_application_risks(
    dependency_risks: Iterable[DependencyRisk],
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
) -> list[ApplicationRisk]:
    """Aggregate dependency scores into ranked application risk assessments.

    An application score is the arithmetic mean of its dependency final scores.
    This preserves the 0–100 scoring scale and does not introduce extra risk
    factors beyond those already present in dependency scores.
    """
    risks = list(dependency_risks)
    risks_by_application: dict[str, list[DependencyRisk]] = {}
    for risk in risks:
        risks_by_application.setdefault(risk.application, []).append(risk)
    vulnerability_keys = {
        _dependency_key(finding.application, finding.library, finding.version)
        for finding in vulnerability_findings
    }
    license_issues = _issue_keys(license_findings)
    outdated_keys = {
        _dependency_key(finding.application, finding.library, finding.version)
        for finding in maintenance_findings
        if finding.maintenance_status in {"Outdated", "Unmaintained"}
    }

    unranked = [
        _score_application(application, items, vulnerability_keys, license_issues, outdated_keys)
        for application, items in risks_by_application.items()
    ]
    ordered = sorted(
        unranked,
        key=lambda assessment: (-assessment.overall_risk_score, assessment.application.casefold()),
    )
    return [
        ApplicationRisk(
            **{
                **assessment.as_dict(),
                "rank": index,
            }
        )
        for index, assessment in enumerate(ordered, start=1)
    ]


def build_risk_summary(applications: Iterable[ApplicationRisk]) -> RiskSummary:
    """Build portfolio-level metrics from ranked application risk assessments."""
    application_list = tuple(applications)
    levels = {
        level: sum(item.overall_risk_level == level for item in application_list)
        for level in ("Critical", "High", "Medium", "Low")
    }
    return RiskSummary(
        highest_risk_application=application_list[0].application if application_list else None,
        average_risk=round(fmean(item.overall_risk_score for item in application_list), 2)
        if application_list
        else 0.0,
        critical_applications=levels["Critical"],
        high_applications=levels["High"],
        medium_applications=levels["Medium"],
        low_applications=levels["Low"],
        applications=application_list,
    )


def analyze_risk(
    dependencies: pd.DataFrame,
    vulnerability_findings: Iterable[VulnerabilityMatch],
    license_findings: Iterable[LicenseFinding],
    maintenance_findings: Iterable[MaintenanceFinding],
    weights: RiskWeights | None = None,
) -> tuple[list[DependencyRisk], RiskSummary]:
    """Calculate dependency risks, application rankings, and portfolio summary."""
    vulnerability_list = list(vulnerability_findings)
    license_list = list(license_findings)
    maintenance_list = list(maintenance_findings)
    dependency_risks = calculate_dependency_risks(
        dependencies,
        vulnerability_list,
        license_list,
        maintenance_list,
        weights,
    )
    applications = calculate_application_risks(
        dependency_risks,
        vulnerability_list,
        license_list,
        maintenance_list,
    )
    summary = build_risk_summary(applications)
    LOGGER.info(
        "Calculated portfolio risk for %d applications; highest risk: %s.",
        len(applications),
        summary.highest_risk_application,
    )
    return dependency_risks, summary


def filter_dependency_risks(
    risks: Iterable[DependencyRisk],
    *,
    application: str | None = None,
    risk_level: str | None = None,
) -> list[DependencyRisk]:
    """Filter dependency assessments by application name and final risk level."""
    application_query = application.casefold().strip() if application else None
    level_query = risk_level.casefold().strip() if risk_level else None
    return [
        risk
        for risk in risks
        if (application_query is None or application_query in risk.application.casefold())
        and (level_query is None or level_query == risk.final_risk_level.casefold())
    ]


def filter_application_risks(
    risks: Iterable[ApplicationRisk], *, risk_level: str | None = None
) -> list[ApplicationRisk]:
    """Filter application assessments by their final overall risk level."""
    level_query = risk_level.casefold().strip() if risk_level else None
    return [
        risk
        for risk in risks
        if level_query is None or level_query == risk.overall_risk_level.casefold()
    ]


def _score_dependency(
    row: Mapping[str, Any],
    vulnerabilities: Mapping[tuple[str, str, str], Sequence[VulnerabilityMatch]],
    licenses: Mapping[tuple[str, str, str], LicenseFinding],
    maintenance: Mapping[tuple[str, str, str], MaintenanceFinding],
    weights: RiskWeights,
) -> DependencyRisk:
    """Calculate the four required score components for one dependency row."""
    application = _text(row["application"])
    library = _text(row["library"])
    version = _text(row["version"])
    key = _dependency_key(application, library, version)
    vulnerability_component = _vulnerability_component(vulnerabilities.get(key, ()), weights)
    license_component = _license_component(licenses.get(key), weights)
    maintenance_component = _maintenance_component(maintenance.get(key), weights)
    depth_component = _depth_component(_text(row["dependency_type"]), weights)
    components = (
        vulnerability_component,
        license_component,
        maintenance_component,
        depth_component,
    )
    final_score = round(sum(component.weighted_score for component in components), 2)
    level = _risk_level(final_score)
    return DependencyRisk(
        application=application,
        dependency_id=_text(row["dependency_id"]),
        library=library,
        version=version,
        vulnerability_score=vulnerability_component.score,
        license_score=license_component.score,
        maintenance_score=maintenance_component.score,
        dependency_depth_score=depth_component.score,
        final_risk_score=final_score,
        final_risk_level=level,
        components=components,
        explanation=" ".join(component.explanation for component in components),
    )


def _vulnerability_component(
    findings: Sequence[VulnerabilityMatch], weights: RiskWeights
) -> RiskComponent:
    """Score maximum dependency CVSS on the required 0–100 component scale."""
    if not findings:
        return _component(
            "Vulnerability Severity", 0.0, weights.vulnerability,
            "No matched vulnerabilities; vulnerability severity score is 0.",
        )
    highest = max(finding.cvss for finding in findings)
    return _component(
        "Vulnerability Severity", round(highest * 10, 2), weights.vulnerability,
        f"Highest matched CVSS is {highest:.1f}; vulnerability severity score is {highest * 10:.1f}.",
    )


def _license_component(finding: LicenseFinding | None, weights: RiskWeights) -> RiskComponent:
    """Score the checker-provided license compatibility classification."""
    status = finding.compatibility_status if finding else "Unknown"
    score = _LICENSE_SCORES.get(status, _LICENSE_SCORES["Unknown"])
    reason = finding.reason if finding else "No license analysis finding was supplied."
    return _component(
        "License Compatibility", score, weights.license,
        f"License status is {status}; license score is {score:.0f}. {reason}",
    )


def _maintenance_component(
    finding: MaintenanceFinding | None, weights: RiskWeights
) -> RiskComponent:
    """Score the checker-provided dependency maintenance status."""
    status = finding.maintenance_status if finding else "Unmaintained"
    score = _MAINTENANCE_SCORES.get(status, _MAINTENANCE_SCORES["Unmaintained"])
    return _component(
        "Maintenance Status", score, weights.maintenance,
        f"Maintenance status is {status}; maintenance score is {score:.0f}.",
    )


def _depth_component(dependency_type: str, weights: RiskWeights) -> RiskComponent:
    """Score direct versus transitive dependency depth without other graph factors."""
    normalized_type = dependency_type.title()
    score = _DEPTH_SCORES.get(normalized_type, _DEPTH_SCORES["Transitive"])
    description = normalized_type if normalized_type in _DEPTH_SCORES else "Unknown (treated as Transitive)"
    return _component(
        "Dependency Depth", score, weights.dependency_depth,
        f"Dependency is {description}; dependency depth score is {score:.0f}.",
    )


def _component(name: str, score: float, weight: float, explanation: str) -> RiskComponent:
    """Construct a uniformly rounded weighted risk component."""
    return RiskComponent(
        name=name,
        score=round(score, 2),
        weight=weight,
        weighted_score=round(score * weight, 2),
        explanation=explanation,
    )


def _score_application(
    application: str,
    risks: Sequence[DependencyRisk],
    vulnerability_keys: set[tuple[str, str, str]],
    license_issue_keys: set[tuple[str, str, str]],
    outdated_keys: set[tuple[str, str, str]],
) -> ApplicationRisk:
    """Aggregate dependency-level values into one unranked application result."""
    score = round(fmean(item.final_risk_score for item in risks), 2)
    level = _risk_level(score)
    return ApplicationRisk(
        application=application,
        total_dependencies=len(risks),
        vulnerable_dependencies=sum(
            _dependency_key(item.application, item.library, item.version) in vulnerability_keys
            for item in risks
        ),
        license_issues=sum(
            _dependency_key(item.application, item.library, item.version) in license_issue_keys
            for item in risks
        ),
        outdated_libraries=sum(
            _dependency_key(item.application, item.library, item.version) in outdated_keys
            for item in risks
        ),
        overall_risk_score=score,
        overall_risk_level=level,
        rank=0,
        explanation=(
            f"Overall score is the average of {len(risks)} dependency risk scores "
            f"({score:.2f}), resulting in a {level} risk level."
        ),
    )


def _risk_level(score: float) -> str:
    """Map transparent 0–100 scores to the required four risk levels."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _vulnerability_index(
    findings: Iterable[VulnerabilityMatch],
) -> dict[tuple[str, str, str], list[VulnerabilityMatch]]:
    """Group vulnerability findings by dependency identity for highest-CVSS lookup."""
    index: dict[tuple[str, str, str], list[VulnerabilityMatch]] = {}
    for finding in findings:
        index.setdefault(
            _dependency_key(finding.application, finding.library, finding.version), []
        ).append(finding)
    return index


def _finding_index(
    findings: Iterable[_Finding],
) -> dict[tuple[str, str, str], _Finding]:
    """Index license or maintenance findings by application/library/version."""
    index: dict[tuple[str, str, str], LicenseFinding | MaintenanceFinding] = {}
    for finding in findings:
        index[_dependency_key(finding.application, finding.library, finding.version)] = finding
    return index


def _issue_keys(findings: Iterable[LicenseFinding]) -> set[tuple[str, str, str]]:
    """Return dependency identities with a non-compatible license outcome."""
    return {
        _dependency_key(finding.application, finding.library, finding.version)
        for finding in findings
        if finding.compatibility_status in {"Incompatible", "Unknown", "Missing"}
    }


def _dependency_key(application: str, library: str, version: str) -> tuple[str, str, str]:
    """Create the shared dependency identity used by all checker outputs."""
    return application.casefold(), library.casefold(), version.casefold()


def _validate_dependencies(dependencies: pd.DataFrame) -> None:
    """Validate the minimal dataframe schema required for risk calculation."""
    if not isinstance(dependencies, pd.DataFrame):
        raise TypeError("dependencies must be a pandas DataFrame.")
    missing_columns = _REQUIRED_COLUMNS.difference(dependencies.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise RiskDataError(f"Dependencies are missing required columns: {missing}.")


def _text(value: Any) -> str:
    """Normalize scalar dataframe values to stable non-null strings."""
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()
