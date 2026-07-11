"""License compatibility analysis for parsed SBOM dependency records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pandas as pd

LOGGER = logging.getLogger(__name__)

_DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "license_rules.json"
_DEFAULT_POLICY = "Proprietary"
_DEPENDENCY_COLUMNS = frozenset({"application", "library", "version", "license"})
_RULE_FIELDS = frozenset({"license", "compatible_with", "risk_level", "commercial_use"})
_UNKNOWN_LICENSES = frozenset({"unknown", "no-license"})

__all__ = [
    "LicenseDataError",
    "LicenseFinding",
    "LicenseSummary",
    "load_license_rules",
    "check_licenses",
    "filter_license_findings",
    "summarize_licenses",
]


class LicenseDataError(ValueError):
    """Raised when license policy data is unavailable or structurally invalid."""


@dataclass(frozen=True, slots=True)
class LicenseFinding:
    """Compatibility result for a single application dependency license."""

    application: str
    library: str
    version: str
    license: str
    compatibility_status: str
    severity: str
    reason: str
    recommendation: str

    def as_dict(self) -> dict[str, str]:
        """Return a presentation-ready representation of the finding."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LicenseSummary:
    """Aggregate license compatibility metrics for a collection of findings."""

    total_libraries: int
    compatible: int
    incompatible: int
    unknown: int
    missing: int

    def as_dict(self) -> dict[str, int]:
        """Return summary values with stable dashboard field names."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _LicenseRule:
    """Internal normalized representation of one license matrix row."""

    license: str
    compatible_with: tuple[str, ...]
    risk_level: str
    commercial_use: bool


@dataclass(frozen=True, slots=True)
class _ApplicationPolicy:
    """Internal normalized application license policy and applicable constraints."""

    license: str
    constraints: frozenset[str]


def load_license_rules(
    rules_path: str | Path = _DEFAULT_RULES_PATH,
) -> dict[str, _LicenseRule]:
    """Load the license compatibility matrix from its JSON policy file.

    The returned mapping is keyed case-insensitively by SPDX-style license name.

    Raises:
        LicenseDataError: If the JSON file cannot be read or contains an invalid
            license policy record.
    """
    path = Path(rules_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LicenseDataError(f"License rules file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise LicenseDataError(f"Unable to read license rules: {exc}") from exc
    if not isinstance(payload, list):
        raise LicenseDataError("License rules must contain a JSON array.")

    rules: dict[str, _LicenseRule] = {}
    for index, record in enumerate(payload):
        rule = _to_license_rule(record, index)
        key = rule.license.casefold()
        if key in rules:
            raise LicenseDataError(f"Duplicate license rule for '{rule.license}'.")
        rules[key] = rule
    LOGGER.info("Loaded %d license compatibility rules from %s.", len(rules), path)
    return rules


def check_licenses(
    dependencies: pd.DataFrame,
    application_policies: Mapping[str, str | Mapping[str, Any]] | None = None,
    rules_path: str | Path = _DEFAULT_RULES_PATH,
) -> list[LicenseFinding]:
    """Evaluate every dependency license against its application's license policy.

    Args:
        dependencies: Parsed dependency records containing application, library,
            version, and license columns.
        application_policies: Optional mapping by application name. A value can
            be a license string or a mapping with ``license`` and optional
            ``constraints`` (for example ``{"license": "Proprietary",
            "constraints": ["Dynamic Linking"]}``). Applications without an
            explicit policy use the conservative ``Proprietary`` default.
        rules_path: Path to the license compatibility matrix JSON file.
    """
    _validate_dependencies(dependencies)
    rules = load_license_rules(rules_path)
    policies = _normalize_policies(application_policies)
    findings = [
        _evaluate_dependency(row, rules, policies)
        for row in dependencies.to_dict(orient="records")
    ]
    LOGGER.info("Produced %d license compatibility findings.", len(findings))
    return findings


def filter_license_findings(
    findings: Iterable[LicenseFinding],
    *,
    application: str | None = None,
    license_name: str | None = None,
    compatibility: str | None = None,
) -> list[LicenseFinding]:
    """Filter license findings by application, license, or compatibility status."""
    application_query = application.casefold().strip() if application else None
    license_query = license_name.casefold().strip() if license_name else None
    compatibility_query = compatibility.casefold().strip() if compatibility else None
    return [
        finding
        for finding in findings
        if (application_query is None or application_query in finding.application.casefold())
        and (license_query is None or license_query in finding.license.casefold())
        and (
            compatibility_query is None
            or compatibility_query == finding.compatibility_status.casefold()
        )
    ]


def summarize_licenses(findings: Iterable[LicenseFinding]) -> LicenseSummary:
    """Calculate total, compatible, incompatible, unknown, and missing counts."""
    findings_list = list(findings)
    status_counts = {
        status: sum(finding.compatibility_status == status for finding in findings_list)
        for status in ("Compatible", "Incompatible", "Unknown", "Missing")
    }
    return LicenseSummary(
        total_libraries=len(findings_list),
        compatible=status_counts["Compatible"],
        incompatible=status_counts["Incompatible"],
        unknown=status_counts["Unknown"],
        missing=status_counts["Missing"],
    )


def _to_license_rule(record: Any, index: int) -> _LicenseRule:
    """Validate and normalize one JSON license-rule record."""
    if not isinstance(record, Mapping):
        raise LicenseDataError(f"License rule {index} must be a JSON object.")
    missing_fields = _RULE_FIELDS.difference(record)
    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise LicenseDataError(f"License rule {index} is missing fields: {missing}.")
    license_name = _text(record["license"])
    risk_level = _text(record["risk_level"])
    if not license_name or not risk_level:
        raise LicenseDataError(f"License rule {index} has an empty license or risk_level.")
    if not isinstance(record["commercial_use"], bool):
        raise LicenseDataError(f"License rule {index} commercial_use must be boolean.")
    compatible_with = _compatibility_terms(record["compatible_with"], index)
    return _LicenseRule(
        license=license_name,
        compatible_with=compatible_with,
        risk_level=risk_level,
        commercial_use=record["commercial_use"],
    )


def _compatibility_terms(value: Any, index: int) -> tuple[str, ...]:
    """Convert matrix compatibility fields to normalized policy terms."""
    if isinstance(value, str):
        return tuple(term.strip() for term in value.split(",") if term.strip())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if all(isinstance(term, str) and term.strip() for term in value):
            return tuple(term.strip() for term in value)
    raise LicenseDataError(
        f"License rule {index} compatible_with must be a string or string list."
    )


def _normalize_policies(
    policies: Mapping[str, str | Mapping[str, Any]] | None,
) -> dict[str, _ApplicationPolicy]:
    """Normalize optional caller-supplied application license policy data."""
    if policies is None:
        return {}
    if not isinstance(policies, Mapping):
        raise TypeError("application_policies must be a mapping when provided.")
    normalized: dict[str, _ApplicationPolicy] = {}
    for application, raw_policy in policies.items():
        application_name = _text(application)
        if not application_name:
            raise LicenseDataError("Application policy names cannot be empty.")
        normalized[application_name.casefold()] = _to_application_policy(raw_policy, application_name)
    return normalized


def _to_application_policy(raw_policy: str | Mapping[str, Any], application: str) -> _ApplicationPolicy:
    """Validate one flexible application policy value."""
    if isinstance(raw_policy, str):
        license_name = _text(raw_policy)
        constraints: frozenset[str] = frozenset()
    elif isinstance(raw_policy, Mapping):
        license_name = _text(raw_policy.get("license"))
        raw_constraints = raw_policy.get("constraints", ())
        if isinstance(raw_constraints, str):
            raw_constraints = (raw_constraints,)
        if not isinstance(raw_constraints, Sequence) or isinstance(
            raw_constraints, (str, bytes)
        ):
            raise LicenseDataError(f"Policy constraints for '{application}' must be a string list.")
        if not all(isinstance(value, str) and value.strip() for value in raw_constraints):
            raise LicenseDataError(f"Policy constraints for '{application}' contain invalid values.")
        constraints = frozenset(value.strip().casefold() for value in raw_constraints)
    else:
        raise LicenseDataError(f"Policy for '{application}' must be a string or mapping.")
    if not license_name:
        raise LicenseDataError(f"Policy license for '{application}' cannot be empty.")
    return _ApplicationPolicy(license=license_name, constraints=constraints)


def _evaluate_dependency(
    row: Mapping[str, Any],
    rules: Mapping[str, _LicenseRule],
    policies: Mapping[str, _ApplicationPolicy],
) -> LicenseFinding:
    """Create one license finding using the matrix and application policy."""
    application = _text(row["application"])
    library = _text(row["library"])
    version = _text(row["version"])
    license_name = _text(row["license"])
    if not license_name:
        return _finding(
            application, library, version, "Missing", "Missing", "High",
            "The dependency does not declare a license.",
            "Obtain the license from the supplier before approving this dependency.",
        )
    rule = rules.get(license_name.casefold())
    if rule is None or rule.license.casefold() in _UNKNOWN_LICENSES:
        return _finding(
            application, library, version, license_name, "Unknown", "High",
            "The dependency license is unknown or has no verified license grant.",
            "Obtain a verified SPDX license declaration or replace the dependency.",
        )
    policy = policies.get(
        application.casefold(), _ApplicationPolicy(_DEFAULT_POLICY, frozenset())
    )
    if _is_compatible(rule, policy):
        return _finding(
            application, library, version, license_name, "Compatible", "Low",
            f"{license_name} is permitted by the {policy.license} application policy.",
            "Retain license notices and reassess on dependency or policy changes.",
        )
    return _finding(
        application, library, version, license_name, "Incompatible", rule.risk_level,
        f"{license_name} is not compatible with the {policy.license} application policy.",
        "Replace the dependency, obtain an approved exception, or change the application policy.",
    )


def _is_compatible(rule: _LicenseRule, policy: _ApplicationPolicy) -> bool:
    """Determine whether policy license or constraints satisfy a matrix rule."""
    terms = {term.casefold() for term in rule.compatible_with}
    if "*" in terms:
        return True
    policy_license = policy.license.casefold()
    if policy_license in terms:
        return True
    if "gpl" in terms and policy_license.startswith("gpl"):
        return True
    return bool(terms.intersection(policy.constraints))


def _finding(
    application: str,
    library: str,
    version: str,
    license_name: str,
    compatibility_status: str,
    severity: str,
    reason: str,
    recommendation: str,
) -> LicenseFinding:
    """Build a typed result while keeping decision branches concise."""
    return LicenseFinding(
        application=application,
        library=library,
        version=version,
        license=license_name,
        compatibility_status=compatibility_status,
        severity=severity,
        reason=reason,
        recommendation=recommendation,
    )


def _validate_dependencies(dependencies: pd.DataFrame) -> None:
    """Validate the minimal dependency dataframe schema required for analysis."""
    if not isinstance(dependencies, pd.DataFrame):
        raise TypeError("dependencies must be a pandas DataFrame.")
    missing_columns = _DEPENDENCY_COLUMNS.difference(dependencies.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Dependencies are missing required columns: {missing}.")


def _text(value: Any) -> str:
    """Convert a scalar value to text, representing nulls as an empty string."""
    if value is None or (not isinstance(value, (list, dict)) and pd.isna(value)):
        return ""
    return str(value).strip()
