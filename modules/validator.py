"""Validation services for parsed Software Bill of Materials datasets.

This module validates dataset structure and data quality only.  It does not
parse source files, modify input data, build graphs, or calculate risk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any, Hashable, Mapping, Sequence

import pandas as pd
from pandas.api.types import is_bool_dtype, is_datetime64_any_dtype

LOGGER = logging.getLogger(__name__)

APPLICATION_COLUMNS = frozenset(
    {
        "app_id",
        "application_name",
        "application_type",
        "business_criticality",
        "environment",
        "owner",
        "technology_stack",
    }
)

_OPTIONAL_APPLICATION_COLUMNS = frozenset({"application_type", "business_criticality", "environment", "owner", "technology_stack"})
DEPENDENCY_COLUMNS = frozenset(
    {
        "app_id",
        "application",
        "dependency_id",
        "library",
        "version",
        "license",
        "dependency_type",
        "parent_dependency",
        "depth",
        "last_updated",
        "ecosystem",
    }
)
VULNERABILITY_COLUMNS = frozenset(
    {
        "cve_id",
        "library",
        "affected_version_range",
        "cvss",
        "severity",
        "patch_available",
        "published_date",
    }
)
LABEL_COLUMNS = frozenset(
    {"dependency_id", "risk_status", "risk_type", "severity", "explanation"}
)

_OPTIONAL_LABEL_COLUMNS = frozenset({"risk_type", "severity", "explanation"})
LICENSE_RULE_FIELDS = frozenset(
    {"license", "risk_level", "commercial_use", "compatible_with"}
)


class ValidationError(ValueError):
    """Base class for an individual, non-fatal dataset validation failure."""

    def __init__(
        self,
        message: str,
        *,
        dataset: str,
        field: str | None = None,
        rows: Sequence[Hashable] = (),
    ) -> None:
        super().__init__(message)
        self.dataset = dataset
        self.field = field
        self.rows = tuple(rows)

    @property
    def code(self) -> str:
        """Return a stable machine-readable classification for this error."""
        return self.__class__.__name__

    def as_dict(self) -> dict[str, Any]:
        """Serialize the error for UI, JSON, or audit logging consumers."""
        return {
            "code": self.code,
            "message": str(self),
            "dataset": self.dataset,
            "field": self.field,
            "rows": list(self.rows),
        }


class SchemaValidationError(ValidationError):
    """Raised in a result when a required field is absent."""


class MissingValueValidationError(ValidationError):
    """Raised in a result when a required field has missing values."""


class DuplicateIdentifierValidationError(ValidationError):
    """Raised in a result when an identifier expected to be unique repeats."""


class DataTypeValidationError(ValidationError):
    """Raised in a result when a value cannot satisfy its required data type."""


class DateValidationError(ValidationError):
    """Raised in a result when a value is not a valid calendar date."""


class ReferentialIntegrityValidationError(ValidationError):
    """Raised in a result when a record references an unknown identifier."""


@dataclass(slots=True)
class ValidationResult:
    """Structured outcome from validation of a single logical dataset."""

    dataset: str
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Return ``True`` when no errors were recorded."""
        return not self.errors

    def add_error(self, error: ValidationError) -> None:
        """Record an error and emit it through the module logger."""
        self.errors.append(error)
        LOGGER.warning("Validation failure: %s", error.as_dict())

    def as_dict(self) -> dict[str, Any]:
        """Serialize this result for response and presentation layers."""
        return {
            "dataset": self.dataset,
            "is_valid": self.is_valid,
            "errors": [error.as_dict() for error in self.errors],
            "warnings": self.warnings.copy(),
        }


@dataclass(slots=True)
class ValidationSummary:
    """Aggregate outcome for all parsed datasets."""

    results: dict[str, ValidationResult]

    @property
    def is_valid(self) -> bool:
        """Return whether every dataset passed validation."""
        return all(result.is_valid for result in self.results.values())

    @property
    def errors(self) -> list[ValidationError]:
        """Return all errors in a stable dataset insertion order."""
        return [error for result in self.results.values() for error in result.errors]

    def as_dict(self) -> dict[str, Any]:
        """Serialize all outcomes for a caller or API response."""
        return {
            "is_valid": self.is_valid,
            "datasets": {
                name: result.as_dict() for name, result in self.results.items()
            },
        }


def validate_applications(df: pd.DataFrame) -> ValidationResult:
    """Validate application inventory metadata and its unique application IDs."""
    result = _validate_dataframe(
        "applications",
        df,
        APPLICATION_COLUMNS,
        nullable_columns={"application_type"},
    )
    _validate_unique_id(result, df, "app_id")
    return result


def validate_dependencies(
    df: pd.DataFrame, applications: pd.DataFrame | None = None
) -> ValidationResult:
    """Validate dependency records and optionally their application references.

    Args:
        df: Parsed dependency table.
        applications: Parsed application table.  When provided, every ``app_id``
            in dependencies must be present in this table.
    """
    result = _validate_dataframe(
        "dependencies",
        df,
        DEPENDENCY_COLUMNS,
        nullable_columns={"parent_dependency", "ecosystem"},
    )
    _validate_unique_id(result, df, "dependency_id")
    _validate_dependency_types(result, df)
    _validate_transitive_parents(result, df)
    _validate_transitive_references(result, df)
    _validate_integer_column(result, df, "depth", minimum=0)
    _validate_date_column(result, df, "last_updated")
    _validate_nonempty_string(result, df, "license")
    if applications is not None:
        _validate_application_references(result, df, applications)
    return result


def validate_vulnerabilities(df: pd.DataFrame) -> ValidationResult:
    """Validate vulnerability records, including CVE identifiers and CVSS range."""
    result = _validate_dataframe("vulnerabilities", df, VULNERABILITY_COLUMNS)
    _validate_unique_id(result, df, "cve_id")
    _validate_nonempty_string(result, df, "cve_id")
    _validate_nonempty_string(result, df, "severity")
    _validate_numeric_range(result, df, "cvss", minimum=0.0, maximum=10.0)
    _validate_date_column(result, df, "published_date")
    _validate_boolean_column(result, df, "patch_available")
    return result


def validate_license_rules(data: Sequence[Mapping[str, Any]] | pd.DataFrame) -> ValidationResult:
    """Validate license compatibility policy records without parsing them.

    ``data`` may be the parsed JSON record sequence or a dataframe created from
    those records.  The source object is never mutated.
    """
    result = ValidationResult(dataset="license_rules")
    records = _license_records(data, result)
    if records is None:
        return result

    seen_licenses: set[str] = set()
    for index, record in enumerate(records):
        missing = LICENSE_RULE_FIELDS.difference(record)
        if missing:
            result.add_error(
                SchemaValidationError(
                    f"Missing required fields: {', '.join(sorted(missing))}.",
                    dataset=result.dataset,
                    rows=(index,),
                )
            )
            continue
        license_name = record.get("license")
        if not isinstance(license_name, str) or not license_name.strip():
            result.add_error(
                MissingValueValidationError(
                    "License names cannot be empty.",
                    dataset=result.dataset,
                    field="license",
                    rows=(index,),
                )
            )
            continue
        normalized_name = license_name.strip().casefold()
        if normalized_name in seen_licenses:
            result.add_error(
                DuplicateIdentifierValidationError(
                    "Duplicate license identifier.",
                    dataset=result.dataset,
                    field="license",
                    rows=(index,),
                )
            )
        seen_licenses.add(normalized_name)
        if not isinstance(record.get("risk_level"), str):
            _type_error(result, "risk_level", index, "a string")
        if not isinstance(record.get("commercial_use"), bool):
            _type_error(result, "commercial_use", index, "a boolean")
        compatible_with = record.get("compatible_with")
        is_string = isinstance(compatible_with, str)
        is_string_list = isinstance(compatible_with, list) and all(
            isinstance(value, str) and value.strip() for value in compatible_with
        )
        if not (is_string or is_string_list):
            _type_error(
                result,
                "compatible_with",
                index,
                "a string or list of non-empty strings",
            )
    return result


def validate_labels(df: pd.DataFrame) -> ValidationResult:
    """Validate dependency risk labels and their unique dependency identifiers."""
    result = _validate_dataframe(
        "labels", df, LABEL_COLUMNS, nullable_columns={"risk_type"}
    )
    _validate_unique_id(result, df, "dependency_id")
    return result


def validate_all(
    applications: pd.DataFrame,
    dependencies: pd.DataFrame,
    vulnerabilities: pd.DataFrame,
    license_rules: Sequence[Mapping[str, Any]] | pd.DataFrame,
    labels: pd.DataFrame,
) -> ValidationSummary:
    """Run all validators and return a complete cross-dataset validation report."""
    results = {
        "applications": validate_applications(applications),
        "dependencies": validate_dependencies(dependencies, applications),
        "vulnerabilities": validate_vulnerabilities(vulnerabilities),
        "license_rules": validate_license_rules(license_rules),
        "labels": validate_labels(labels),
    }
    return ValidationSummary(results=results)


def _validate_dataframe(
    dataset: str,
    df: pd.DataFrame,
    required_columns: frozenset[str],
    nullable_columns: set[str] | None = None,
) -> ValidationResult:
    """Validate a dataframe's presence, schema, and required-field nulls."""
    result = ValidationResult(dataset=dataset)
    if not isinstance(df, pd.DataFrame):
        result.add_error(
            DataTypeValidationError(
                "Dataset must be a pandas DataFrame.", dataset=dataset
            )
        )
        return result
    missing_columns = required_columns.difference(df.columns)
    if missing_columns:
        if dataset == "applications":
            missing_columns = missing_columns.difference(_OPTIONAL_APPLICATION_COLUMNS)
        elif dataset == "labels":
            missing_columns = missing_columns.difference(_OPTIONAL_LABEL_COLUMNS)
        if missing_columns:
            result.add_error(
                SchemaValidationError(
                    f"Missing required columns: {', '.join(sorted(missing_columns))}.",
                    dataset=dataset,
                )
            )
    nullable_columns = nullable_columns or set()
    for column in required_columns.intersection(df.columns).difference(nullable_columns):
        missing_rows = _missing_rows(df[column])
        if missing_rows:
            result.add_error(
                MissingValueValidationError(
                    "Required field contains missing values.",
                    dataset=dataset,
                    field=column,
                    rows=missing_rows,
                )
            )
    return result


def _validate_unique_id(result: ValidationResult, df: pd.DataFrame, column: str) -> None:
    """Record duplicate non-null identifier values, if the column exists."""
    if not isinstance(df, pd.DataFrame) or column not in df:
        return
    duplicate_rows = tuple(
        df.index[df[column].notna() & df[column].duplicated(keep=False)].tolist()
    )
    if duplicate_rows:
        result.add_error(
            DuplicateIdentifierValidationError(
                "Identifier values must be unique.",
                dataset=result.dataset,
                field=column,
                rows=duplicate_rows,
            )
        )


def _validate_dependency_types(result: ValidationResult, df: pd.DataFrame) -> None:
    """Ensure dependency type values are exactly Direct or Transitive."""
    if "dependency_type" not in df:
        return
    values = df["dependency_type"]
    invalid = values.notna() & ~values.isin({"Direct", "Transitive"})
    if invalid.any():
        result.add_error(
            DataTypeValidationError(
                "Dependency type must be 'Direct' or 'Transitive'.",
                dataset=result.dataset,
                field="dependency_type",
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_transitive_parents(result: ValidationResult, df: pd.DataFrame) -> None:
    """Require a parent ID or an inbound ``transitive_deps`` relationship."""
    if not {"dependency_type", "parent_dependency"}.issubset(df.columns):
        return
    parent = df["parent_dependency"]
    missing_parent = parent.isna() | parent.fillna("").astype(str).str.strip().eq("")
    referenced_children = _transitive_child_keys(df)
    invalid = df["dependency_type"].eq("Transitive") & missing_parent & ~df.apply(
        lambda row: _dependency_key(row) in referenced_children, axis=1
    )
    if invalid.any():
        result.add_error(
            MissingValueValidationError(
                "Transitive dependencies must include parent_dependency.",
                dataset=result.dataset,
                field="parent_dependency",
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_transitive_references(result: ValidationResult, df: pd.DataFrame) -> None:
    """Ensure every ``transitive_deps`` child points to an SBOM dependency row."""
    if "transitive_deps" not in df:
        return
    known = {_dependency_key(row) for _, row in df.iterrows()}
    unresolved_rows: list[Hashable] = []
    for index, row in df.iterrows():
        for library, version in _parse_transitive_dependencies(row.get("transitive_deps")):
            if (_scope_key(row), library.casefold(), version.casefold()) not in known:
                unresolved_rows.append(index)
                break
    if unresolved_rows:
        result.add_error(
            ReferentialIntegrityValidationError(
                "transitive_deps references a dependency that does not exist in the same application.",
                dataset=result.dataset,
                field="transitive_deps",
                rows=tuple(unresolved_rows),
            )
        )


def _transitive_child_keys(df: pd.DataFrame) -> set[tuple[str, str, str]]:
    """Return application-scoped child identities declared by parent records."""
    children: set[tuple[str, str, str]] = set()
    if "transitive_deps" not in df:
        return children
    for _, row in df.iterrows():
        for library, version in _parse_transitive_dependencies(row.get("transitive_deps")):
            children.add((_scope_key(row), library.casefold(), version.casefold()))
    return children


def _dependency_key(row: pd.Series) -> tuple[str, str, str]:
    """Create the application-scoped identity used for relationship checks."""
    return (_scope_key(row), str(row.get("library", "")).strip().casefold(), str(row.get("version", "")).strip().casefold())


def _scope_key(row: pd.Series) -> str:
    """Prefer stable application ID, falling back to application display name."""
    return str(row.get("app_id") or row.get("application") or "").strip().casefold()


def _parse_transitive_dependencies(value: Any) -> list[tuple[str, str]]:
    """Parse canonical ``library:version;...`` relationship text."""
    if value is None or pd.isna(value):
        return []
    children: list[tuple[str, str]] = []
    for chunk in str(value).replace(",", ";").split(";"):
        library, _, version = chunk.strip().partition(":")
        if library.strip():
            children.append((library.strip(), version.strip()))
    return children


def _validate_integer_column(
    result: ValidationResult, df: pd.DataFrame, column: str, minimum: int
) -> None:
    """Ensure a required numeric column contains whole values above a minimum."""
    if column not in df:
        return
    converted = pd.to_numeric(df[column], errors="coerce")
    invalid = df[column].notna() & (
        converted.isna() | (converted % 1 != 0) | (converted < minimum)
    )
    if invalid.any():
        result.add_error(
            DataTypeValidationError(
                f"Values must be whole numbers greater than or equal to {minimum}.",
                dataset=result.dataset,
                field=column,
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_numeric_range(
    result: ValidationResult, df: pd.DataFrame, column: str, minimum: float, maximum: float
) -> None:
    """Ensure a column is numeric and falls within an inclusive range."""
    if column not in df:
        return
    converted = pd.to_numeric(df[column], errors="coerce")
    invalid = df[column].notna() & (
        converted.isna() | (converted < minimum) | (converted > maximum)
    )
    if invalid.any():
        result.add_error(
            DataTypeValidationError(
                f"Values must be numeric and between {minimum:g} and {maximum:g}.",
                dataset=result.dataset,
                field=column,
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_date_column(result: ValidationResult, df: pd.DataFrame, column: str) -> None:
    """Ensure all non-null values in a column can be converted to dates."""
    if column not in df:
        return
    values = df[column]
    if is_datetime64_any_dtype(values):
        invalid = values.notna() & pd.isna(values)
    else:
        converted = pd.to_datetime(values, errors="coerce")
        invalid = values.notna() & converted.isna()
    if invalid.any():
        result.add_error(
            DateValidationError(
                "Values must be valid dates.",
                dataset=result.dataset,
                field=column,
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_boolean_column(result: ValidationResult, df: pd.DataFrame, column: str) -> None:
    """Ensure a dataframe column contains booleans, allowing nullable booleans."""
    if column not in df or is_bool_dtype(df[column]):
        return
    invalid = df[column].notna() & ~df[column].map(lambda value: isinstance(value, bool))
    if invalid.any():
        result.add_error(
            DataTypeValidationError(
                "Values must be boolean.",
                dataset=result.dataset,
                field=column,
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_nonempty_string(result: ValidationResult, df: pd.DataFrame, column: str) -> None:
    """Ensure a required text field contains string values.

    Blank strings are identified separately by the generic required-value check,
    avoiding duplicate messages for the same data quality problem.
    """
    if column not in df:
        return
    invalid = df[column].notna() & ~df[column].map(lambda value: isinstance(value, str))
    if invalid.any():
        result.add_error(
            DataTypeValidationError(
                "Values must be strings.",
                dataset=result.dataset,
                field=column,
                rows=tuple(df.index[invalid].tolist()),
            )
        )


def _validate_application_references(
    result: ValidationResult, dependencies: pd.DataFrame, applications: pd.DataFrame
) -> None:
    """Ensure dependency application identifiers exist in the application table."""
    if "app_id" not in dependencies or not isinstance(applications, pd.DataFrame):
        return
    if "app_id" not in applications:
        result.add_error(
            ReferentialIntegrityValidationError(
                "Cannot validate app_id references: applications.app_id is missing.",
                dataset=result.dataset,
                field="app_id",
            )
        )
        return
    valid_ids = set(applications["app_id"].dropna().astype(str))
    unknown = dependencies["app_id"].notna() & ~dependencies["app_id"].astype(str).isin(valid_ids)
    if unknown.any():
        result.add_error(
            ReferentialIntegrityValidationError(
                "Dependency app_id does not exist in applications.",
                dataset=result.dataset,
                field="app_id",
                rows=tuple(dependencies.index[unknown].tolist()),
            )
        )


def _license_records(
    data: Sequence[Mapping[str, Any]] | pd.DataFrame, result: ValidationResult
) -> list[Mapping[str, Any]] | None:
    """Return license records from supported in-memory structured containers."""
    if isinstance(data, pd.DataFrame):
        return data.to_dict(orient="records")
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
        records = list(data)
        if all(isinstance(record, Mapping) for record in records):
            return records
    result.add_error(
        DataTypeValidationError(
            "License rules must be a DataFrame or sequence of mapping records.",
            dataset=result.dataset,
        )
    )
    return None


def _missing_rows(series: pd.Series) -> tuple[Hashable, ...]:
    """Return index values for null or blank text entries in a required field."""
    missing = series.isna()
    if series.dtype == object or pd.api.types.is_string_dtype(series):
        missing |= series.fillna("").astype(str).str.strip().eq("")
    return tuple(series.index[missing].tolist())


def _type_error(
    result: ValidationResult, field: str, row: int, expected: str
) -> None:
    """Add a standardized type-validation error for one license-rule field."""
    result.add_error(
        DataTypeValidationError(
            f"Value must be {expected}.",
            dataset=result.dataset,
            field=field,
            rows=(row,),
        )
    )
