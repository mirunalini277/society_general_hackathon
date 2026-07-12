"""SBOM ingestion and normalization utilities.

The parser deliberately performs only structural normalization.  Validation of
business constraints and graph relationships belongs to :mod:`validator`.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO, StringIO
import json
import logging
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence, TextIO

import pandas as pd

LOGGER = logging.getLogger(__name__)

SBOM_COLUMNS = [
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
]

_STRING_COLUMNS = [
    "app_id",
    "application",
    "dependency_id",
    "library",
    "version",
    "license",
    "dependency_type",
    "parent_dependency",
    "ecosystem",
]

Source = str | Path | bytes | bytearray | BinaryIO | TextIO


class SBOMParseError(ValueError):
    """Raised when an SBOM source cannot be decoded into tabular records."""


@dataclass(frozen=True, slots=True)
class ParsedSBOM:
    """Normalized SBOM records together with provenance information."""

    dependencies: pd.DataFrame
    source_name: str
    source_format: str

    @property
    def application_count(self) -> int:
        """Return the number of unique applications in the dataset."""
        return int(self.dependencies["app_id"].nunique())

    @property
    def dependency_count(self) -> int:
        """Return the total number of dependency records."""
        return len(self.dependencies.index)


def parse_sbom(source: Source, filename: str | None = None) -> ParsedSBOM:
    """Parse an SBOM CSV or JSON source into a normalized dataframe.

    Args:
        source: A local path, Streamlit upload-like object, raw bytes, or text
            file handle containing a CSV or JSON document.
        filename: Optional source name. Required for raw bytes when the format
            cannot be inferred from the content.

    Returns:
        Parsed SBOM data with stable column names and pandas date/depth types.

    Raises:
        SBOMParseError: If the source type, format, or document structure is
            unsupported or unreadable.
    """
    source_name = filename or _source_name(source)
    source_format = _detect_format(source_name, source)
    try:
        frame = _read_source(source, source_format)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, pd.errors.ParserError) as exc:
        LOGGER.warning("Unable to parse SBOM source %s: %s", source_name, exc)
        raise SBOMParseError(f"Unable to parse '{source_name}': {exc}") from exc

    return ParsedSBOM(
        dependencies=normalize_sbom(frame),
        source_name=source_name,
        source_format=source_format,
    )


def normalize_sbom(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with canonical SBOM column names and data types.

    Missing columns are not rejected here so the validation module can provide
    a complete, user-friendly validation report rather than a single error.
    """
    if not isinstance(frame, pd.DataFrame):
        raise SBOMParseError("SBOM content must decode to a table of records.")

    normalized = frame.copy()
    normalized.columns = [str(column).strip().lower() for column in normalized.columns]
    normalized = normalized.rename(
        columns={
            "dependency": "library",
            "name": "library",
            "component": "library",
            "component_id": "dependency_id",
            "type": "dependency_type",
            "parent": "parent_dependency",
            "lastupdated": "last_updated",
            "dep_id": "dependency_id",
            "application_id": "app_id",
            "application_name": "application",
            "license_name": "license",
            "transitive_deps": "transitive_deps",
        }
    )
    normalized = normalized.loc[:, ~normalized.columns.duplicated()].copy()

    if "app_id" not in normalized and "application_id" in normalized:
        normalized["app_id"] = normalized["application_id"]
    if "application" not in normalized:
        if "application_name" in normalized:
            normalized["application"] = normalized["application_name"]
        elif "name" in normalized:
            normalized["application"] = normalized["name"]
    if "dependency_id" not in normalized and "dep_id" in normalized:
        normalized["dependency_id"] = normalized["dep_id"]
    if "parent_dependency" not in normalized and "parent" in normalized:
        normalized["parent_dependency"] = normalized["parent"]
    if "license" not in normalized and "license_name" in normalized:
        normalized["license"] = normalized["license_name"]

    defaults = {
        "app_id": "",
        "application": "",
        "dependency_id": "",
        "library": "",
        "version": "",
        "license": "",
        "dependency_type": "Direct",
        "parent_dependency": "",
        "depth": 0,
        "last_updated": pd.NaT,
        "ecosystem": "",
        "transitive_deps": "",
    }
    for column, default in defaults.items():
        if column not in normalized:
            normalized[column] = default

    for column in _STRING_COLUMNS:
        if column in normalized:
            normalized[column] = normalized[column].fillna("").astype(str).str.strip()

    if "dependency_type" in normalized:
        normalized["dependency_type"] = normalized["dependency_type"].str.title()
    if "transitive_deps" in normalized:
        normalized["transitive_deps"] = normalized["transitive_deps"].map(
            _normalize_transitive_dependencies
        )
        normalized = _resolve_transitive_dependency_versions(normalized)
    if "depth" in normalized:
        normalized["depth"] = pd.to_numeric(normalized["depth"], errors="coerce").astype("Int64")
    if "last_updated" in normalized:
        normalized["last_updated"] = pd.to_datetime(
            normalized["last_updated"], errors="coerce", utc=False
        )

    ordered_columns = [column for column in SBOM_COLUMNS if column in normalized]
    other_columns = [column for column in normalized.columns if column not in ordered_columns]
    return normalized[ordered_columns + other_columns]


def _normalize_transitive_dependencies(value: Any) -> str:
    """Return transitive links as ``library:version;...`` for all source formats.

    The supplied CSV represents parent-to-child links in one field.  Keeping a
    canonical string is dataframe/CSV-friendly while allowing the graph and
    validator to interpret the same relationship consistently.
    """
    if value is None or (not isinstance(value, (str, bytes, Sequence)) and pd.isna(value)):
        return ""
    values = value if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else [value]
    children: list[str] = []
    for item in values:
        for chunk in str(item).replace(",", ";").split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            library, separator, version = chunk.partition(":")
            library = library.strip()
            version = version.strip()
            if library:
                children.append(f"{library}:{version}" if separator else library)
    return ";".join(dict.fromkeys(children))


def _resolve_transitive_dependency_versions(frame: pd.DataFrame) -> pd.DataFrame:
    """Align declared child versions with an unambiguous transitive SBOM record.

    The official sample occasionally declares a child version in
    ``transitive_deps`` that differs from the corresponding flat SBOM row.
    Relationship resolution is library-based in that case, but only when the
    application has exactly one transitive record for that library.  Exact
    references and ambiguous version conflicts are left untouched.
    """
    candidates: dict[tuple[str, str], list[str]] = {}
    for row in frame.to_dict(orient="records"):
        if str(row.get("dependency_type", "")).casefold() != "transitive":
            continue
        key = (_relationship_scope(row), str(row.get("library", "")).strip().casefold())
        version = str(row.get("version", "")).strip()
        if version:
            candidates.setdefault(key, []).append(version)

    resolved = frame.copy()
    for index, row in resolved.iterrows():
        value = row.get("transitive_deps", "")
        if not value:
            continue
        children: list[str] = []
        for library, version in _transitive_pairs(value):
            versions = candidates.get((_relationship_scope(row), library.casefold()), [])
            if version not in versions and len(set(versions)) == 1:
                version = versions[0]
            children.append(f"{library}:{version}" if version else library)
        resolved.at[index, "transitive_deps"] = ";".join(dict.fromkeys(children))
    return resolved


def _transitive_pairs(value: Any) -> list[tuple[str, str]]:
    """Return normalized child library/version pairs from canonical link text."""
    pairs: list[tuple[str, str]] = []
    for chunk in str(value).split(";"):
        library, _, version = chunk.strip().partition(":")
        if library.strip():
            pairs.append((library.strip(), version.strip()))
    return pairs


def _relationship_scope(row: Mapping[str, Any]) -> str:
    """Return the stable application scope used to repair parent-child links."""
    return str(row.get("app_id") or row.get("application") or "").strip().casefold()


def normalize_application_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize application records from the official dataset to the backend schema."""
    if not isinstance(frame, pd.DataFrame):
        raise SBOMParseError("Application content must decode to a table of records.")

    normalized = frame.copy()
    normalized.columns = [str(column).strip().lower() for column in normalized.columns]
    renamed = {
        "name": "application_name",
        "criticality": "business_criticality",
        "business_owner": "owner",
        "deployment": "environment",
        "language": "technology_stack",
    }
    normalized = normalized.rename(columns=renamed)

    if "app_id" not in normalized and "application_id" in normalized:
        normalized["app_id"] = normalized["application_id"]
    if "application_name" not in normalized and "application" in normalized:
        normalized["application_name"] = normalized["application"]
    if "application_type" not in normalized:
        normalized["application_type"] = ""
    if "business_criticality" not in normalized and "criticality" in normalized:
        normalized["business_criticality"] = normalized["criticality"]
    if "environment" not in normalized and "deployment" in normalized:
        normalized["environment"] = normalized["deployment"]
    if "owner" not in normalized and "business_owner" in normalized:
        normalized["owner"] = normalized["business_owner"]
    if "technology_stack" not in normalized and "language" in normalized:
        normalized["technology_stack"] = normalized["language"]

    for column in ("app_id", "application_name", "application_type", "business_criticality", "environment", "owner", "technology_stack"):
        if column in normalized:
            normalized[column] = normalized[column].fillna("").astype(str).str.strip()
    return normalized


def normalize_vulnerability_records(records: Sequence[Mapping[str, Any]] | pd.DataFrame) -> list[dict[str, Any]]:
    """Normalize official vulnerability records to the backend's internal schema."""
    if isinstance(records, pd.DataFrame):
        items = records.to_dict(orient="records")
    else:
        items = [dict(record) for record in records]

    normalized: list[dict[str, Any]] = []
    for item in items:
        row = {str(key).strip(): value for key, value in item.items()}
        if "cvss_score" in row and "cvss" not in row:
            row["cvss"] = row["cvss_score"]
        if "affected_versions" in row and "affected_version_range" not in row:
            versions = row["affected_versions"]
            if isinstance(versions, Sequence) and not isinstance(versions, (str, bytes)):
                row["affected_version_range"] = ",".join(str(version).strip() for version in versions if str(version).strip())
            else:
                row["affected_version_range"] = str(versions or "")
        if "library" in row:
            row["library"] = str(row["library"]).strip()
        if "severity" in row:
            row["severity"] = str(row["severity"]).strip()
        if "patch_available" in row and not isinstance(row["patch_available"], bool):
            row["patch_available"] = bool(row["patch_available"])
        normalized.append(row)
    return normalized


def normalize_license_records(data: Sequence[Mapping[str, Any]] | pd.DataFrame) -> list[dict[str, Any]]:
    """Normalize official license rules to the backend's internal policy schema."""
    if isinstance(data, pd.DataFrame):
        records = data.to_dict(orient="records")
    else:
        records = [dict(record) for record in data]

    normalized: list[dict[str, Any]] = []
    for record in records:
        row = {str(key).strip(): value for key, value in record.items()}
        if "compatible_with_proprietary" in row and "compatible_with" not in row:
            row["compatible_with"] = "Proprietary" if row["compatible_with_proprietary"] else ""
        if "commercial_use" not in row:
            row["commercial_use"] = not bool(row.get("viral", False))
        if "risk_level" in row and not row.get("risk_level"):
            row["risk_level"] = "Low"
        normalized.append(row)
    return normalized


def normalize_label_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize dependency-label records from the official dataset to the backend schema."""
    if not isinstance(frame, pd.DataFrame):
        raise SBOMParseError("Label content must decode to a table of records.")

    normalized = frame.copy()
    normalized.columns = [str(column).strip().lower() for column in normalized.columns]
    normalized = normalized.rename(columns={"dep_id": "dependency_id", "application_id": "app_id", "is_risky": "risk_status"})
    if "risk_status" in normalized:
        normalized["risk_status"] = normalized["risk_status"].astype(str).str.strip()
    if "risk_type" not in normalized:
        normalized["risk_type"] = ""
    if "severity" not in normalized:
        normalized["severity"] = ""
    if "explanation" not in normalized:
        normalized["explanation"] = ""
    return normalized


def load_json_file(path: str | Path) -> Any:
    """Load JSON from disk using a sequence of common encodings."""
    target = Path(path)
    raw_bytes = target.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return json.loads(raw_bytes.decode(encoding))
        except UnicodeDecodeError:
            continue
        except json.JSONDecodeError:
            raise
    raise UnicodeDecodeError("utf-8", raw_bytes, 0, 1, "Unable to decode JSON file.")


def _read_source(source: Source, source_format: str) -> pd.DataFrame:
    """Decode an input source using its known file format."""
    content = _read_content(source)
    if source_format == "csv":
        return pd.read_csv(StringIO(_as_text(content)))

    payload = json.loads(_as_text(content))
    records = _json_records(payload)
    return pd.json_normalize(records)


def _read_content(source: Source) -> str | bytes:
    """Read source content without assuming a particular upload implementation."""
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, str):
        return Path(source).read_bytes()
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if hasattr(source, "getvalue"):
        return source.getvalue()
    if hasattr(source, "read"):
        return source.read()
    raise SBOMParseError("Unsupported SBOM source type.")


def _as_text(content: str | bytes) -> str:
    """Decode uploaded bytes using a robust fallback chain."""
    if isinstance(content, str):
        return content
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("utf-8", content, 0, 1, "Unable to decode SBOM content.")


def _json_records(payload: Any) -> list[dict[str, Any]]:
    """Extract records from conventional JSON SBOM wrappers or a record list."""
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return payload
    if isinstance(payload, dict):
        for key in ("dependencies", "components", "records", "data"):
            value = payload.get(key)
            if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                return value
    raise SBOMParseError(
        "JSON SBOM must be a list of dependency records or contain a "
        "'dependencies', 'components', 'records', or 'data' list."
    )


def _source_name(source: Source) -> str:
    """Return a meaningful name for local paths and uploaded files."""
    if isinstance(source, (str, Path)):
        return Path(source).name
    name = getattr(source, "name", None)
    return str(name) if name else "uploaded_sbom"


def _detect_format(source_name: str, source: Source) -> str:
    """Determine CSV or JSON using filename first, then content inspection."""
    suffix = Path(source_name).suffix.lower()
    if suffix in {".csv", ".json"}:
        return suffix[1:]
    if isinstance(source, (bytes, bytearray)):
        leading = bytes(source).lstrip()[:1]
        if leading in {b"[", b"{"}:
            return "json"
        return "csv"
    raise SBOMParseError("Only CSV and JSON SBOM files are supported.")
