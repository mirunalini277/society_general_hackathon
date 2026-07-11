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
from typing import Any, BinaryIO, TextIO

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
        }
    )
    normalized = normalized.loc[:, ~normalized.columns.duplicated()].copy()

    for column in _STRING_COLUMNS:
        if column in normalized:
            normalized[column] = normalized[column].fillna("").astype(str).str.strip()

    if "dependency_type" in normalized:
        normalized["dependency_type"] = normalized["dependency_type"].str.title()
    if "depth" in normalized:
        normalized["depth"] = pd.to_numeric(normalized["depth"], errors="coerce").astype("Int64")
    if "last_updated" in normalized:
        normalized["last_updated"] = pd.to_datetime(
            normalized["last_updated"], errors="coerce", utc=False
        )

    ordered_columns = [column for column in SBOM_COLUMNS if column in normalized]
    other_columns = [column for column in normalized.columns if column not in ordered_columns]
    return normalized[ordered_columns + other_columns]


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
    """Decode uploaded bytes, accepting UTF-8 BOM files."""
    if isinstance(content, str):
        return content
    return content.decode("utf-8-sig")


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
