"""NetworkX dependency graph construction and query services.

The module operates on already parsed and validated dependency data.  It does
not parse files, calculate risk, or mutate the source dataframe.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Hashable, Literal

import networkx as nx
import pandas as pd

LOGGER = logging.getLogger(__name__)

_REQUIRED_COLUMNS = frozenset(
    {
        "application",
        "dependency_id",
        "library",
        "version",
        "dependency_type",
        "license",
        "depth",
        "last_updated",
        "ecosystem",
    }
)
_ROOT_PREFIX = "application::"
_DependencyNode = tuple[str, str, str]

__all__ = [
    "build_dependency_graph",
    "get_application_subgraph",
    "get_direct_dependencies",
    "get_transitive_dependencies",
    "find_dependency_path",
    "export_graph",
]


def build_dependency_graph(dependencies: pd.DataFrame) -> nx.DiGraph:
    """Build a directed dependency graph from normalized SBOM dependency rows.

    Dependency nodes use ``(application, library, version)`` identifiers, so
    repeated records for an identical dependency instance are represented once.
    Application root nodes use ``application::<application>`` identifiers and
    point to direct dependencies.  Transitive rows with an unknown parent are
    retained as isolated nodes and logged as unresolved relationships.

    Args:
        dependencies: Parsed and validated SBOM dependency dataframe.

    Returns:
        A directed graph whose edges point from parent to child dependency.

    Raises:
        TypeError: If ``dependencies`` is not a dataframe.
        ValueError: If required dependency columns are absent.
    """
    _validate_graph_input(dependencies)
    graph = nx.DiGraph()
    parent_nodes = _parent_node_index(dependencies)

    for application in _applications(dependencies):
        root_node = _root_node(application)
        graph.add_node(
            root_node,
            node_kind="application",
            application=application,
            library=None,
            version=None,
            dependency_type="Root",
            license=None,
            depth=-1,
            last_updated=None,
            ecosystem=None,
            risk=None,
        )

    for row in dependencies.to_dict(orient="records"):
        application = _text_value(row["application"])
        node = _dependency_node(application, row["library"], row["version"])
        graph.add_node(node, **_node_attributes(row, application))

        dependency_type = _text_value(row["dependency_type"]).casefold()
        parent_id = _text_value(row.get("parent_dependency"))
        if dependency_type == "direct":
            graph.add_edge(_root_node(application), node)
        elif parent_id:
            parent = parent_nodes.get((application, parent_id))
            if parent is None:
                LOGGER.warning(
                    "Unresolved parent dependency '%s' for '%s' in application '%s'.",
                    parent_id,
                    row["dependency_id"],
                    application,
                )
            else:
                graph.add_edge(parent, node)
        else:
            LOGGER.warning(
                "Transitive dependency '%s' in application '%s' has no parent.",
                row["dependency_id"],
                application,
            )

    LOGGER.info(
        "Built dependency graph with %d nodes and %d edges.",
        graph.number_of_nodes(),
        graph.number_of_edges(),
    )
    return graph


def get_application_subgraph(graph: nx.DiGraph, application: str) -> nx.DiGraph:
    """Return an independent graph containing one application and its dependencies.

    Unresolved or otherwise isolated dependencies belonging to the application
    are included, in addition to nodes reachable from the application's root.
    """
    _validate_graph(graph)
    application_name = _text_value(application)
    root = _root_node(application_name)
    nodes: set[Hashable] = {
        node
        for node, data in graph.nodes(data=True)
        if data.get("application") == application_name
    }
    if root in graph:
        nodes.add(root)
    return graph.subgraph(nodes).copy()


def get_direct_dependencies(graph: nx.DiGraph, application: str) -> list[_DependencyNode]:
    """Return unique direct dependency node identifiers for an application."""
    _validate_graph(graph)
    root = _root_node(_text_value(application))
    if root not in graph:
        return []
    return sorted(
        (
            node
            for node in graph.successors(root)
            if graph.nodes[node].get("dependency_type") == "Direct"
        ),
        key=_node_sort_key,
    )


def get_transitive_dependencies(
    graph: nx.DiGraph, application: str
) -> list[_DependencyNode]:
    """Return unique transitive dependency node identifiers for an application."""
    _validate_graph(graph)
    application_name = _text_value(application)
    return sorted(
        (
            node
            for node, data in graph.nodes(data=True)
            if data.get("application") == application_name
            and data.get("dependency_type") == "Transitive"
        ),
        key=_node_sort_key,
    )


def find_dependency_path(
    graph: nx.DiGraph,
    application: str,
    library: str,
    version: str | None = None,
) -> list[Hashable] | None:
    """Find a root-to-dependency path for an application dependency instance.

    If ``version`` is omitted, the function finds the shallowest reachable
    dependency with the supplied library name.  ``None`` is returned when the
    application, dependency, or route does not exist.
    """
    _validate_graph(graph)
    application_name = _text_value(application)
    root = _root_node(application_name)
    if root not in graph:
        return None

    candidates = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("application") == application_name
        and data.get("library") == _text_value(library)
        and (version is None or data.get("version") == _text_value(version))
    ]
    paths: list[list[Hashable]] = []
    for candidate in candidates:
        try:
            paths.append(nx.shortest_path(graph, root, candidate))
        except nx.NetworkXNoPath:
            continue
    return min(paths, key=len) if paths else None


def export_graph(
    graph: nx.DiGraph, destination: str | Path, format: Literal["json", "graphml"] = "json"
) -> Path:
    """Export a dependency graph to JSON node-link data or GraphML.

    Args:
        graph: Dependency graph produced by :func:`build_dependency_graph`.
        destination: Target file path. Parent directories are created as needed.
        format: ``"json"`` for portable node-link JSON or ``"graphml"`` for
            third-party graph tooling.

    Returns:
        The resolved output path.

    Raises:
        ValueError: If the requested export format is unsupported.
    """
    _validate_graph(graph)
    output = Path(destination)
    output.parent.mkdir(parents=True, exist_ok=True)
    normalized_format = format.casefold()
    if normalized_format == "json":
        data = nx.node_link_data(graph, edges="edges")
        output.write_text(json.dumps(data, default=str, indent=2), encoding="utf-8")
    elif normalized_format == "graphml":
        nx.write_graphml(_graphml_safe_copy(graph), output)
    else:
        raise ValueError("format must be either 'json' or 'graphml'.")
    LOGGER.info("Exported dependency graph to %s.", output)
    return output.resolve()


def _validate_graph_input(dependencies: pd.DataFrame) -> None:
    """Check graph-builder input has the schema required for graph generation."""
    if not isinstance(dependencies, pd.DataFrame):
        raise TypeError("dependencies must be a pandas DataFrame.")
    missing = _REQUIRED_COLUMNS.difference(dependencies.columns)
    if missing:
        raise ValueError(f"Missing graph columns: {', '.join(sorted(missing))}.")


def _validate_graph(graph: nx.DiGraph) -> None:
    """Ensure an operation receives a directed NetworkX graph."""
    if not isinstance(graph, nx.DiGraph):
        raise TypeError("graph must be a networkx.DiGraph.")


def _parent_node_index(dependencies: pd.DataFrame) -> dict[tuple[str, str], _DependencyNode]:
    """Map application/dependency IDs to their stable graph node identifiers."""
    index: dict[tuple[str, str], _DependencyNode] = {}
    for row in dependencies.to_dict(orient="records"):
        application = _text_value(row["application"])
        dependency_id = _text_value(row["dependency_id"])
        node = _dependency_node(application, row["library"], row["version"])
        existing = index.get((application, dependency_id))
        if existing is not None and existing != node:
            LOGGER.warning(
                "Duplicate dependency_id '%s' in application '%s'; using first record.",
                dependency_id,
                application,
            )
            continue
        index[(application, dependency_id)] = node
    return index


def _applications(dependencies: pd.DataFrame) -> list[str]:
    """Return deterministic, non-empty application names from dependency data."""
    return sorted({_text_value(value) for value in dependencies["application"]})


def _dependency_node(application: str, library: Any, version: Any) -> _DependencyNode:
    """Build the canonical identity for one dependency instance."""
    return application, _text_value(library), _text_value(version)


def _root_node(application: str) -> str:
    """Build the stable root node identifier for an application."""
    return f"{_ROOT_PREFIX}{application}"


def _node_attributes(row: dict[str, Any], application: str) -> dict[str, Any]:
    """Extract the node metadata required by the graph contract."""
    return {
        "node_kind": "dependency",
        "application": application,
        "library": _text_value(row["library"]),
        "version": _text_value(row["version"]),
        "dependency_type": _text_value(row["dependency_type"]),
        "license": _text_value(row["license"]),
        "depth": _python_value(row["depth"]),
        "last_updated": _python_value(row["last_updated"]),
        "ecosystem": _text_value(row["ecosystem"]),
        "risk": None,
    }


def _python_value(value: Any) -> Any:
    """Convert pandas scalar values to JSON- and GraphML-compatible objects."""
    if pd.isna(value):
        return None
    return value.item() if hasattr(value, "item") else value


def _text_value(value: Any) -> str:
    """Convert optional scalar data to a trimmed, stable string value."""
    if pd.isna(value):
        return ""
    return str(value).strip()


def _node_sort_key(node: _DependencyNode) -> tuple[str, str, str]:
    """Provide deterministic sorting for dependency node identifiers."""
    return node


def _graphml_safe_copy(graph: nx.DiGraph) -> nx.DiGraph:
    """Copy a graph with GraphML-compatible scalar node and edge attributes."""
    copy = nx.DiGraph()
    for node, attributes in graph.nodes(data=True):
        copy.add_node(str(node), **{key: _graphml_value(value) for key, value in attributes.items()})
    for source, target, attributes in graph.edges(data=True):
        copy.add_edge(
            str(source),
            str(target),
            **{key: _graphml_value(value) for key, value in attributes.items()},
        )
    return copy


def _graphml_value(value: Any) -> Any:
    """Convert nullable and complex values to a GraphML-supported scalar."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
