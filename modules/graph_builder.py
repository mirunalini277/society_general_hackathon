"""NetworkX dependency graph construction and query services.

The module operates on already parsed and validated dependency data.  It does
not parse files, calculate risk, or mutate the source dataframe.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Hashable, Iterable, Literal

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
    "summarize_transitive_resolution",
    "export_graph",
]


@dataclass(frozen=True, slots=True)
class TransitiveResolutionSummary:
    """Coverage metrics for declared SBOM transitive relationships."""

    direct_dependencies: int
    transitive_dependencies: int
    reachable_transitive_dependencies: int
    transitive_edges_built: int
    unresolved_transitive_references: int
    inferred_orphan_transitive_edges: int

    @property
    def is_fully_resolved(self) -> bool:
        return (
            self.reachable_transitive_dependencies == self.transitive_dependencies
            and self.unresolved_transitive_references == 0
        )


def build_dependency_graph(
    dependencies: pd.DataFrame,
    vulnerability_matches: Iterable[Any] | None = None,
) -> nx.DiGraph:
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
    unresolved_transitive_references: list[dict[str, str]] = []
    transitive_edges: set[tuple[Hashable, Hashable]] = set()
    inferred_orphan_edges = 0
    parent_nodes = _parent_node_index(dependencies)
    node_index: dict[tuple[str, str, str], _DependencyNode] = {}
    transitive_library_nodes: dict[tuple[str, str], list[_DependencyNode]] = {}

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
        node_index[(application, _text_value(row["library"]), _text_value(row["version"]))] = node
        if _text_value(row["dependency_type"]).casefold() == "transitive":
            transitive_library_nodes.setdefault(
                (application, _text_value(row["library"]).casefold()), []
            ).append(node)

    for row in dependencies.to_dict(orient="records"):
        application = _text_value(row["application"])
        node = node_index[(application, _text_value(row["library"]), _text_value(row["version"]))]

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
                "Transitive dependency '%s' in application '%s' has no explicit parent.",
                row["dependency_id"],
                application,
            )

        if "transitive_deps" in row and row.get("transitive_deps"):
            for child in _parse_transitive_dependencies(row["transitive_deps"]):
                child_node = node_index.get((application, child[0], child[1]))
                child_nodes = [child_node] if child_node is not None else transitive_library_nodes.get(
                    (application, child[0].casefold()), []
                )
                if not child_nodes:
                    unresolved_transitive_references.append(
                        {
                            "application": application,
                            "parent_dependency_id": _text_value(row.get("dependency_id")),
                            "library": child[0],
                            "version": child[1],
                        }
                    )
                    LOGGER.warning(
                        "Unresolved transitive dependency '%s:%s' from '%s' in application '%s'.",
                        child[0], child[1], row["dependency_id"], application,
                    )
                    continue
                for resolved_child in child_nodes:
                    graph.add_edge(node, resolved_child)
                    transitive_edges.add((node, resolved_child))

    # Preserve application visibility for flat-SBOM transitive records that
    # declare no parent. Declared parent-child edges above always take priority.
    for node, attributes in graph.nodes(data=True):
        if (
            attributes.get("node_kind") == "dependency"
            and attributes.get("dependency_type") == "Transitive"
            and graph.in_degree(node) == 0
        ):
            graph.add_edge(
                _root_node(attributes["application"]),
                node,
                relationship_source="inferred_orphan_transitive",
            )
            inferred_orphan_edges += 1

    graph.graph["transitive_edges_built"] = len(transitive_edges)
    graph.graph["unresolved_transitive_references"] = unresolved_transitive_references
    graph.graph["inferred_orphan_transitive_edges"] = inferred_orphan_edges

    if vulnerability_matches is not None:
        _propagate_vulnerability_risk(graph, vulnerability_matches)

    LOGGER.info(
        "Built dependency graph with %d nodes and %d edges.",
        graph.number_of_nodes(),
        graph.number_of_edges(),
    )
    return graph


def summarize_transitive_resolution(
    graph: nx.DiGraph, dependencies: pd.DataFrame
) -> TransitiveResolutionSummary:
    """Measure whether each declared transitive dependency is root-reachable."""
    _validate_graph(graph)
    _validate_graph_input(dependencies)
    direct = 0
    transitive = 0
    reachable = 0
    for row in dependencies.to_dict(orient="records"):
        dependency_type = _text_value(row["dependency_type"]).casefold()
        if dependency_type == "direct":
            direct += 1
            continue
        if dependency_type != "transitive":
            continue
        transitive += 1
        application = _text_value(row["application"])
        node = _dependency_node(application, row["library"], row["version"])
        root = _root_node(application)
        if node in graph and root in graph and nx.has_path(graph, root, node):
            reachable += 1
    return TransitiveResolutionSummary(
        direct_dependencies=direct,
        transitive_dependencies=transitive,
        reachable_transitive_dependencies=reachable,
        transitive_edges_built=int(graph.graph.get("transitive_edges_built", 0)),
        unresolved_transitive_references=len(
            graph.graph.get("unresolved_transitive_references", [])
        ),
        inferred_orphan_transitive_edges=int(
            graph.graph.get("inferred_orphan_transitive_edges", 0)
        ),
    )


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
        "inherited_risk": False,
        "normalized_library": _normalize_library_name(row.get("library", "")),
    }


def _propagate_vulnerability_risk(graph: nx.DiGraph, vulnerability_matches: Iterable[Any]) -> None:
    """Mark vulnerable nodes and all root-reachable parents as exposed.

    Edges point from an application/parent dependency to its child.  Therefore
    exposure must travel through predecessors, so Application -> A -> B -> C
    marks the application, A, and B when C has a matched vulnerability.
    ``nx.ancestors`` is cycle-safe and naturally supports shared/diamond paths.
    """
    vulnerable_nodes: set[Hashable] = set()
    for match in vulnerability_matches:
        application = _text_value(getattr(match, "application", None) or match.get("application"))
        library = _text_value(getattr(match, "library", None) or match.get("library"))
        version = _text_value(getattr(match, "version", None) or match.get("version"))
        node = _dependency_node(application, library, version)
        if node in graph:
            graph.nodes[node]["risk"] = getattr(match, "severity", None) or match.get("severity") or "Unknown"
            graph.nodes[node]["vulnerable"] = True
            vulnerable_nodes.add(node)

    for node in vulnerable_nodes:
        severity = graph.nodes[node].get("risk") or "Unknown"
        for ancestor in nx.ancestors(graph, node):
            graph.nodes[ancestor]["inherited_risk"] = True
            graph.nodes[ancestor]["risk"] = severity
            graph.nodes[ancestor]["vulnerable"] = True


def _parse_transitive_dependencies(value: Any) -> list[tuple[str, str]]:
    """Parse a transitive dependency list into library/version pairs."""
    if value is None:
        return []
    text = _text_value(value)
    if not text:
        return []
    children: list[tuple[str, str]] = []
    for chunk in re.split(r"[;,]", text):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":", 1)
        library = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""
        if library:
            children.append((library, version))
    return children


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


def _normalize_library_name(value: Any) -> str:
    """Normalize library names for stable graph and matching operations."""
    return re.sub(r"[^a-z0-9]+", "", _text_value(value).casefold())


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
