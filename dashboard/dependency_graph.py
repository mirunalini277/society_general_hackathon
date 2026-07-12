"""Expandable dependency graph visualization embedded in the vulnerability page."""

from __future__ import annotations

import json
import logging
from typing import Any

import streamlit as st
from streamlit.components.v1 import html as component_html

from dashboard.shared import application_selector
from modules.graph_builder import get_application_subgraph, get_direct_dependencies

try:
    from pyvis.network import Network
except Exception as exc:  # pragma: no cover
    Network = None  # type: ignore[assignment]
    _PYVIS_IMPORT_ERROR = exc
else:
    _PYVIS_IMPORT_ERROR = None

LOGGER = logging.getLogger(__name__)


def render(context: Any, application_name: str | None = None, embedded: bool = False) -> None:
    """Render an expandable dependency graph for one application investigation."""
    if embedded:
        selected_application = application_name
    else:
        st.markdown("<div class='page-kicker'>Dependency topology</div>", unsafe_allow_html=True)
        st.title("Dependency graph")
        selected_application = application_selector(context, key="graph_application_scope")

    try:
        graph = _graph_from_context(context)
    except Exception as exc:
        LOGGER.exception("Unable to read dependency graph from the render context.")
        st.error(f"Unable to render the dependency graph: {exc}")
        return

    if graph is None or graph.number_of_nodes() == 0:
        st.info("Run an analysis to generate the dependency graph.")
        return

    if selected_application is None:
        st.info("Select an application to inspect its dependency graph.")
        return

    app_graph = get_application_subgraph(graph, selected_application)
    if app_graph.number_of_nodes() == 0:
        st.info(f"No dependency graph is available for {selected_application}.")
        return

    _enrich_graph_for_investigation(app_graph, context)
    initial_nodes = _initial_visible_nodes(app_graph, selected_application)
    payload = _build_graph_payload(app_graph, initial_nodes)

    control_cols = st.columns((4, 1))
    with control_cols[0]:
        graph_query = st.text_input(
            "Search node",
            placeholder="Filter or highlight by library name",
            key=f"graph_search_{selected_application}_{embedded}",
            label_visibility="collapsed",
        )
    with control_cols[1]:
        if st.button("Reset view", key=f"graph_reset_{selected_application}_{embedded}", use_container_width=True):
            st.session_state.pop(f"graph_expanded_{selected_application}", None)
            st.rerun()

    if Network is None:
        st.error("PyVis is required to render the dependency graph.")
        return

    try:
        html_content = _build_expandable_graph_html(payload, graph_query or "")
    except Exception as exc:
        LOGGER.exception("Failed to build dependency graph HTML.")
        st.error(f"Unable to build the dependency graph view: {exc}")
        return

    component_html(html_content, height=820, scrolling=False)
    st.markdown(
        "<div class='graph-legend'>"
        "<span><i class='legend-dot legend-app'></i> Application</span>"
        "<span><i class='legend-dot legend-direct'></i> Direct dependency</span>"
        "<span><i class='legend-dot legend-transitive'></i> Transitive dependency</span>"
        "<span><i class='legend-dot legend-vulnerable'></i> Vulnerable</span>"
        "<span class='legend-hint'>Click a node to expand transitive dependencies · Double-click to highlight path</span>"
        "</div>",
        unsafe_allow_html=True,
    )


def _graph_from_context(context: Any) -> Any | None:
    if isinstance(context, dict):
        return context.get("graph")
    return getattr(context, "graph", None)


def _enrich_graph_for_investigation(graph: Any, context: Any) -> None:
    vulnerabilities: dict[tuple[Any, Any, Any], list[Any]] = {}
    for finding in getattr(context, "vulnerability_findings", []):
        vulnerabilities.setdefault((finding.application, finding.library, finding.version), []).append(finding)
    maintenance = {(item.application, item.library, item.version): item for item in getattr(context, "maintenance_findings", [])}
    for _, attributes in graph.nodes(data=True):
        key = (attributes.get("application"), attributes.get("library"), attributes.get("version"))
        findings = vulnerabilities.get(key, [])
        attributes["ui_cves"] = ", ".join(item.cve_id for item in findings) or "No matched CVE"
        attributes["ui_vulnerability_count"] = len(findings)
        attributes["ui_patch"] = "Available" if any(item.patch_available for item in findings) else ("Unavailable" if findings else "Not applicable")
        attributes["ui_vulnerable"] = bool(findings)
        attributes["ui_maintenance"] = getattr(maintenance.get(key), "maintenance_status", "Not available")


def _initial_visible_nodes(graph: Any, application: str) -> set[str]:
    """Expose the complete backend subgraph on first render.

    Earlier versions exposed only direct dependencies and required a click on
    their parent before any transitive node could be seen.  That made valid
    backend relationships appear to be missing.  The client still expands and
    collapses branches interactively; this only makes the existing graph data
    visible by default.
    """
    return {str(node) for node in graph.nodes}


def _build_graph_payload(graph: Any, initial_visible: set[str]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    for node, attributes in graph.nodes(data=True):
        node_id = str(node)
        nodes.append(
            {
                "id": node_id,
                "label": _node_label(attributes),
                "library": str(attributes.get("library") or "N/A"),
                "version": str(attributes.get("version") or "N/A"),
                "dependency_type": str(attributes.get("dependency_type") or "N/A"),
                "license": str(attributes.get("license") or "N/A"),
                "maintenance": str(attributes.get("ui_maintenance", "Not available")),
                "cves": str(attributes.get("ui_cves", "No matched CVE")),
                "vulnerability_count": int(attributes.get("ui_vulnerability_count", 0)),
                "patch": str(attributes.get("ui_patch", "Not applicable")),
                "color": _node_color(attributes),
                "size": 30 if attributes.get("node_kind") == "application" else 18,
                "shape": "dot" if attributes.get("node_kind") == "application" else "ellipse",
                "kind": str(attributes.get("node_kind", "dependency")),
                "hidden": node_id not in initial_visible,
            }
        )
    for source, target, _ in graph.edges(data=True):
        edges.append({"from": str(source), "to": str(target)})
    children: dict[str, list[str]] = {}
    for edge in edges:
        children.setdefault(edge["from"], []).append(edge["to"])

    roots = [node["id"] for node in nodes if node["kind"] == "application"]
    levels = {root: 0 for root in roots}
    queue = list(roots)
    while queue:
        parent = queue.pop(0)
        for child in children.get(parent, []):
            level = levels[parent] + 1
            if child not in levels or level < levels[child]:
                levels[child] = level
                queue.append(child)
    for node in nodes:
        if node["id"] not in levels:
            node["level"] = 1 if node["dependency_type"] == "Direct" else 2
        else:
            node["level"] = levels[node["id"]]
    initially_expanded = sorted(node_id for node_id, child_ids in children.items() if child_ids)
    return {
        "nodes": nodes,
        "edges": edges,
        "children": children,
        "initial_visible": sorted(initial_visible),
        "initially_expanded": initially_expanded,
    }


def _build_expandable_graph_html(payload: dict[str, Any], search_query: str) -> str:
    network = Network(height="700px", width="100%", directed=True, bgcolor="#0b0d10", font_color="#e5e7eb", heading="")
    network.set_options(
        json.dumps(
            {
                "interaction": {"hover": True, "navigationButtons": False, "keyboard": True, "dragView": True, "zoomView": True},
                "layout": {"hierarchical": {"enabled": False}},
                "physics": {
                    "enabled": True,
                    "barnesHut": {
                        "gravitationalConstant": -3600,
                        "centralGravity": 0.08,
                        "springLength": 155,
                        "springConstant": 0.045,
                        "damping": 0.12,
                        "avoidOverlap": 0.55,
                    },
                    "stabilization": {"enabled": True, "iterations": 160},
                },
                "edges": {"color": {"color": "#475569", "highlight": "#93C5FD"}, "smooth": False, "width": 1.5},
            }
        )
    )
    html_content = network.generate_html(notebook=False)
    payload_json = json.dumps(payload).replace("</", "<\\/")
    search_json = json.dumps(search_query).replace("</", "<\\/")

    html_content = html_content.replace(
        "</head>",
        """
        <style>
            body { margin: 0; background: #0b0d10; }
            #mynetwork { background: #12161b; border: 1px solid #2a313a; border-radius: 8px; }
            .graph-shell { display: flex; flex-direction: column; gap: 10px; }
            .graph-toolbar { display: flex; gap: 8px; flex-wrap: wrap; }
            .graph-btn { background: #171c22; border: 1px solid #2a313a; border-radius: 7px; color: #e5e7eb; cursor: pointer; font: 600 12px Inter, Arial, sans-serif; padding: 8px 12px; }
            .graph-btn:hover { background: #1f2630; border-color: #3a444f; }
            .graph-details { background: #171c22; border: 1px solid #2a313a; border-radius: 8px; color: #f3f4f6; font-family: Inter, Arial, sans-serif; padding: 14px 16px; }
            .graph-details-title { font-size: .92rem; font-weight: 700; margin-bottom: 8px; }
            .graph-details-grid { display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
            .graph-detail-item { background: rgba(248,250,252,.04); border: 1px solid rgba(148,163,184,.16); border-radius: 8px; padding: 8px 10px; }
            .graph-detail-label { color: #94a3b8; display: block; font-size: .68rem; letter-spacing: .08em; margin-bottom: 4px; text-transform: uppercase; }
            .graph-detail-value { color: #f8fafc; font-size: .88rem; font-weight: 600; word-break: break-word; }
        </style>
        </head>""",
        1,
    )
    html_content = html_content.replace(
        '<div id="mynetwork"></div>',
        """
        <div class="graph-shell">
          <div class="graph-toolbar">
            <button class="graph-btn" type="button" onclick="graphZoomIn()">Zoom in</button>
            <button class="graph-btn" type="button" onclick="graphZoomOut()">Zoom out</button>
            <button class="graph-btn" type="button" onclick="graphFit()">Fit</button>
            <button class="graph-btn" type="button" onclick="graphReset()">Reset</button>
            <button class="graph-btn" type="button" onclick="graphSearch()">Search</button>
            <button class="graph-btn" type="button" onclick="graphClearHighlight()">Clear highlight</button>
          </div>
          <div id="graph-details" class="graph-details">Click a node to expand dependencies or inspect metadata.</div>
          <div id="mynetwork"></div>
        </div>""",
        1,
    )
    html_content = html_content.replace(
        "</body>",
        f"""
        <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const payload = {payload_json};
            const externalSearch = {search_json};
            const detailsElement = document.getElementById('graph-details');
            if (typeof network === 'undefined') return;

            const nodeIndex = Object.fromEntries(payload.nodes.map((node) => [node.id, node]));
            const visible = new Set(payload.initial_visible);
            const expanded = new Set(payload.initially_expanded);
            let highlighted = new Set();
            let selectedPath = [];

            const visibleNodes = () => payload.nodes
                .filter((node) => visible.has(node.id))
                .map((node) => ({{
                    id: node.id,
                    label: node.label,
                    color: highlighted.has(node.id) ? '#FBBF24' : node.color,
                    size: node.size,
                    shape: node.shape,
                    fixed: node.kind === 'application' ? {{ x: true, y: true }} : false,
                    x: node.kind === 'application' ? 0 : undefined,
                    y: node.kind === 'application' ? 0 : undefined,
                    font: {{ color: '#f8fafc', face: 'Inter', size: 14 }},
                    borderWidth: highlighted.has(node.id) ? 3 : 2,
                }}));

            const visibleEdges = () => payload.edges
                .filter((edge) => visible.has(edge.from) && visible.has(edge.to))
                .map((edge) => ({{
                    from: edge.from,
                    to: edge.to,
                    color: selectedPath.includes(edge.from) && selectedPath.includes(edge.to) ? '#FBBF24' : '#64748B',
                    width: selectedPath.includes(edge.from) && selectedPath.includes(edge.to) ? 2.4 : 1.5,
                }}));

            const nodeData = new vis.DataSet();
            const edgeData = new vis.DataSet();
            const edgeId = (edge) => edge.from + '→' + edge.to;
            let graphInitialized = false;
            const renderGraph = (reset = false) => {{
                if (reset) {{
                    nodeData.clear();
                    edgeData.clear();
                }}
                const nextNodes = visibleNodes();
                const nextEdges = visibleEdges().map((edge) => ({{ ...edge, id: edgeId(edge) }}));
                const nextNodeIds = new Set(nextNodes.map((node) => node.id));
                const nextEdgeIds = new Set(nextEdges.map((edge) => edge.id));
                nodeData.getIds().filter((id) => !nextNodeIds.has(id)).forEach((id) => nodeData.remove(id));
                edgeData.getIds().filter((id) => !nextEdgeIds.has(id)).forEach((id) => edgeData.remove(id));
                nextNodes.forEach((node) => nodeData.update(node));
                nextEdges.forEach((edge) => edgeData.update(edge));
                if (!graphInitialized) {{
                    network.setData({{ nodes: nodeData, edges: edgeData }});
                    network.setOptions({{
                        layout: {{ hierarchical: {{ enabled: false }} }},
                        physics: {{
                            enabled: true,
                            barnesHut: {{ gravitationalConstant: -3600, centralGravity: 0.08, springLength: 155, springConstant: 0.045, damping: 0.12, avoidOverlap: 0.55 }},
                        }},
                    }});
                    graphInitialized = true;
                }}
                network.stabilize(45);
            }};

            const escapeHtml = (value) => String(value)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

            const updateDetails = (nodeId) => {{
                const metadata = nodeIndex[nodeId];
                if (!metadata) return;
                detailsElement.innerHTML = [
                    '<div class="graph-details-title">' + escapeHtml(metadata.label) + '</div>',
                    '<div class="graph-details-grid">',
                    detail('Library', metadata.library),
                    detail('Version', metadata.version),
                    detail('Dependency Type', metadata.dependency_type),
                    detail('License', metadata.license),
                    detail('Maintenance', metadata.maintenance),
                    detail('Vulnerability Count', metadata.vulnerability_count),
                    detail('CVEs', metadata.cves),
                    detail('Patch', metadata.patch),
                    '</div>'
                ].join('');
            }};

            const detail = (label, value) =>
                '<div class="graph-detail-item"><span class="graph-detail-label">' + label +
                '</span><span class="graph-detail-value">' + escapeHtml(value) + '</span></div>';

            const descendantsOf = (nodeId) => {{
                const descendants = new Set();
                const pending = [...(payload.children[nodeId] || [])];
                while (pending.length) {{
                    const child = pending.pop();
                    if (descendants.has(child)) continue;
                    descendants.add(child);
                    pending.push(...(payload.children[child] || []));
                }}
                return descendants;
            }};

            const expandNode = (nodeId) => {{
                const children = payload.children[nodeId] || [];
                let added = false;
                children.forEach((childId) => {{
                    if (!visible.has(childId)) {{
                        visible.add(childId);
                        added = true;
                    }}
                }});
                if (added) renderGraph();
                expanded.add(nodeId);
            }};

            const collapseNode = (nodeId) => {{
                const branch = descendantsOf(nodeId);
                const parents = {{}};
                payload.edges.forEach((edge) => {{
                    (parents[edge.to] ||= []).push(edge.from);
                }});
                branch.forEach((child) => {{
                    const remainsReachable = (parents[child] || []).some((parent) => visible.has(parent) && !branch.has(parent) && parent !== nodeId);
                    if (!remainsReachable) visible.delete(child);
                    expanded.delete(child);
                }});
                expanded.delete(nodeId);
                renderGraph();
            }};

            const findPathToRoot = (nodeId) => {{
                const parents = {{}};
                payload.edges.forEach((edge) => {{ parents[edge.to] = edge.from; }});
                const path = [nodeId];
                let current = nodeId;
                while (parents[current]) {{
                    current = parents[current];
                    path.unshift(current);
                }}
                return path;
            }};

            network.on('click', function(params) {{
                if (!params.nodes.length) return;
                const nodeId = params.nodes[0];
                updateDetails(nodeId);
                if (expanded.has(nodeId)) collapseNode(nodeId);
                else expandNode(nodeId);
            }});

            network.on('hoverNode', function(params) {{
                updateDetails(params.node);
            }});

            network.on('doubleClick', function(params) {{
                if (!params.nodes.length) return;
                selectedPath = findPathToRoot(params.nodes[0]);
                highlighted = new Set(selectedPath);
                renderGraph(true);
                updateDetails(params.nodes[0]);
            }});

            window.graphZoomIn = () => network.moveTo({{ scale: network.getScale() * 1.2 }});
            window.graphZoomOut = () => network.moveTo({{ scale: network.getScale() * 0.84 }});
            window.graphFit = () => network.fit({{ animation: true }});
            window.graphReset = () => {{
                visible.clear();
                payload.initial_visible.forEach((nodeId) => visible.add(nodeId));
                expanded.clear();
                highlighted = new Set();
                selectedPath = [];
                renderGraph();
                detailsElement.textContent = 'Click a node to expand dependencies or inspect metadata.';
            }};
            window.graphSearch = () => {{
                const term = (externalSearch || '').trim().toLowerCase();
                if (!term) return;
                const matches = payload.nodes
                    .filter((node) => node.library.toLowerCase().includes(term) || node.label.toLowerCase().includes(term))
                    .map((node) => node.id);
                if (!matches.length) return;
                matches.forEach((nodeId) => {{
                    visible.add(nodeId);
                    findPathToRoot(nodeId).forEach((pathNode) => visible.add(pathNode));
                }});
                highlighted = new Set(matches);
                renderGraph();
                network.selectNodes([matches[0]]);
                network.focus(matches[0], {{ scale: 1.1, animation: true }});
                updateDetails(matches[0]);
            }};
            window.graphClearHighlight = () => {{
                highlighted = new Set();
                selectedPath = [];
                renderGraph();
            }};

            renderGraph();
            if (externalSearch) window.graphSearch();
        }});
        </script>
        </body>""",
        1,
    )
    return html_content


def _node_label(attributes: dict[str, Any]) -> str:
    if attributes.get("node_kind") == "application":
        return str(attributes.get("application") or "Application")
    return str(attributes.get("library") or "Dependency")


def _node_color(attributes: dict[str, Any]) -> str:
    if attributes.get("node_kind") == "application":
        return "#38BDF8"
    if attributes.get("ui_vulnerable"):
        return "#F87171"
    dependency_type = str(attributes.get("dependency_type", "")).casefold()
    if dependency_type == "direct":
        return "#60A5FA"
    return "#A78BFA"
