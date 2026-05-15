"""Capability graph export for AgentBOM."""

from __future__ import annotations


def build_capability_graph(
    providers: list[dict[str, str]],
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    mcp_servers: list[dict[str, object]],
    capabilities: list[dict[str, str]],
    reachable_capabilities: list[dict[str, str]],
) -> dict[str, list[dict[str, str]]]:
    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    parsed_mcp_servers = _parsed_mcp_servers(mcp_servers)

    for provider in providers:
        _append_unique(nodes, _node("provider", provider["name"]))
    for model in models:
        _append_unique(nodes, _node("model", model["name"]))
    for framework in frameworks:
        _append_unique(nodes, _node("framework", framework["name"]))
    for server in parsed_mcp_servers:
        _append_unique(nodes, _node("mcp_server", str(server["name"])))
        _append_unique(nodes, _node("capability", "mcp_tool_invocation"))
    for capability in capabilities:
        _append_unique(nodes, _node("capability", capability["name"]))
    for reachable in reachable_capabilities:
        _append_unique(nodes, _node("capability", reachable["capability"]))
    for server in parsed_mcp_servers:
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            continue
        for category in categories:
            _append_unique(nodes, _node("mcp_risk", str(category)))

    _add_provider_edges(edges, providers, models)
    _add_reachability_edges(edges, models, frameworks, reachable_capabilities)
    _add_mcp_edges(edges, parsed_mcp_servers)

    return {
        "nodes": sorted(nodes, key=lambda item: (item["type"], item["id"])),
        "edges": sorted(edges, key=lambda item: (item["source"], item["target"], item["type"])),
    }


def _add_provider_edges(
    edges: list[dict[str, str]],
    providers: list[dict[str, str]],
    models: list[dict[str, str]],
) -> None:
    for model in models:
        matches = [provider for provider in providers if provider["path"] == model["source_file"]]
        if not matches and len(providers) == 1:
            matches = providers
        for provider in matches:
            _append_unique(
                edges,
                _edge(
                    _node_id("model", model["name"]),
                    _node_id("provider", provider["name"]),
                    "uses",
                ),
            )


def _add_reachability_edges(
    edges: list[dict[str, str]],
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    reachable_capabilities: list[dict[str, str]],
) -> None:
    model_names = {model["name"] for model in models}
    framework_names = {framework["name"] for framework in frameworks}
    for reachable in reachable_capabilities:
        actor = reachable["reachable_from"]
        capability_id = _node_id("capability", reachable["capability"])
        if actor in model_names:
            _append_unique(edges, _edge(_node_id("model", actor), capability_id, "reaches"))
        if actor in framework_names:
            framework_id = _node_id("framework", actor)
            _append_unique(edges, _edge(framework_id, capability_id, "enables"))
            _append_unique(edges, _edge(framework_id, capability_id, "reaches"))


def _add_mcp_edges(
    edges: list[dict[str, str]],
    mcp_servers: list[dict[str, object]],
) -> None:
    for server in mcp_servers:
        server_id = _node_id("mcp_server", str(server["name"]))
        _append_unique(
            edges,
            _edge(server_id, _node_id("capability", "mcp_tool_invocation"), "exposes"),
        )
        categories = server.get("risk_categories", [])
        if not isinstance(categories, list):
            continue
        for category in categories:
            _append_unique(
                edges,
                _edge(server_id, _node_id("mcp_risk", str(category)), "risk"),
            )


def _parsed_mcp_servers(
    mcp_servers: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [server for server in mcp_servers if server.get("kind") == "server"]


def _node(node_type: str, name: str) -> dict[str, str]:
    return {"id": _node_id(node_type, name), "type": node_type, "name": name}


def _node_id(node_type: str, name: str) -> str:
    return f"{node_type}:{name}"


def _edge(source: str, target: str, edge_type: str) -> dict[str, str]:
    return {"source": source, "target": target, "type": edge_type}


def _append_unique(items: list[dict[str, str]], item: dict[str, str]) -> None:
    if item not in items:
        items.append(item)
