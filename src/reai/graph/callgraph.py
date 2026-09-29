from __future__ import annotations

from collections import defaultdict

from reai.extraction.models import (
    CallEdge,
    CallGraph,
    CallGraphNode,
    FunctionRecord,
    StronglyConnectedComponent,
)


def build_call_graph(functions: list[FunctionRecord], edges: list[CallEdge]) -> CallGraph:
    function_by_address = {function.address: function for function in functions}
    components = strongly_connected_components(
        sorted(function_by_address),
        [(edge.caller, edge.callee) for edge in edges if edge.callee in function_by_address],
    )
    scc_by_node: dict[int, int] = {}
    recursive_by_node: dict[int, bool] = {}
    component_records: list[StronglyConnectedComponent] = []
    edge_pairs = {(edge.caller, edge.callee) for edge in edges}

    for scc_id, nodes in enumerate(components):
        recursive = len(nodes) > 1 or any((node, node) in edge_pairs for node in nodes)
        component_records.append(
            StronglyConnectedComponent(scc_id=scc_id, nodes=nodes, recursive=recursive)
        )
        for node in nodes:
            scc_by_node[node] = scc_id
            recursive_by_node[node] = recursive

    graph_nodes: list[CallGraphNode] = []
    for function in sorted(functions, key=lambda item: item.address):
        function.scc_id = scc_by_node.get(function.address)
        function.recursive = recursive_by_node.get(function.address, False)
        graph_nodes.append(
            CallGraphNode(
                address=function.address,
                name=function.name,
                scc_id=function.scc_id,
                recursive=function.recursive,
            )
        )

    return CallGraph(
        nodes=graph_nodes,
        edges=sorted(edges, key=lambda edge: (edge.caller, edge.callee, edge.source_address or 0)),
        components=component_records,
    )


def strongly_connected_components(nodes: list[int], edges: list[tuple[int, int]]) -> list[list[int]]:
    adjacency: dict[int, list[int]] = defaultdict(list)
    for source, target in edges:
        adjacency[source].append(target)
    for node in nodes:
        adjacency[node] = sorted(set(adjacency[node]))

    index = 0
    stack: list[int] = []
    on_stack: set[int] = set()
    indexes: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    components: list[list[int]] = []

    def visit(node: int) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for target in adjacency[node]:
            if target not in indexes:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])

        if lowlinks[node] == indexes[node]:
            component: list[int] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(sorted(component))

    for node in sorted(nodes):
        if node not in indexes:
            visit(node)

    return sorted(components, key=lambda component: component[0] if component else -1)
