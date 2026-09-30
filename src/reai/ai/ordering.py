from __future__ import annotations

import json
from collections import defaultdict, deque


def select_target_addresses(target_rows: list[dict], *, max_functions: int | None = None) -> list[str]:
    rows = sorted(target_rows, key=_target_sort_key)
    addresses = [row["address"] for row in rows]
    if max_functions is not None:
        return addresses[:max_functions]
    return addresses


def include_target_callees(seed_addresses: list[str], all_target_addresses: list[str], calls: list[dict]) -> list[str]:
    target_set = set(all_target_addresses)
    selected = set(seed_addresses)
    pending = list(seed_addresses)

    callees_by_caller: dict[str, set[str]] = defaultdict(set)
    for call in calls:
        caller = call["caller"]
        callee = call["callee"]
        if caller in target_set and callee in target_set:
            callees_by_caller[caller].add(callee)

    while pending:
        caller = pending.pop()
        for callee in sorted(callees_by_caller.get(caller, set())):
            if callee not in selected:
                selected.add(callee)
                pending.append(callee)

    return [address for address in all_target_addresses if address in selected]


def _target_sort_key(row: dict) -> tuple[int, int | str]:
    has_pseudocode = row.get("decompilation_status") == "success" and bool(row.get("pseudocode_path"))
    try:
        address: int | str = int(str(row["address"]), 16)
    except (KeyError, TypeError, ValueError):
        address = str(row.get("address") or "")
    return (0 if has_pseudocode else 1, address)


def build_bottom_up_groups(
    target_addresses: list[str],
    calls: list[dict],
    components: list[dict],
) -> list[list[str]]:
    targets = set(target_addresses)
    component_by_node: dict[str, int] = {}
    nodes_by_component: dict[int, set[str]] = {}

    for component in components:
        scc_id = int(component["scc_id"])
        nodes = set(json.loads(component["nodes_json"]))
        relevant = nodes & targets
        if not relevant:
            continue
        nodes_by_component[scc_id] = relevant
        for node in relevant:
            component_by_node[node] = scc_id

    next_component_id = max(nodes_by_component.keys(), default=-1) + 1
    for address in targets:
        if address not in component_by_node:
            component_by_node[address] = next_component_id
            nodes_by_component[next_component_id] = {address}
            next_component_id += 1

    component_edges: dict[int, set[int]] = defaultdict(set)
    indegree: dict[int, int] = {component: 0 for component in nodes_by_component}
    for call in calls:
        caller = call["caller"]
        callee = call["callee"]
        if caller not in targets or callee not in targets:
            continue
        caller_component = component_by_node[caller]
        callee_component = component_by_node[callee]
        if caller_component == callee_component:
            continue
        # Dependency direction is callee -> caller, so leaves are analyzed first.
        if caller_component not in component_edges[callee_component]:
            component_edges[callee_component].add(caller_component)
            indegree[caller_component] += 1

    queue = deque(sorted(component for component, degree in indegree.items() if degree == 0))
    ordered_layers: list[list[int]] = []
    while queue:
        layer = sorted(queue)
        queue.clear()
        ordered_layers.append(layer)
        for component in layer:
            for parent in sorted(component_edges.get(component, set())):
                indegree[parent] -= 1
                if indegree[parent] == 0:
                    queue.append(parent)

    ordered_components = {component for layer in ordered_layers for component in layer}
    if len(ordered_components) != len(nodes_by_component):
        remaining = sorted(set(nodes_by_component) - ordered_components)
        ordered_layers.append(remaining)

    return [
        sorted(node for component in layer for node in nodes_by_component[component])
        for layer in ordered_layers
    ]
