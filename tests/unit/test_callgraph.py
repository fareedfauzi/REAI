from reai.extraction.models import CallEdge, FunctionRecord
from reai.graph.callgraph import build_call_graph, strongly_connected_components


def _func(address: int, name: str) -> FunctionRecord:
    return FunctionRecord(address=address, end_address=address + 0x10, name=name, size=0x10)


def test_scc_detection_marks_recursive_component():
    components = strongly_connected_components(
        [0x1000, 0x2000, 0x3000],
        [(0x1000, 0x2000), (0x2000, 0x1000), (0x2000, 0x3000)],
    )

    assert [0x1000, 0x2000] in components
    assert [0x3000] in components


def test_build_call_graph_adds_scc_metadata():
    functions = [_func(0x1000, "sub_1000"), _func(0x2000, "sub_2000")]
    edges = [
        CallEdge(caller=0x1000, callee=0x2000),
        CallEdge(caller=0x2000, callee=0x1000),
    ]

    graph = build_call_graph(functions, edges)

    assert len(graph.edges) == 2
    assert graph.components[0].recursive is True
    assert all(node.recursive for node in graph.nodes)
    assert all(function.recursive for function in functions)
