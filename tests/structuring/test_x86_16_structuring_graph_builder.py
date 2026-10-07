import networkx as nx

from inertia.structuring.structuring_graph_builder import (
    build_region_graph,
    resolve_clinic_from_codegen,
)


class _Node:
    def __init__(self, addr, statements=None):
        self.addr = addr
        self.statements = tuple(statements or ())


class _Stmt:
    def __init__(self, ins_addr=None, addr=None, tags=None):
        self.ins_addr = ins_addr
        self.addr = addr
        self.tags = dict(tags or {})


class _Clinic:
    def __init__(self, graph):
        self.graph = graph


class _CFunc:
    def __init__(self, addr):
        self.addr = addr


class _Functions:
    def __init__(self, func):
        self._func = func

    def function(self, addr, create=False):
        del create
        if addr == self._func.addr:
            return self._func
        return None


class _Project:
    def __init__(self, func):
        self.kb = type("_KB", (), {"functions": _Functions(func)})()


class _Func:
    def __init__(self, addr, clinic):
        self.addr = addr
        self._clinic = clinic


class _Codegen:
    def __init__(self, addr, clinic=None, project=None):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = project


def _make_graph():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, b)
    graph.add_edge(b, c)
    return graph


def test_build_region_graph_uses_direct_clinic():
    clinic = _Clinic(_make_graph())
    codegen = _Codegen(0x1000, clinic=clinic)

    result = build_region_graph(codegen)

    assert result.graph is not None
    assert result.entry is not None
    assert result.entry.region_id == 0x1000
    assert len(result.graph.nodes) == 3


def test_build_region_graph_records_clinic_statement_address_set():
    graph = nx.DiGraph()
    a = _Node(
        0x1000,
        statements=(
            _Stmt(ins_addr=0x1000),
            _Stmt(tags={"ins_addr": 0x1002}),
            _Stmt(addr=0x1004),
            _Stmt(),
        ),
    )
    graph.add_node(a)
    codegen = _Codegen(0x1000, clinic=_Clinic(graph))

    result = build_region_graph(codegen)

    assert result.graph is not None
    [region] = list(result.graph.nodes)
    assert region.metadata["region_statement_ins_addrs"] == (0x1000, 0x1002, 0x1004)
    assert region.metadata["region_statement_span_source"] == "clinic_node_statements"


def test_build_region_graph_records_clinic_statement_provenance_keys():
    graph = nx.DiGraph()
    a = _Node(
        0x1000,
        statements=(
            _Stmt(tags={"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 1}),
            _Stmt(tags={"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 2}),
            _Stmt(tags={"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 1}),
        ),
    )
    graph.add_node(a)
    codegen = _Codegen(0x1000, clinic=_Clinic(graph))

    result = build_region_graph(codegen)

    assert result.graph is not None
    [region] = list(result.graph.nodes)
    assert region.metadata["region_statement_provenance_keys"] == (
        ("vex", 0x1000, 1),
        ("vex", 0x1000, 2),
    )
    assert region.metadata["region_statement_span_source"] == "clinic_node_statements"


def test_resolve_clinic_from_project_fallback():
    clinic = _Clinic(_make_graph())
    func = _Func(0x1000, clinic)
    project = _Project(func)
    codegen = _Codegen(0x1000, clinic=None, project=project)

    resolved = resolve_clinic_from_codegen(codegen)
    result = build_region_graph(codegen)

    assert resolved is clinic
    assert result.graph is not None
    assert result.entry is not None
    assert result.entry.region_id == 0x1000


def test_build_region_graph_returns_empty_when_no_clinic():
    codegen = _Codegen(0x1000, clinic=None, project=None)

    result = build_region_graph(codegen)

    assert result.graph is None
    assert result.entry is None
