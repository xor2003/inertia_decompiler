"""Preserve the native function's authenticated CFG during condition lowering."""
import io
from types import SimpleNamespace

import angr
import pytest

import inertia.frontend.x86_16.public_api  # noqa: F401
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.pipeline.errors import PipelineHardError
from inertia.structuring.condition_materialization import condition_chain_successors_8616

pytestmark = pytest.mark.decompiler


def _project() -> angr.Project:
    """Load a branch whose two paths share one return, without a DOS runner."""
    return angr.Project(
        io.BytesIO(bytes.fromhex('3bc37c0231c0c3')),
        main_opts={'backend':'blob','arch':Arch86_16(),'base_addr':0x1000,
                   'entry_point':0x1000}, auto_load_libs=False,
    )


@pytest.mark.parametrize('stale_default', [False, True])
def test_condition_cfg_uses_authenticated_private_function(stale_default):
    """A missing or same-address default function cannot erase branch edges."""
    project = _project()
    kb = angr.KnowledgeBase(project)
    function = kb.functions.function(addr=0x1000, create=True)
    nodes = []
    for addr, size in ((0x1000,4),(0x1004,2),(0x1006,1)):
        node = project.factory.block(addr,size=size).codenode
        function._register_node(True,node)
        nodes.append(node)
    function.transition_graph.add_edges_from(((nodes[0],nodes[1]),
                                              (nodes[0],nodes[2]),
                                              (nodes[1],nodes[2])))
    if stale_default:
        project.kb.functions.function(addr=0x1000,create=True)
    codegen = SimpleNamespace(_func=function,cfunc=SimpleNamespace(addr=0x1000))

    successors = condition_chain_successors_8616(project,codegen)

    assert {key:frozenset(value) for key,value in successors.items()} == {
        0x1000:frozenset((0x1004,0x1006)),
        0x1004:frozenset((0x1006,)), 0x1006:frozenset(),
    }


def test_foreign_condition_cfg_owner_is_rejected():
    """A same-address foreign CFG cannot authorize branch orientation."""
    project = _project()
    foreign = _project()
    function = foreign.kb.functions.function(addr=0x1000,create=True)
    codegen = SimpleNamespace(_func=function,cfunc=SimpleNamespace(addr=0x1000))

    with pytest.raises(PipelineHardError,match='different project'):
        condition_chain_successors_8616(project,codegen)
