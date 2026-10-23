"""Keep typed condition evidence attached to its recovered function owner."""

import io
from types import SimpleNamespace

import angr
import pytest

import inertia.frontend.x86_16.public_api  # noqa: F401
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics import register_source_block_inventory
from inertia.structuring.condition_register_expression import condition_register_expression_8616

pytestmark = pytest.mark.decompiler


def _project() -> angr.Project:
    """Decode a signed compare/branch near function without DOS execution."""
    return angr.Project(
        io.BytesIO(bytes.fromhex("3bc37c0231c0c3")),  # cmp ax,bx; jl +2; xor ax,ax; ret
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000,
                   "entry_point": 0x1000},
        auto_load_libs=False,
    )


def _register_branch_blocks(project: angr.Project, function: object) -> None:
    """Register the branch-split block inventory on the function's own KB."""
    for addr, size in ((0x1000, 4), (0x1004, 2), (0x1006, 1)):
        function._register_node(True, project.factory.block(addr, size=size).codenode)


@pytest.mark.parametrize("stale_default", [False, True])
def test_condition_transfer_uses_retained_analysis_function(stale_default):
    """An empty or same-address default KB cannot discard the recovery owner."""
    project = _project()
    analysis_kb = angr.KnowledgeBase(project)
    function = analysis_kb.functions.function(addr=0x1000, create=True)
    _register_branch_blocks(project, function)
    if stale_default:
        project.kb.functions.function(addr=0x1000, create=True)
    codegen = SimpleNamespace(
        project=project, _func=function,
        cfunc=SimpleNamespace(addr=0x1000),
    )

    transferred = transfer_typed_conditions_to_codegen_8616(project, 0x1000, codegen)

    assert transferred == 1
    [condition] = codegen._inertia_typed_conditions
    assert condition.op == "slt"
    assert condition.lhs.name == "ax"
    assert condition.rhs.name == "bx"
    assert condition.src_insn == 0x1002
    assert condition.taken_target == 0x1006
    assert condition.fallthrough_target == 0x1004
    stats = codegen._inertia_condition_ownership_stats
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1


def test_address_only_codegen_still_uses_default_kb_function():
    """Codegen without a retained owner keeps the default project lookup."""
    project = _project()
    function = project.kb.functions.function(addr=0x1000, create=True)
    _register_branch_blocks(project, function)
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x1000),
    )

    transferred = transfer_typed_conditions_to_codegen_8616(project, 0x1000, codegen)

    assert transferred == 1
    [condition] = codegen._inertia_typed_conditions
    assert condition.op == "slt"


def test_foreign_retained_function_is_rejected():
    """A same-address function from a foreign project cannot supply conditions."""
    project = _project()
    foreign = _project()
    function = foreign.kb.functions.function(addr=0x1000, create=True)
    codegen = SimpleNamespace(
        project=project, _func=function,
        cfunc=SimpleNamespace(addr=0x1000),
    )

    with pytest.raises(PipelineHardError, match="different project"):
        transfer_typed_conditions_to_codegen_8616(project, 0x1000, codegen)


def test_requested_address_cannot_replace_retained_owner():
    """A conflicting transfer request cannot fall back to a different function."""
    project = _project()
    analysis_kb = angr.KnowledgeBase(project)
    function = analysis_kb.functions.function(addr=0x1000, create=True)
    _register_branch_blocks(project, function)
    project.kb.functions.function(addr=0x1004, create=True)
    codegen = SimpleNamespace(
        project=project, _func=function,
        cfunc=SimpleNamespace(addr=0x1000),
    )

    with pytest.raises(PipelineHardError, match="requested function address"):
        transfer_typed_conditions_to_codegen_8616(project, 0x1004, codegen)


@pytest.mark.parametrize("stale_default", [False, True])
def test_register_binding_reads_retained_function_inventory(monkeypatch, stale_default):
    """Register binding and branch transfer must use the same function owner."""
    project = _project()
    analysis_kb = angr.KnowledgeBase(project)
    function = analysis_kb.functions.function(addr=0x1000, create=True)
    _register_branch_blocks(project, function)
    if stale_default:
        project.kb.functions.function(addr=0x1000, create=True)
    codegen = SimpleNamespace(_func=function, cfunc=SimpleNamespace(addr=0x1000))
    observed = []
    collect = register_source_block_inventory.collect_register_source_block_inventory_8616

    def record_owner(owner):
        observed.append(owner)
        return collect(owner)

    monkeypatch.setattr(
        register_source_block_inventory, "collect_register_source_block_inventory_8616", record_owner,
    )
    # This function has no AX definition: owner selection must not turn its
    # incoming AX into an invented C definition, even with a candidate tag.
    result = condition_register_expression_8616(
        project, codegen, {(0x1000, "ax", 2): object()},
        instruction_addr=0x1000, register="ax", size=2,
    )
    assert observed == [function]
    assert result is None


def test_register_binding_rejects_foreign_retained_function():
    """A foreign owner must fail before its register facts can be consumed."""
    project, foreign = _project(), _project()
    function = foreign.kb.functions.function(addr=0x1000, create=True)
    codegen = SimpleNamespace(_func=function, cfunc=SimpleNamespace(addr=0x1000))
    with pytest.raises(PipelineHardError, match="different project"):
        condition_register_expression_8616(
            project, codegen, {}, instruction_addr=0x1000, register="ax", size=2,
        )
