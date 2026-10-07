"""Preserve rollback state and snapshot-time bindings across failed rewrites."""

from itertools import count
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunction, CStatements
from angr.knowledge_plugins.variables.variable_manager import VariableManager, VariableManagerInternal
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeShort

from inertia.cli.cli_decompilation import _DecompileRun8616
from inertia.cli.cli_rollback_snapshot_8616 import (
    PickledCfuncSnapshot8616,
    pickled_trusted_cfunc_8616,
    unpickle_trusted_cfunc_8616,
)


def _context() -> SimpleNamespace:
    """Build real angr nodes and a variable manager over a tiny loaded image."""
    project = angr.load_shellcode(b"\xc3", arch="x86")
    manager = VariableManagerInternal(VariableManager(project.kb))
    identifiers = count()
    codegen = SimpleNamespace(
        project=project, next_ident=lambda name: name,
        next_node_idx=lambda: next(identifiers),
    )
    word = SimTypeInt(False).with_arch(project.arch)
    value = CConstant(7, word, codegen=codegen)
    codegen.cfunc = CFunction(
        0, "probe", SimTypeFunction([], word).with_arch(project.arch), [],
        CStatements([value, value], codegen=codegen), {}, manager, codegen=codegen,
    )
    return SimpleNamespace(
        project=project, dec=SimpleNamespace(codegen=codegen),
        large_x86_16_function=False, block_count=1, byte_count=1,
    )


@pytest.mark.parametrize("replacement", [True, False])
def test_rollback_retains_manager_when_live_tree_is_replaced_or_missing(replacement: bool) -> None:
    """Restoration must use bindings from capture, not the failed pass's tree."""
    context = _context()
    manager = context.dec.codegen.cfunc.variable_manager.manager
    snapshot = _DecompileRun8616._snapshot_codegen_cfunc(context)
    context.dec.codegen.cfunc = _context().dec.codegen.cfunc if replacement else None
    assert _DecompileRun8616._restore_codegen_cfunc(context, snapshot)
    restored = context.dec.codegen.cfunc.variable_manager
    assert restored.manager is manager
    assert restored.types._kb is context.project.kb


def test_rollback_restores_values_types_aliases_and_independent_graphs() -> None:
    """Value/type changes cannot leak into a saved graph or later restores."""
    context = _context()
    original = context.dec.codegen.cfunc.statements.statements[0]
    snapshot = _DecompileRun8616._snapshot_codegen_cfunc(context)
    original.value = 99
    original.set_type(SimTypeShort(False).with_arch(context.project.arch))
    assert _DecompileRun8616._restore_codegen_cfunc(context, snapshot)
    first, second = context.dec.codegen.cfunc.statements.statements
    assert first is second and first is not original
    assert first.value == 7 and first.type.size == 32
    assert first.codegen is context.dec.codegen
    first.value = 123
    assert _DecompileRun8616._restore_codegen_cfunc(context, snapshot)
    restored = context.dec.codegen.cfunc.statements.statements[0]
    assert restored is not first and restored.value == 7


def test_unpicklable_state_keeps_the_existing_deepcopy_fallback() -> None:
    """An unsupported serializer must not disable the rollback guard."""
    def callback() -> None:
        """Remain intentionally local and therefore unpicklable."""
    context = _context()
    context.dec.codegen.cfunc = SimpleNamespace(statements=[7], callback=callback)
    snapshot = _DecompileRun8616._snapshot_codegen_cfunc(context)
    assert snapshot is not None
    context.dec.codegen.cfunc.statements.append(9)
    assert _DecompileRun8616._restore_codegen_cfunc(context, snapshot)
    assert context.dec.codegen.cfunc.statements == [7]
    assert context.dec.codegen.cfunc.callback is callback


def test_corrupt_serialized_snapshot_refuses_without_replacing_live_tree() -> None:
    """A damaged payload must leave the current tree intact and report failure."""
    context = _context()
    original = context.dec.codegen.cfunc
    damaged = PickledCfuncSnapshot8616(
        b"not a pickle", has_variable_manager=False,
        boundary_manager=None, boundary_type_store_kb=None,
    )
    assert not _DecompileRun8616._restore_codegen_cfunc(context, damaged)
    assert context.dec.codegen.cfunc is original


class _BrokenReducer:
    """Expose an unexpected third-party failure that must remain visible."""

    def __reduce_ex__(self, protocol: int) -> object:
        raise RuntimeError("unexpected reducer defect")


def test_unexpected_reducer_failure_propagates() -> None:
    """Only documented serialization boundary failures trigger fallback."""
    with pytest.raises(RuntimeError, match="unexpected reducer defect"):
        pickled_trusted_cfunc_8616(_BrokenReducer(), preserve_objects=())


def test_snapshot_restores_binding_without_a_live_manager() -> None:
    """The no-manager branch retains the snapshot-time type-store key."""
    kb = object()
    source = SimpleNamespace(variable_manager=SimpleNamespace(
        manager=None, types=SimpleNamespace(_kb=kb),
    ))
    snapshot = pickled_trusted_cfunc_8616(source, preserve_objects=())
    assert snapshot is not None
    source.variable_manager.types._kb = object()
    restored = unpickle_trusted_cfunc_8616(snapshot, preserve_objects=())
    assert restored.variable_manager.types._kb is kb
