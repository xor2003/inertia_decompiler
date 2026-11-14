"""Scoped callee demands must include earlier calls without demanding future ones."""

from types import SimpleNamespace

import pytest

from inertia.ir import declared_selector_scoped_callee as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("split_blocks", [False, True])
def test_scoped_demand_collects_cfg_prerequisites_only(monkeypatch, split_blocks):
    """A missing later callee needs earlier call proofs, independent of address order."""
    first = IRInstr("CALL", None, (), addr=0x300)
    selected = IRInstr("CALL", None, (), addr=0x100)
    future = IRInstr("CALL", None, (), addr=0x200)
    if split_blocks:
        blocks = (
            IRBlock(0x300, (first,), successor_addrs=(0x100,)),
            IRBlock(0x100, (selected,), successor_addrs=(0x200,)),
            IRBlock(0x200, (future,)),
        )
    else:
        blocks = (IRBlock(0x300, (first, selected, future)),)
    artifact = IRFunctionArtifact(0x300, blocks)
    rows = tuple(SimpleNamespace(caller_start=0x300, callsite_addr=row.addr,
                                 target_addr=0x1000 + index)
                 for index, row in enumerate((first, selected, future)))
    source = SimpleNamespace(callsite_index=SimpleNamespace(
        _entries_by_normalized_target={row.target_addr: (row,) for row in rows}))
    root = SimpleNamespace(artifact=artifact, boundary=object())
    observed = []

    def collect(_project, _artifact, _boundary, *, direct_target_resolver, selected_callsites):
        observed.append(selected_callsites)
        return ()

    monkeypatch.setattr(owner, "_exact_boundary_for_8616",
                        lambda _project, addr: None if addr == 0x1001 else object())
    monkeypatch.setattr(owner, "_premise_target_resolver_8616", lambda _project: object())
    monkeypatch.setattr(owner, "collect_entry_domain_call_preservations_8616", collect)
    owner.ScopedSelectorCollection8616(object(), source, root).collect()
    assert observed == [frozenset((0x300, 0x100))]
