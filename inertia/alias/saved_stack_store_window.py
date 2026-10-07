"""Reject unknown cross-selector writes during saved stack-byte lifetimes.

Layer: Alias.
Responsibility: consume closed typed IR CFGs and exact save/restore coordinates
to detect writes requiring physical disjointness evidence. Logical DS/ES names
never prove disjointness from SS. No calling convention or C recovery occurs.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from inertia.ir.core import IRAddress, IRFunctionArtifact, MemSpace


def _site_reaches_8616(
    artifact: IRFunctionArtifact, source: tuple[int, int], target: tuple[int, int],
) -> bool:
    """Test instruction-order reachability, retaining paths through backedges."""
    if source[0] == target[0] and source[1] <= target[1]:
        return True
    blocks = {block.addr: block for block in artifact.blocks}
    pending = list(blocks[source[0]].successor_addrs)
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        if address == target[0]:
            return True
        if address not in visited:
            visited.add(address)
            pending.extend(blocks[address].successor_addrs)
    return False


def unproved_cross_selector_store_on_restore_path_8616(
    artifact: IRFunctionArtifact, saved: tuple[int, int], restored: tuple[int, int],
) -> bool:
    """Refuse non-SS stores on any closed CFG save-to-restore path.

    Coordinates are (block address, machine instruction address). Stores
    before a save or after its final use cannot corrupt that saved value.
    Backedges retain the lifetime when a later write reaches another restore.
    Include whole machine instructions so shared addresses cannot hide writes.
    Callers must first establish closed CFG coverage and saved-byte lineage.
    """
    blocks = {block.addr: block for block in artifact.blocks}
    save_block, restore_block = blocks.get(saved[0]), blocks.get(restored[0])
    if save_block is None or restore_block is None:
        return True
    saves = tuple(index for index, item in enumerate(save_block.instrs) if item.addr == saved[1])
    restores = tuple(index for index, item in enumerate(restore_block.instrs) if item.addr == restored[1])
    if not saves or not restores:
        return True
    source = (save_block.addr, min(saves))
    target = (restore_block.addr, max(restores))
    for block in artifact.blocks:
        for index, instruction in enumerate(block.instrs):
            if instruction.op != "STORE":
                continue
            address = instruction.args[0] if instruction.args else None
            if isinstance(address, IRAddress) and address.space is MemSpace.SS:
                continue
            site = (block.addr, index)
            if _site_reaches_8616(artifact, source, site) and _site_reaches_8616(artifact, site, target):
                return True
    return False
