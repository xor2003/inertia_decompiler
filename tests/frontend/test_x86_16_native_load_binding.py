"""Native LOAD operands must bind before their values can prune branch edges."""
from dataclasses import replace

import pytest
import tests.ir.test_x86_16_declared_resize_boundary as native
from inertia.ir.core import IRAddress
from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616


@pytest.mark.parametrize("tamper", [False, True])
def test_native_load_operand_binds_before_pruning(tamper: bool) -> None:
    """Changing only a LOAD address cannot hide a live wrong-service branch."""
    env = native._environment()
    allocation = bytearray(env.allocation)
    allocation[2:4] = (0 if tamper else 0x40).to_bytes(2, "little")
    allocation[4:6] = (0x40).to_bytes(2, "little")
    env = replace(env, allocation=bytes(allocation))
    # LOAD BX from DS:2; CMP BX,40; JE skip; MOV AX,4b00; skip: INT21.
    # Only the real BX=40 path can use the exact AH4A declaration.
    caller = bytes.fromhex("b80001 8ec0 b8004a 8b1e0200 83fb40 7403 b8004b cd21 e80100 c3")
    boot = native._boot(caller, env)
    project, raw, coverage = native._world(boot, len(caller))
    relation = native._resize_relation(env, native.MODULE_BASE + 20)
    skipped_edge = (native.MODULE_BASE, native.MODULE_BASE + 17)
    if tamper:
        original = native._resize_premise(project, coverage, native.MODULE_BASE + 22, boot, (relation,))
        assert not original.complete
        assert skipped_edge not in original.infeasible_edges
        loads = tuple(row for block in raw.blocks for row in block.instrs if row.op == "LOAD" and row.addr == native.MODULE_BASE + 8)
        assert len(loads) == 2
        for row in loads:
            address = row.args[0]
            assert isinstance(address, IRAddress)
            assert address.offset in (2, 3)
            original_site, original_origin = row.addr, row.origin
            object.__setattr__(row, "args", (replace(address, offset=address.offset + 2),))
            assert row.addr == original_site and row.origin is original_origin
    premise = native._resize_premise(project, coverage, native.MODULE_BASE + 22, boot, (relation,))
    if tamper:
        assert not premise.complete
        assert premise.failure is Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        assert skipped_edge not in premise.infeasible_edges
    else:
        assert premise.complete
        assert skipped_edge in premise.infeasible_edges
        assert len(premise.service_consumptions) == 1
        assert premise.service_consumptions[0].answer_bx == 0x40
