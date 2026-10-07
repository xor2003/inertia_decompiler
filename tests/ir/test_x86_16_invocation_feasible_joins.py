"""Root-only infeasible edges must filter register and memory predecessor joins."""
import time
from types import SimpleNamespace

import pytest
import tests.ir.test_x86_16_declared_resize_boundary as native
import inertia.ir.real16_invocation_domain as domain
from inertia.ir.core import IRBlock, IRFunctionArtifact
from inertia.ir.real16_path_memory8616 import PathMemory8616


@pytest.mark.parametrize("unknown", [False, True])
def test_native_live_predecessor_diamond(unknown: bool) -> None:
    """Impossible direct edge cannot poison the live shared resize block."""
    setup = "648b1e0005" if unknown else "bb8000"
    caller = bytes.fromhex("b80001 8ec0 b8004a " + setup + " 83fb40 7203 bb4000 cd21 e80100 c3")
    delta = 2 if unknown else 0
    env = native._environment()
    boot = native._boot(caller, env)
    project, _, coverage = native._world(boot, len(caller))
    int_addr = native.MODULE_BASE + 19 + delta
    relation = native._resize_relation(env, int_addr)
    premise = native._resize_premise(project, coverage, int_addr + 2, boot, (relation,))
    edge = (native.MODULE_BASE, int_addr)
    if unknown:
        assert not premise.complete
        assert edge not in premise.infeasible_edges
    else:
        assert edge in premise.infeasible_edges
        assert premise.complete
        assert len(premise.service_consumptions) == 1
        assert premise.service_consumptions[0].answer_bx == 0x40


@pytest.mark.parametrize("filtered", [False, True])
def test_scope_filter_is_explicit_and_meets_memory(
    monkeypatch: pytest.MonkeyPatch, filtered: bool,
) -> None:
    """Ambient root evidence cannot leak into an unfiltered nested scope."""
    head, other, shared = 0x1000, 0x1003, 0x1006
    artifact = IRFunctionArtifact(head, (
        IRBlock(head, successor_addrs=(other, shared)),
        IRBlock(other, successor_addrs=(shared,)), IRBlock(shared),
    ))
    impossible = frozenset({(head, shared)})
    ctx = SimpleNamespace(deadline=time.monotonic() + 5, callsite_addr=123,
                          stop_block_addr=shared,
                          edge_feasibility=SimpleNamespace(infeasible_edges=tuple(impossible)))
    seed = domain._PathState8616({}, PathMemory8616())

    def block_exit(ctx: object, artifact: object, block: IRBlock,
                   entry: domain._PathState8616, *, stop_after: int | None) -> domain._PathState8616:
        state = domain._PathState8616(dict(entry.registers), entry.memory.copy())
        if block.addr in (head, other):
            value = 0x80 if block.addr == head else 0x40
            state.registers["bx"] = value
            state.memory.apply_write(0x2000, 1, bytes([value]))
        return state

    monkeypatch.setattr(domain, "_simulate_path_block_8616", block_exit)
    kwargs = {"infeasible_edges": impossible} if filtered else {}
    result = domain._simulate_scope_8616(
        ctx, artifact, frozenset({head, other, shared}), head, seed,
        stop_after=None, callsite_addr=None, **kwargs,
    )
    assert isinstance(result, dict)
    joined = result[shared]
    if filtered:
        assert joined.registers["bx"] == 0x40
        assert joined.memory.known[0x2000] == 0x40
        assert not joined.memory.unknown
    else:
        assert "bx" not in joined.registers
        assert 0x2000 not in joined.memory.known
        assert 0x2000 in joined.memory.unknown
    assert ctx.callsite_addr == 123
