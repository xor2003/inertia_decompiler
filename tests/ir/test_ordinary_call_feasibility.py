"""Optional authenticated ordinary calls refine only explicitly supplied effects."""

import time
from collections.abc import Callable
from typing import cast

import pytest

from inertia.ir import real16_edge_feasibility8616 as edge
from inertia.ir.core import IRBlock, IRCondition, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.real16_path_memory8616 import PathMemory8616
from inertia.ir.ssa_function import build_x86_16_ir_predecessor_map

pytestmark = pytest.mark.decompiler
ApplyCall = Callable[[IRInstr, dict[str, int], PathMemory8616], bool]


def value(number: int) -> IRValue:
    """Build a word-sized constant operand."""
    return IRValue(MemSpace.CONST, const=number, size=2)


def artifact(target: object | None = None) -> IRFunctionArtifact:
    """Build a call followed by an AX-dependent diamond with a shared exit."""
    target = value(100) if target is None else target
    branch = IRInstr(
        "CJMP",
        None,
        (IRCondition("eq", (IRValue(MemSpace.REG, name="ax", size=2), value(0)), width_bits=16), value(10)),
        addr=1,
    )
    return IRFunctionArtifact(
        0,
        (
            IRBlock(0, (IRInstr("CALL", None, (target,), addr=0), branch), successor_addrs=(10, 20)),
            IRBlock(10, successor_addrs=(30,)),
            IRBlock(20, successor_addrs=(30,)),
            IRBlock(30),
        ),
    )


def run(hook: ApplyCall | None = None, target: object | None = None) -> edge.Real16EdgeFeasibility8616:
    """Analyze the diamond with known input bytes and an optional call effect."""
    body = artifact(target)
    memory = PathMemory8616()
    memory.apply_write(0x100, 1, b"x")
    return edge.invocation_feasible_scope_8616(
        artifact=body,
        dangerous=frozenset({0, 10, 20, 30}),
        predecessor_map=build_x86_16_ir_predecessor_map(body),
        head_addr=0,
        call_block_addr=30,
        callsite_addr=30,
        seed={"ax": 1},
        seed_memory=memory,
        apply_service=lambda *_: False,
        iteration_limit=64,
        deadline=time.monotonic() + 5,
        work_limit=10000,
        apply_call=hook,
    )


def test_authenticated_ordinary_call_prunes() -> None:
    """Test authenticated ordinary call prunes."""
    seen = []

    def authenticated(row: IRInstr, registers: dict[str, int], memory: PathMemory8616) -> bool:
        """Model a successful call that returns zero in AX."""
        assert row.args[0].const == 100
        assert memory.known[0x100] == ord("x")
        registers["ax"] = 0
        seen.append(row)
        return True

    result = run(authenticated)
    assert seen
    assert result.converged
    assert result.infeasible_edges == ((0, 20),)


@pytest.mark.parametrize("target", [
    IRValue(MemSpace.TMP, size=4, expr=("Iop_Add32",), source_tmp=30),
    IRValue(MemSpace.CONST, size=4, const=100),
    IRValue(MemSpace.REG, size=4, name="eax"),
])
def test_native_target_views_reach_authentication(target: IRValue) -> None:
    """The callback owns target proof for native dword temporary coordinates."""
    seen: list[IRValue] = []

    def authenticated(row: IRInstr, registers: dict[str, int], memory: PathMemory8616) -> bool:
        """Consume the supplied typed target and publish the proven AX result."""
        assert row.args[0] is target
        seen.append(target)
        registers["ax"] = 0
        return True

    result = run(authenticated, target)
    assert seen
    assert result.infeasible_edges == ((0, 20),)


@pytest.mark.parametrize("answer", [False, None, 1])
def test_refused_hook_drops_mutated_facts(answer: object) -> None:
    """Test refused hook drops mutated facts."""

    def refused(row: IRInstr, registers: dict[str, int], memory: PathMemory8616) -> bool:
        """Mutate scratch state, then supply an invalid acceptance answer."""
        registers["ax"] = 0
        memory.apply_write(0x100, 1, b"y")
        return cast(bool, answer)

    result = run(refused)
    assert result.infeasible_edges == ()
    assert result.live_blocks == frozenset({0, 10, 20, 30})


def test_default_no_hook_retains_edges() -> None:
    """Test default no hook retains edges."""
    assert run().infeasible_edges == ()


@pytest.mark.parametrize(
    "target", [object(), IRValue(MemSpace.CONST, const=True, size=2), IRValue(MemSpace.REG, name="", size=2)]
)
def test_malformed_target_never_invokes_hook(target: object) -> None:
    """Test malformed target never invokes hook."""

    def forbidden(*_: object) -> bool:
        """Reject accidental dispatch of a malformed target."""
        raise AssertionError("malformed target invoked hook")

    assert run(forbidden, target).infeasible_edges == ()


def test_partial_known_registers_not_projected_as_constant() -> None:
    """Test partial known registers not projected as constant."""
    memory = PathMemory8616()
    memory.apply_write(0x100, 1, b"x")
    seen = []

    def authenticated(row: IRInstr, registers: dict[str, int], current: PathMemory8616) -> bool:
        """Record the fully known projection without inventing missing bits."""
        seen.append(dict(registers))
        return True

    result = edge._kb_call_row_8616(
        artifact().blocks[0].instrs[0], {"ax": (0xFF, 0)}, memory, lambda *_: False, authenticated
    )
    assert all("ax" not in registers for registers in seen)
    assert "ax" not in result
    assert memory.known[0x100] == ord("x")


def test_declared_interrupt_uses_only_service_hook() -> None:
    """Test declared interrupt uses only service hook."""
    memory = PathMemory8616()
    row = IRInstr("CALL", None, (value(0xFF021),), addr=0)
    seen = []

    def service(instruction: IRInstr, registers: dict[str, int], current: PathMemory8616) -> bool:
        """Model the declared interrupt through its existing service hook."""
        registers["ax"] = 0
        seen.append(instruction)
        return True

    def forbidden(*_: object) -> bool:
        """Reject accidental ordinary-call dispatch of an interrupt."""
        raise AssertionError("interrupt invoked ordinary hook")

    result = edge._kb_call_row_8616(row, {"ax": (0xFFFF, 1)}, memory, service, forbidden)
    assert seen
    assert result["ax"] == (0xFFFF, 0)


def test_malformed_destination_and_refusal_taint_memory() -> None:
    """Test malformed destination and refusal taint memory."""
    memory = PathMemory8616()
    memory.apply_write(0x100, 1, b"x")
    row = IRInstr("CALL", value(1), (value(100),), addr=0)

    def forbidden(*_: object) -> bool:
        """Reject accidental dispatch of a malformed destination."""
        raise AssertionError("malformed destination invoked hook")

    assert edge._kb_call_row_8616(row, {"ax": (0xFFFF, 1)}, memory, lambda *_: False, forbidden) == {}
    assert memory.tainted
    assert not memory.known
    memory = PathMemory8616()
    memory.apply_write(0x100, 1, b"x")

    def refused(row: IRInstr, registers: dict[str, int], current: PathMemory8616) -> bool:
        """Leave mutated scratch facts that must be discarded on refusal."""
        registers["ax"] = 0
        current.apply_write(0x100, 1, b"y")
        return False

    assert (
        edge._kb_call_row_8616(artifact().blocks[0].instrs[0], {"ax": (0xFFFF, 1)}, memory, lambda *_: False, refused)
        == {}
    )
    assert memory.tainted
    assert not memory.known
