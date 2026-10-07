"""Layer: validation call composition lowering.

Responsibility: lift real PyVEX blocks inside declared function byte ranges
and lower them into ``flat32_region``-shaped part documents, admitting only
statically provable direct transfers.

A block end is admitted only as ``Ijk_Boring`` with a constant next IP,
``Ijk_Call`` with a constant next IP naming a declared function entry, or
``Ijk_Ret``.  Conditional exits must be constant-target ``Ijk_Boring`` and
must not be followed by further observable effects.  An ``Ijk_Boring``
terminal target outside the owning function's declared byte range is
admitted as a typed tail transfer on ``_LiftedBlock.tail_targets`` only
when it is a binary-derived unconditional direct jump to a separately
declared function entry — no conditional exits, a real jump rather than
contiguous fallthrough, and a declared foreign entry target.  Everything
else — indirect jumps, exception edges, unsupported jumpkinds,
conditional exits to foreign entries, foreign interior targets and
undeclared targets — refuses through ``CallCompositionRefusal``; there is
no default case and declared ranges are never widened.  An ``Ijk_Call``
block whose ``irsb.next`` is not a lifted constant is a deferred-indirect
call: it is admitted with ``call_target=None`` only while
``session.admit_indirect_calls`` is set (the composed-call engine mode
entered through ``_compose_root``), and execution then proves the finite
target set from the composed ``ip`` term; otherwise it keeps the
``call_indirect_target`` lift refusal.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    BlockLiftRetry,
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _LiftedBlock,
)

if TYPE_CHECKING:
    import pyvex


def _static_next(irsb: pyvex.IRSB) -> int | None:
    """Resolve only constant copies through VEX temps/registers to the next IP."""
    import pyvex

    temps: dict[int, int | None] = {}
    registers: dict[int, int | None] = {}

    def value(expr: Any) -> int | None:  # noqa: ANN401 — pyvex expression boundary
        """Follow typed const/Get/RdTmp copies; arithmetic needs another proof."""
        if isinstance(expr, pyvex.expr.Const):
            raw = expr.con.value
            if isinstance(raw, int):
                return raw
            if isinstance(raw, float):
                return None  # F32/F64 immediates (incl. NaN) are not addresses
            return int(raw)
        if isinstance(expr, pyvex.expr.RdTmp):
            return temps.get(expr.tmp)
        if isinstance(expr, pyvex.expr.Get):
            return registers.get(expr.offset)
        return None

    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.WrTmp):
            temps[int(statement.tmp)] = value(statement.data)
        elif isinstance(statement, pyvex.stmt.Put):
            registers[int(statement.offset)] = value(statement.data)
    return value(irsb.next)


def _check_exits(irsb: pyvex.IRSB, ip_offset: int) -> list[int]:
    """Validate exit targets and forbid observable effects after the first exit."""
    import pyvex

    targets: list[int] = []
    seen_exit = False
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.Exit):
            seen_exit = True
            if str(statement.jumpkind) != "Ijk_Boring":
                raise CallCompositionRefusal("exception_edge")
            # Dynamic third-party PyVEX IRConst variants expose value at this boundary.
            target = getattr(statement.dst, "value", None)
            if not isinstance(target, int):
                raise CallCompositionRefusal("indirect_exit_target")
            targets.append(target & 0xFFFFFFFF)
        elif (
            seen_exit
            and statement.tag not in {"Ist_IMark", "Ist_WrTmp", "Ist_NoOp"}
            and not (isinstance(statement, pyvex.stmt.Put) and int(statement.offset) == ip_offset)
        ):
            raise CallCompositionRefusal("effect_after_conditional_exit")
    return targets


def _lower_block(
    session: _ComposeSession,
    function_entry: int,
    irsb: pyvex.IRSB,
    *,
    address: int,
    jumpkind: str,
    call_target: int | None,
    fallthrough: int | None,
    tail_targets: frozenset[int],
) -> dict[str, Any]:
    """Lower one lifted block into the flat32_region part shape."""
    output_regs = (*session.reg_widths, "ip")
    lowered = S._lower_irsb(
        irsb,
        output_regs=output_regs,
        max_assignments_per_function=session.limits.max_assignments_per_block,
        architecture=flat32_register_architecture(),
    )
    if isinstance(lowered, S.LowerFailure):
        raise CallCompositionRefusal(f"{lowered.reason}:{lowered.message}")
    source: dict[str, Any] = {
        "ir": "vex",
        "jumpkind": jumpkind,
        "machine_code_size": int(irsb.size),
    }
    if call_target is not None and fallthrough is not None:
        source["transfer"] = {
            "kind": "direct_call",
            "target": {"linear": hex(call_target)},
            "fallthrough": {"linear": hex(fallthrough)},
        }
    elif jumpkind == "Ijk_Call" and fallthrough is not None:
        source["transfer"] = {
            "kind": "indirect_call",
            "fallthrough": {"linear": hex(fallthrough)},
        }
    elif tail_targets:
        source["transfer"] = {
            "kind": "tail_transfer",
            "targets": [{"linear": hex(target)} for target in sorted(tail_targets)],
        }
    return {
        "entry": {"linear": hex(address)},
        "function_entry": {"linear": hex(function_entry)},
        "source": source,
        **lowered,
    }


def _direct_target(session: _ComposeSession, irsb: pyvex.IRSB) -> int | None:
    """Resolve a call block's declared-entry target, or defer an indirect call.

    A constant ``irsb.next`` names the destination in lifted bytes; a
    non-constant ``irsb.next`` means the destination is selected by live
    caller state.  With ``session.admit_indirect_calls`` set the block is
    admitted with ``call_target=None`` so execution can decompose the
    composed ``ip`` term into its finite selector arms; without it the
    historical ``call_indirect_target`` lift refusal stands.  A resolved
    target still requires declared-function membership.
    """
    resolved = _static_next(irsb)
    if resolved is None:
        if not session.admit_indirect_calls:
            raise CallCompositionRefusal("call_indirect_target")
        return None
    target = resolved & 0xFFFFFFFF
    if target not in session.functions:
        raise CallCompositionRefusal(f"call_target_unmapped:{hex(target)}")
    return target


def _tail_transfer_target(
    session: _ComposeSession,
    terminal: int,
    *,
    exit_targets: list[int],
    fallthrough: int,
) -> int | None:
    """Admit only an unconditional direct jump to a foreign declared entry.

    The evidence is binary-derived: ``terminal`` is the block's constant
    terminal ``irsb.next`` already resolved by ``_static_next`` and known to
    sit outside the owning function's declared byte range.  Admission
    additionally requires all of:

    - no conditional ``Ist.Exit`` edges — a conditional transfer out of the
      declared range is not an unconditional tail transfer and keeps
      refusing;
    - ``terminal`` is not the byte-contiguous fallthrough — a block that
      ends at the declared boundary and falls into the next declared entry
      carries no jump instruction, so this is never conflated with a tail
      transfer;
    - ``terminal`` is a declared entry in ``session.functions`` — foreign
      interior targets and undeclared targets keep refusing.

    Binding audit: no separate decoded-instruction check is required on this
    frontend.  ``irsb.next`` is exactly the decoded terminal transfer of the
    lifted block; on x86 VEX a constant non-fallthrough ``next`` under
    ``Ijk_Boring`` with no ``Ist.Exit`` edges is produced only by a terminal
    unconditional transfer.  Conditional transfers always emit an
    ``Ist.Exit``, calls/rets/sysops/signals change ``jumpkind`` or fail to
    lift, and every non-transfer instruction yields ``next == fallthrough``,
    which the ``terminal == fallthrough`` check already excludes.
    Register-indirect encodings whose operand constant-folds through
    ``_static_next`` are admitted deliberately — the destination is a
    proved-constant declared entry, matching ``_direct_target`` admission
    for folded ``call reg`` targets.

    Returns the admitted destination entry, or ``None`` when the edge must
    keep flowing into the owning closure's range check and refuse.
    """
    if exit_targets or terminal == fallthrough or terminal not in session.functions:
        return None
    return terminal


def _accepted_jumpkind(irsb: pyvex.IRSB) -> str:
    """Admit integer-functional control only after checking opaque IR effects."""
    from tools.dosunit.contracts.binary_environment import requires_environment_contract

    if requires_environment_contract(irsb):
        raise CallCompositionRefusal("external_environment_contract_required")
    jumpkind = str(irsb.jumpkind)
    if jumpkind not in {"Ijk_Boring", "Ijk_Ret", "Ijk_Call"}:
        raise CallCompositionRefusal(f"unsupported_jumpkind:{jumpkind}")
    return jumpkind


def _first_exit_instruction_count(irsb: pyvex.IRSB) -> int | None:
    """Find a decoded instruction boundary after an earlier conditional exit.

    VEX can continue lifting later instructions after a conditional transfer.
    Relifting through the exiting instruction separates its fallthrough effects
    from its taken path without discarding either path's machine semantics.
    """
    import pyvex

    count = 0
    seen_exit = False
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.IMark):
            if seen_exit:
                if count == 0:
                    raise CallCompositionRefusal("conditional_exit_without_instruction")
                return count
            count += 1
        elif isinstance(statement, pyvex.stmt.Exit):
            seen_exit = True
    return None


def _lift_control_block(session: _ComposeSession, address: int, size: int) -> pyvex.IRSB:
    """Lift a typed block ending before instructions after a conditional exit."""
    import angr
    import pyvex

    try:
        lifted = session.project.factory.block(address, size=size, opt_level=0)
        irsb = lifted.vex
        if not isinstance(irsb, pyvex.IRSB):
            raise CallCompositionRefusal("non_vex_lifter")
        instruction_count = _first_exit_instruction_count(irsb)
        if instruction_count is not None:
            irsb = session.project.factory.block(
                address, size=size, opt_level=0, num_inst=instruction_count,
            ).vex
    except (angr.errors.AngrError, angr.errors.SimError, pyvex.errors.PyVEXError) as ex:
        raise CallCompositionRefusal(f"lift_failed:{hex(address)}:{type(ex).__name__}") from ex
    if not isinstance(irsb, pyvex.IRSB):
        raise CallCompositionRefusal("non_vex_lifter")
    return irsb


def _lift_block(session: _ComposeSession, function_entry: int, address: int, end: int) -> _LiftedBlock:
    """Lift one block, admitting only boring, call or return ends.

    A call with a folded-constant ``irsb.next`` is a direct call; with
    ``session.admit_indirect_calls`` a non-constant one is deferred with
    ``call_target=None`` and proves its finite targets during composition.
    """
    size = min(end - address, session.limits.max_lift_bytes)
    irsb = _lift_control_block(session, address, size)
    jumpkind = _accepted_jumpkind(irsb)
    ip_offset = session.project.arch.ip_offset
    if ip_offset is None:
        raise CallCompositionRefusal("missing_arch_ip_offset")
    exit_targets = _check_exits(irsb, int(ip_offset))
    call_target: int | None = None
    fallthrough: int | None = None
    tail_targets: frozenset[int] = frozenset()
    if jumpkind == "Ijk_Ret":
        if exit_targets:
            raise CallCompositionRefusal("conditional_return_block")
        successors: tuple[int, ...] = ()
    elif jumpkind == "Ijk_Call":
        if exit_targets:
            raise CallCompositionRefusal("call_block_conditional_exit")
        call_target = _direct_target(session, irsb)
        fallthrough = address + int(irsb.size)
        successors = (fallthrough,)
    else:
        resolved = _static_next(irsb)
        if resolved is None:
            raise CallCompositionRefusal("indirect_jump")
        terminal = resolved & 0xFFFFFFFF
        successors = (*exit_targets, terminal)
        if not function_entry <= terminal < end:
            tail = _tail_transfer_target(
                session,
                terminal,
                exit_targets=exit_targets,
                fallthrough=address + int(irsb.size),
            )
            if tail is not None:
                # The tail target leaves the owning closure: it is recorded
                # on the block, never enqueued into this function's range.
                tail_targets = frozenset({tail})
                successors = ()
    part = _lower_block(
        session,
        function_entry,
        irsb,
        address=address,
        jumpkind=jumpkind,
        call_target=call_target,
        fallthrough=fallthrough,
        tail_targets=tail_targets,
    )
    return _LiftedBlock(
        address=address,
        irsb=irsb,
        part=part,
        jumpkind=jumpkind,
        successors=successors,
        call_target=call_target,
        fallthrough=fallthrough,
        tail_targets=tail_targets,
    )


def _lift_function(session: _ComposeSession, entry: int) -> dict[int, _LiftedBlock]:
    """Close the reachable block set inside the declared function byte range.

    The shared deadline is checked once per lifted block: a single VEX lift
    is itself uninterruptible, but a multi-block closure can no longer run
    the budget to zero before the first refusal boundary.

    ``limits.retry_max_blocks_per_function`` is the opt-in bounded
    continuation of this worklist: only when ``len(blocks)`` reaches the
    original ``max_blocks_per_function`` cap with pending successors may
    the same ``pending`` queue and ``blocks`` map continue once up to the
    retry cap.  The continuation relifts nothing, does not touch the
    deadline or any other limit, and engages at most once per closure —
    exhausting the retry cap keeps the ``block_limit`` refusal.  A
    closure that completes under the initial cap never engages it, and
    the typed :class:`BlockLiftRetry` evidence, the ``session.blocks``
    cache entry and the ``blocks_lifted`` counter are published only for
    a completed closure.
    """
    cached = session.blocks.get(entry)
    if cached is not None:
        return cached
    size = session.functions.get(entry)
    if not isinstance(size, int) or size <= 0:
        raise CallCompositionRefusal(f"unknown_function_entry:{hex(entry)}")
    end = entry + size
    blocks: dict[int, _LiftedBlock] = {}
    pending: deque[int] = deque([entry])
    block_cap = session.limits.max_blocks_per_function
    retry_cap = session.limits.retry_max_blocks_per_function
    retry_engaged = False
    while pending:
        _check_compose_deadline(session.compose_stats)
        address = pending.popleft()
        if address in blocks:
            continue
        if not entry <= address < end:
            raise CallCompositionRefusal(f"edge_outside_declared_function:{hex(address)}")
        if len(blocks) >= block_cap:
            if retry_engaged or retry_cap is None:
                raise CallCompositionRefusal("block_limit")
            retry_engaged = True
            block_cap = retry_cap
        block = _lift_block(session, entry, address, end)
        blocks[address] = block
        pending.extend(block.successors)
    if retry_engaged:
        session.block_lift_retries.append(
            BlockLiftRetry(
                entry=entry,
                initial_cap=session.limits.max_blocks_per_function,
                retry_cap=block_cap,
                blocks_lifted=len(blocks),
            )
        )
    session.blocks[entry] = blocks
    session.blocks_lifted += len(blocks)
    return blocks
