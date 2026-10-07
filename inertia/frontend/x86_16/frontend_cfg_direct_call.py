"""Discover source-bound near CALL edges without changing execution VEX.

Layer: Frontend/CFG adapter.
Responsibility: supply angr CFG discovery with the owned symbolic near-CALL
binding proof (``semantics.direct_near_call_target_binding``). A call target
is published only when the block's symbolic ``next`` operand is proven to be
the lifter's CS-relative continuation for the exact decoded word-E8 at the
block tail, the retained temporary producer DAG, origin provenance, native
re-lift, full-width control, selector fetch window, and mapped bytes all
agree. Indirect, far, operand-prefixed, and selector-dependent calls stay
unresolved as typed refusals; this discovers edges, not call semantics or
callee bodies.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import angr
import cle
import pyvex
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import DEFAULT_RESOLVERS
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver

from .arch_86_16 import Arch86_16
from .control_coordinates import ControlAddressDomain

if TYPE_CHECKING:
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallTargetBinding8616,
    )

    from .relative_control_edge import RelativeEdgeRefusal

__all__ = [
    "NativeDirectCallResolver8616",
    "native_direct_call_evidence_8616",
    "register_native_direct_call_resolver_8616",
]

_MAX_NATIVE_BLOCK_BYTES_8616: int = 4096


@dataclass(frozen=True)
class _DiscoveryIrsbBoundary8616:
    """Minimal angr-block boundary carrying the supplied discovery IRSB.

    The native re-lift owns ``addr``, ``size`` and the Capstone decode; only
    ``vex`` is the discovery-time operand stream angr handed to discovery.
    """

    addr: int
    size: int
    vex: object
    capstone: object


def _imark_stream_8616(vex: object) -> tuple[tuple[int, int, int], ...]:
    """Return the block's instruction-boundary coordinates as typed facts."""
    if not isinstance(vex, pyvex.IRSB):
        return ()
    return tuple(
        (_external_int_8616(row.addr), _external_int_8616(row.delta), _external_int_8616(row.len))
        for row in vex.statements
        if isinstance(row, pyvex.stmt.IMark)
    )


def _external_int_8616(value: object) -> int:
    """Coerce pyvex/angr integer-like boundary values into owned ints."""
    return int(cast(Any, value))


def _discovery_irsb_bound_8616(
    discovery_irsb: object, native: object,
) -> bool:
    """Bind the supplied discovery IRSB to the native re-lift it must be.

    The supplied operand must be the discovery-time VEX for the same decoded
    instruction stream: same block coordinates, same ``Ijk_Call`` terminal,
    and the same ``IMark`` (addr, delta, len) sequence. Structural operand
    agreement itself is discharged by the binding owner on the imported IR.
    """
    if not isinstance(discovery_irsb, pyvex.IRSB) or not isinstance(native, pyvex.IRSB):
        return False
    if str(discovery_irsb.jumpkind) != "Ijk_Call":
        return False
    if discovery_irsb.addr != native.addr or discovery_irsb.size != native.size:
        return False
    return _imark_stream_8616(discovery_irsb) == _imark_stream_8616(native)


def _direct_call_source_8616(
    native: angr.block.Block,
    vex: object,
    discovery_irsb: object | None,
) -> object | None:
    """Choose the operand stream the binding proof must authorize.

    Without a supplied discovery operand the native re-lift is the source.
    With one, the supplied IRSB must first bind to that re-lift; the proof
    then operates on the supplied stream so an inconsistent discovery
    operand cannot be authorized by a fresh proof over different IR.
    """
    if discovery_irsb is None:
        return cast(object, native)
    if not _discovery_irsb_bound_8616(discovery_irsb, vex):
        return None
    return _DiscoveryIrsbBoundary8616(
        addr=native.addr,
        size=_external_int_8616(native.size),
        vex=discovery_irsb,
        capstone=native.capstone,
    )


def native_direct_call_evidence_8616(
    project: object,
    *,
    block_addr: int,
    block_size: int,
    discovery_irsb: object | None = None,
) -> DirectNearCallTargetBinding8616 | RelativeEdgeRefusal | None:
    """Prove one bounded native block's terminal near CALL or refuse it.

    The candidate is re-lifted at ``opt_level=0`` so temporary identity
    matches the discovery-time VEX, decoded through the shared exact-byte
    edge owner, imported through the owned VEX→IR boundary, and discharged by
    ``prove_direct_near_call_target_binding_from_decoded_8616`` against a
    decoded entry built from the block's own Capstone instruction facts. No
    callee CFG, ABI summary, or selector value is required or guessed.

    When ``discovery_irsb`` is supplied it must be the same instruction
    stream (coordinates, ``Ijk_Call``, identical IMark sequence); the proof
    then binds *that* operand's temporary DAG to the native re-lift through
    the owner, so a corrupted discovery operand cannot be authorized by a
    fresh proof over different IR.

    Returns ``None`` when no evaluable terminal-call surface exists (missing
    VEX, IMark, byte, or decoded-instruction evidence, a non-CALL block
    terminal, or an unbound supplied IRSB); a ``RelativeEdgeRefusal`` when
    the exact terminal bytes are not a supported near-relative edge
    (indirect or far calls); otherwise the shared binding verdict — only
    ``binding.complete`` authorizes publishing ``binding.target_addr`` for
    CFG discovery.
    """
    if not (
        isinstance(project, angr.Project)
        and isinstance(project.arch, Arch86_16)
        and project.arch.control_address_domain is ControlAddressDomain.LOADER_LINEAR
    ):
        return None
    if (
        type(block_addr) is not int
        or block_addr < 0
        or type(block_size) is not int
        or not 0 < block_size <= _MAX_NATIVE_BLOCK_BYTES_8616
    ):
        return None
    native = project.factory.block(
        block_addr, size=block_size, opt_level=0, collect_data_refs=True
    )
    vex = native.vex
    if not isinstance(vex, pyvex.IRSB) or str(vex.jumpkind) != "Ijk_Call":
        return None
    marks = [row for row in vex.statements if isinstance(row, pyvex.stmt.IMark)]
    if not marks:
        return None
    last = marks[-1]
    head = last.addr + last.delta
    size = last.len
    raw = native.bytes
    data = bytes(raw) if isinstance(raw, (bytes, bytearray, memoryview)) else None
    offset = head - native.addr
    if (
        data is None
        or len(data) != native.size
        or offset < 0
        or size <= 0
        or offset + size != len(data)
    ):
        return None
    # Defer IR/semantics imports until analysis: package bootstrap installs
    # this adapter before the IR package is necessarily initialized.
    from inertia.ir.vex_import import _block_to_ir
    from inertia.semantics.direct_near_call_target_binding import (
        prove_direct_near_call_target_binding_from_decoded_8616,
    )

    from .frontend_direct_callsite_index import DecodedDirectCallsite8616
    from .relative_control_edge import DecodedRelativeEdge, decode_relative_edge

    decoded = decode_relative_edge(
        head, data[offset : offset + size], source="cfg_direct_call"
    )
    if not isinstance(decoded, DecodedRelativeEdge):
        return decoded
    insns = tuple(native.capstone.insns)
    index = next(
        (i for i, insn in enumerate(insns) if insn.address == head), None
    )
    if index is None:
        return None
    entry = DecodedDirectCallsite8616(
        caller_start=native.addr,
        instructions=insns,
        instruction_index=index,
        callsite_addr=head,
        target_addr=decoded.next_head + decoded.displacement,
        is_far=False,
    )
    source_block = _direct_call_source_8616(native, vex, discovery_irsb)
    if source_block is None:
        return None
    ir_block, _transport, _terminal_jump = _block_to_ir(source_block)
    call = next(
        (
            instr
            for instr in reversed(ir_block.instrs)
            if instr.op == "CALL" and instr.addr == head
        ),
        None,
    )
    if call is None:
        return None
    return prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=ir_block, instruction=call, decoded=entry
    )


class NativeDirectCallResolver8616(IndirectJumpResolver):  # type: ignore[misc]  # dynamic angr base
    """A state-independent adapter consuming the native near-CALL proof."""

    def __init__(self, project: angr.Project) -> None:
        """Bind this third-party CFG adapter to one loaded project."""
        super().__init__(project, timeless=True)

    def filter(self, cfg: object, addr: int, func_addr: int,
               block: object, jumpkind: str) -> bool:
        """Keep other architectures, jump sites and return sites untouched."""
        return (
            isinstance(self.project.arch, Arch86_16)
            and self.project.arch.control_address_domain is ControlAddressDomain.LOADER_LINEAR
            and jumpkind == "Ijk_Call"
            and isinstance(block, pyvex.IRSB)
        )

    def resolve(self, cfg: object, addr: int, func_addr: int,
                block: pyvex.IRSB, jumpkind: str,
                func_graph_complete: bool = True,
                **kwargs: object) -> tuple[bool, list[int]]:
        """Re-lift a bounded source block and prove its terminal near CALL."""
        # angr supplies this callback argument; a native instruction theorem
        # does not depend on whether discovery has completed the CFG.
        del func_graph_complete
        if not self.filter(cfg, addr, func_addr, block, jumpkind):
            return False, []
        # Defer the semantics import until analysis: package bootstrap
        # installs this adapter before the IR package is initialized.
        from inertia.semantics.direct_near_call_target_binding import (
            DirectNearCallTargetBinding8616,
        )

        evidence = native_direct_call_evidence_8616(
            self.project, block_addr=addr, block_size=block.size,
            discovery_irsb=block,
        )
        if (
            not isinstance(evidence, DirectNearCallTargetBinding8616)
            or not evidence.complete
            or evidence.target_addr is None
        ):
            return False, []
        if not self._is_target_valid(cfg, evidence.target_addr):
            return False, []
        return True, [evidence.target_addr]


def register_native_direct_call_resolver_8616() -> None:
    """Supplement only the x86-16 default third-party resolver registry.

    The registry is angr's plugin boundary, not an owned semantic state.
    Preserve existing resolvers and avoid duplicates across bootstrap calls.
    """
    backend_resolvers = DEFAULT_RESOLVERS.setdefault(Arch86_16.name, {})
    existing = backend_resolvers.get(cle.Backend, ())
    if NativeDirectCallResolver8616 not in existing:
        backend_resolvers[cle.Backend] = [NativeDirectCallResolver8616, *existing]
