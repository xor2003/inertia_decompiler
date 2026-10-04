"""Discover source-bound near JMP edges without changing execution VEX.

Layer: Frontend/CFG adapter.
Responsibility: supply angr CFG discovery with the existing exact-byte,
full-width terminal-JMP proof. A target is accepted only across every selector
capable of fetching its native head; selector-dependent wrap stays unresolved.
This discovers edges, not whole-function equivalence or register preservation.
"""
from __future__ import annotations

import angr
import cle
import pyvex
from angr.analyses.cfg.indirect_jump_resolvers.default_resolvers import DEFAULT_RESOLVERS
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver

from .arch_86_16 import Arch86_16
from .control_coordinates import ControlAddressDomain

__all__ = ["NativeDirectJumpResolver8616", "register_native_direct_jump_resolver_8616"]

_MAX_NATIVE_BLOCK_BYTES_8616: int = 4096


def _instruction_marks_8616(block: pyvex.IRSB) -> tuple[tuple[int, int, int], ...]:
    """Bind discovery coordinates to the instruction stream read from the image."""
    return tuple(
        (row.addr, row.delta, row.len) for row in block.statements
        if isinstance(row, pyvex.stmt.IMark)
    )


class NativeDirectJumpResolver8616(IndirectJumpResolver):  # type: ignore[misc]  # dynamic angr base
    """A state-independent adapter consuming the native terminal proof owner."""

    def __init__(self, project: angr.Project) -> None:
        """Bind this third-party CFG adapter to one loaded project."""
        super().__init__(project, timeless=True)

    def filter(self, cfg: object, addr: int, func_addr: int,
               block: object, jumpkind: str) -> bool:
        """Keep other architectures, call sites and return sites untouched."""
        return (
            isinstance(self.project.arch, Arch86_16)
            and self.project.arch.control_address_domain is ControlAddressDomain.LOADER_LINEAR
            and jumpkind == "Ijk_Boring"
            and isinstance(block, pyvex.IRSB)
        )

    def resolve(self, cfg: object, addr: int, func_addr: int,
                block: pyvex.IRSB, jumpkind: str,
                func_graph_complete: bool = True,
                **kwargs: object) -> tuple[bool, list[int]]:
        """Bind the supplied discovery operand to the native terminal theorem."""
        # angr supplies this callback argument; a native instruction theorem
        # does not depend on whether discovery has completed the CFG.
        del func_graph_complete
        if not self.filter(cfg, addr, func_addr, block, jumpkind):
            return False, []
        if not 0 < block.size <= _MAX_NATIVE_BLOCK_BYTES_8616:
            return False, []
        native = self.project.factory.block(addr, size=block.size, opt_level=0)
        if not isinstance(native.vex, pyvex.IRSB):
            return False, []
        if block.addr != native.addr or block.jumpkind != native.vex.jumpkind:
            return False, []
        if _instruction_marks_8616(block) != _instruction_marks_8616(native.vex):
            return False, []
        marks = [row for row in native.vex.statements if isinstance(row, pyvex.stmt.IMark)]
        if not marks:
            return False, []
        last = marks[-1]
        expressions = {
            row.tmp: row.data for row in native.vex.statements
            if isinstance(row, pyvex.stmt.WrTmp)
        }
        # Defer the IR import until analysis: package bootstrap installs the
        # third-party adapter before the IR package is necessarily initialized.
        from .ir.vex_terminal_jump import terminal_direct_jump_evidence_8616

        evidence = terminal_direct_jump_evidence_8616(
            native, native.vex, instruction_addr=last.addr + last.delta,
            instruction_size=last.len, tmp_exprs=expressions,
            type_environment=native.vex.tyenv,
        )
        target = evidence.proven_target
        if evidence.failure is not None or target is None:
            return False, []
        # The native theorem also discharges the selector fetch domain. A
        # separate proof over the supplied operand prevents fresh source IR
        # from authorizing an altered discovery operand or temporary producer.
        supplied = terminal_direct_jump_evidence_8616(
            native, block, instruction_addr=last.addr + last.delta,
            instruction_size=last.len,
            tmp_exprs={row.tmp: row.data for row in block.statements
                       if isinstance(row, pyvex.stmt.WrTmp)},
            type_environment=block.tyenv,
        )
        if supplied.failure is not None or supplied.proven_target != target:
            return False, []
        if not self._is_target_valid(cfg, target):
            return False, []
        return True, [target]


def register_native_direct_jump_resolver_8616() -> None:
    """Supplement only the x86-16 default third-party resolver registry.

    The registry is angr's plugin boundary, not an owned semantic state.
    Preserve existing resolvers and avoid duplicates across bootstrap calls.
    """
    backend_resolvers = DEFAULT_RESOLVERS.setdefault(Arch86_16.name, {})
    existing = backend_resolvers.get(cle.Backend, ())
    if NativeDirectJumpResolver8616 not in existing:
        backend_resolvers[cle.Backend] = [NativeDirectJumpResolver8616, *existing]
