"""Reuse native terminal-jump evidence for callee candidate discovery.

Layer: tools/dosunit source-bound callee intake.
Responsibility: recover a full loaded jump target only when the existing IR
owner proves the exact bytes and VEX expression agree across the architectural
selector domain. This is discovery evidence, not callee equivalence or return
restoration. Indirect and selector-dependent controls remain unresolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pyvex


@dataclass(frozen=True, slots=True)
class _NativeBlock:
    """Exact source bytes exposed to the native terminal-jump boundary."""

    addr: int
    size: int
    bytes: bytes


def proven_terminal_target(
    irsb: pyvex.IRSB, body: bytes, *, head: int, size: int,
) -> int | None:
    """Consume the native jump theorem without narrowing or assuming CS.

    The scanner has already verified the body against live source bytes.
    Keep the expression symbolic for subsequent lowering and composition;
    only publish the theorem's full-width discovery destination.
    """
    # The IR package must initialize after the frontend bootstrap, as in the
    # existing angr direct-jump resolver that consumes this same theorem.
    from angr_platforms.X86_16.ir.vex_terminal_jump import terminal_direct_jump_evidence_8616

    evidence = terminal_direct_jump_evidence_8616(
        _NativeBlock(irsb.addr, len(body), body), irsb,
        instruction_addr=head, instruction_size=size,
        tmp_exprs={statement.tmp: statement.data for statement in irsb.statements
                   if isinstance(statement, pyvex.stmt.WrTmp)},
        type_environment=irsb.tyenv,
    )
    if evidence.failure is not None or not evidence.stats.closed:
        return None
    return cast(int | None, evidence.proven_target)
