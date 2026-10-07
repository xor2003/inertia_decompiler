"""Per-block transfer state for the entry-word transport proof.

Layer: Widening.
Responsibility: own the closed typed transfer obligations for one SSA block:
exact operand reads, tracked definition versions, register-family clobbers,
strictly block-local TMP producers, control-transfer coherence, and seed-site
enforcement. A proven conditional branch rewrites the architectural IP family
while preserving data registers; its typed ``control_target`` must be a
recorded block successor. Instructions after the first control transfer are a
conservative safe tail — only no-register effects, block-local TMP writes, and
exact plain-literal IP writes survive; any other post-control register write
refuses, since it cannot describe the taken edge. The block-entry register map
is ``None`` when the entry is unseeded or poisoned, which then propagates as a
poisoned exit. Unknown effects and CALLs kill all register evidence; no cone
construction or selected-site policy lives here.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeGuard

from inertia.ir.core import IRInstr, IRValue, MemSpace
from inertia.ir.scalar_instruction_effects import (
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from inertia.semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)

from .entry_word_transport_contracts import (
    EntryWordTransportRefusal8616,
)
from .entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as Refusal,
)
from .entry_word_transport_snapshots import (
    SnapshotCapture8616,
    captured_word_8616,
    snapshot_capture_view_8616,
)


@dataclass(slots=True)
class TransportDefinition8616:
    """One tracked definition: SSA version, word flag, and capture view.

    ``capture`` is set only on block-local TMP producers whose MOV source was
    an exact current-register view; it is never implied by a register name.
    """

    version: int | None
    word: bool
    capture: SnapshotCapture8616 | None = None


def plain_word_read_8616(value: IRValue) -> bool:
    """Require an exact read view of one word-width scalar operand.

    A REG name carrying source_tmp is still plain here; its historical capture
    is resolved through the retained TMP producer by the snapshot owner, never
    by the current register name alone.
    """
    if value.space not in {MemSpace.TMP, MemSpace.REG} or value.size != 2:
        return False
    if value.space is MemSpace.REG and not full_word_register_8616(value.name):
        return False
    if value.offset or value.index is not None or value.index_shift:
        return False
    return (
        value.call_output is None and not value.expr and value.const is None
    )


def full_word_register_8616(name: str | None) -> bool:
    """A seed/target register must be a complete architectural 16-bit view."""
    return name is not None and register_value_projection_8616(name, name) == (0, 16)


def plain_destination_8616(value: IRValue) -> bool:
    """A definition site is exact storage, never a displaced/decorated view."""
    if value.const is not None:
        return False
    if value.space is MemSpace.REG and value.source_tmp is not None:
        return False
    return (
        value.space in {MemSpace.TMP, MemSpace.REG}
        and not value.offset
        and value.index is None
        and not value.index_shift
        and value.call_output is None
        and not value.expr
    )


@dataclass(slots=True)
class TransportRun8616:
    """Per-block transfer state; TMP producer scope is strictly block-local."""

    regs: dict[str, TransportDefinition8616] = field(default_factory=dict)
    temps: dict[int, TransportDefinition8616] = field(default_factory=dict)
    refusals: list[EntryWordTransportRefusal8616] = field(default_factory=list)
    raw: int = 0
    normalized: int = 0

    def read_word(self, value: IRValue) -> bool | None:
        """Resolve one operand to the tracked word; None marks a bad view."""
        if not plain_word_read_8616(value):
            return None
        if value.space is MemSpace.TMP:
            if value.source_tmp is None:
                return None
            definition = self.temps.get(value.source_tmp)
        else:
            if value.name is None:
                return None
            if value.source_tmp is not None:
                return self._read_capture_8616(value, value.source_tmp)
            definition = self.regs.get(value.name.lower())
        if definition is None:
            return False
        if definition.version != value.version:
            self.refusals.append(EntryWordTransportRefusal8616(
                Refusal.STALE_TMP_VERSION,
                "read version differs from retained producer",
            ))
            return False
        return definition.word

    def _read_capture_8616(self, value: IRValue, source_tmp: int) -> bool:
        """Resolve a captured REG view through its block-local TMP producer."""
        definition = self.temps.get(source_tmp)
        word, refusal = captured_word_8616(
            None if definition is None else definition.capture, value,
        )
        if refusal is not None:
            self.refusals.append(refusal)
        return word


def _plain_literal_8616(value: object) -> TypeGuard[IRValue]:
    """An exact CONST literal with no decoration or captured provenance."""
    if not isinstance(value, IRValue) or value.space is not MemSpace.CONST:
        return False
    if value.const is None or value.offset or value.index is not None:
        return False
    return (
        not value.index_shift and not value.expr
        and value.call_output is None and value.source_tmp is None
    )


def _apply_branch_8616(
    run: TransportRun8616,
    control_target: int | None,
    successor_addrs: tuple[int, ...],
    block_addr: int,
    index: int,
) -> None:
    """A proven control transfer kills the architectural IP family only.

    The typed ``control_target`` supplied by the IR effect owner must be a
    recorded successor of this block; data registers survive untouched.
    """
    for member in register_value_family_8616("ip"):
        run.regs.pop(member, None)
    if control_target is None or control_target not in successor_addrs:
        run.refusals.append(EntryWordTransportRefusal8616(
            Refusal.MISSING_BRANCH_TARGET,
            "branch target absent from recorded successors",
            block_addr, index,
        ))


def _tail_write_check_8616(
    instruction: IRInstr,
    destination: IRValue,
    successor_addrs: tuple[int, ...],
) -> tuple[Refusal, str] | None:
    """Refuse post-control writes the taken edge never executes.

    Only the fallthrough path observes the tail: block-local TMP writes are
    invisible outside the block and an exact literal IP write is the ordinary
    recorded fallthrough exit; every other register write would be attributed
    to the taken edge incorrectly.
    """
    if destination.space is MemSpace.TMP:
        return None
    if (
        destination.name is None
        or destination.name.lower() not in register_value_family_8616("ip")
    ):
        return Refusal.POST_CONTROL_DATA_WRITE, "post-control data-register write"
    source = instruction.args[0] if len(instruction.args) == 1 else None
    if not _plain_literal_8616(source):
        return Refusal.UNTRACKED_IP_WRITE, "nonliteral ip restore"
    if source.const is None or source.const not in successor_addrs:
        return Refusal.MISSING_BRANCH_TARGET, "ip trailer target absent from successors"
    return None


def _apply_unknown_8616(
    run: TransportRun8616,
    instruction: IRInstr,
    block_addr: int,
    index: int,
) -> None:
    """Kill register evidence; a non-CALL TMP producer is also forgotten."""
    run.regs.clear()
    effect = scalar_instruction_effect_8616(instruction)
    run.refusals.append(EntryWordTransportRefusal8616(
        Refusal.UNKNOWN_EFFECT, effect.detail, block_addr, index,
    ))
    destination = instruction.dst
    if (
        instruction.op != "CALL" and destination is not None
        and destination.space is MemSpace.TMP
        and destination.source_tmp is not None
    ):
        run.temps.pop(destination.source_tmp, None)


def _written_word_8616(
    run: TransportRun8616,
    instruction: IRInstr,
    destination: IRValue,
) -> tuple[bool, SnapshotCapture8616 | None]:
    """Resolve the MOV source word and retain its exact register capture."""
    if not (
        instruction.op == "MOV"
        and destination.size == 2
        and len(instruction.args) == 1
    ):
        return False, None
    source = instruction.args[0]
    if not isinstance(source, IRValue):
        return False, None
    word = bool(run.read_word(source))
    view = snapshot_capture_view_8616(source)
    capture = (
        None
        if view is None
        else SnapshotCapture8616(view[0], view[1], word)
    )
    return word, capture


def _write_register_8616(
    run: TransportRun8616,
    destination: IRValue,
    word: bool,
) -> None:
    """Clobber the whole architectural family, then bind the new version."""
    if destination.name is None:
        run.regs.clear()
        return
    for member in register_value_family_8616(destination.name):
        run.regs.pop(member, None)
    run.regs[destination.name.lower()] = TransportDefinition8616(
        destination.version, word,
    )


def _write_temporary_8616(
    run: TransportRun8616,
    destination: IRValue,
    word: bool,
    capture: SnapshotCapture8616 | None,
    block_addr: int,
    index: int,
) -> None:
    """Bind one block-local TMP producer; redefinition refuses the word."""
    tmp = destination.source_tmp
    if tmp is None:
        return
    if tmp in run.temps:
        run.refusals.append(EntryWordTransportRefusal8616(
            Refusal.DUPLICATE_TMP_PRODUCER, "tmp producer redefined",
            block_addr, index,
        ))
        word = False
        capture = None
    run.temps[tmp] = TransportDefinition8616(destination.version, word, capture)


def _enforce_seed_8616(
    run: TransportRun8616,
    destination: IRValue,
    block_addr: int,
    index: int,
    seed_name: str,
    seed_version: int | None,
) -> None:
    """The seed site must define the proven full-word register version."""
    if (
        destination.space is not MemSpace.REG
        or destination.name is None
        or destination.name.lower() != seed_name
        or destination.version != seed_version
    ):
        run.refusals.append(EntryWordTransportRefusal8616(
            Refusal.SEED_NOT_PROVEN,
            "seed site does not define the proven word",
            block_addr, index,
        ))
    else:
        run.regs[seed_name] = TransportDefinition8616(destination.version, True)


def _write_closed_8616(
    run: TransportRun8616,
    instruction: IRInstr,
    block_addr: int,
    index: int,
    seed_index: int | None,
    seed_name: str,
    seed_version: int | None,
    controlled: bool,
    successor_addrs: tuple[int, ...],
) -> None:
    """Apply one closed register-write effect to the transfer state."""
    destination = instruction.dst
    if destination is None or not plain_destination_8616(destination):
        run.regs.clear()
        run.refusals.append(EntryWordTransportRefusal8616(
            Refusal.UNSUPPORTED_OPERAND, "closed effect with malformed dst",
            block_addr, index,
        ))
        return
    if controlled:
        tail_refusal = _tail_write_check_8616(
            instruction, destination, successor_addrs,
        )
        if tail_refusal is not None:
            run.regs.clear()
            run.refusals.append(EntryWordTransportRefusal8616(
                tail_refusal[0], tail_refusal[1], block_addr, index,
            ))
            return
    word, capture = _written_word_8616(run, instruction, destination)
    if destination.space is MemSpace.REG:
        _write_register_8616(run, destination, word)
    else:
        _write_temporary_8616(
            run, destination, word, capture, block_addr, index,
        )
    if index == seed_index:
        _enforce_seed_8616(
            run, destination, block_addr, index, seed_name, seed_version,
        )


def transfer_block_8616(
    *,
    block_addr: int,
    ssa_instrs: tuple[IRInstr, ...],
    entry_regs: dict[str, bool] | None,
    stop_index: int,
    seed_index: int | None,
    seed_name: str,
    seed_version: int | None,
    successor_addrs: tuple[int, ...],
) -> tuple[TransportRun8616, dict[str, bool] | None]:
    """Run the closed typed transfer over one block (or a target prefix).

    Unknown effects and CALLs kill all register evidence. ``entry_regs`` of
    None marks an unseeded/poisoned entry, which propagates as a poisoned exit.
    A proven control transfer starts the conservative safe tail. Returns the
    final state plus the exit word-map (None when poisoned).
    """
    run = TransportRun8616()
    if entry_regs is not None:
        for name, word in entry_regs.items():
            run.regs[name] = TransportDefinition8616(0, word)
    controlled = False
    for index, instruction in enumerate(ssa_instrs[:stop_index]):
        run.raw += 1
        effect = scalar_instruction_effect_8616(instruction)
        if effect.kind is ScalarInstructionEffectKind8616.UNKNOWN:
            _apply_unknown_8616(run, instruction, block_addr, index)
            continue
        run.normalized += 1
        if effect.kind is ScalarInstructionEffectKind8616.NO_REGISTER_WRITE:
            continue
        if effect.kind is ScalarInstructionEffectKind8616.INSTRUCTION_POINTER_WRITE:
            _apply_branch_8616(
                run, effect.control_target, successor_addrs, block_addr, index,
            )
            controlled = True
            continue
        _write_closed_8616(
            run, instruction, block_addr, index,
            seed_index, seed_name, seed_version,
            controlled, successor_addrs,
        )
    exit_regs = (
        None
        if entry_regs is None
        else {name: definition.word for name, definition in run.regs.items()}
    )
    return run, exit_regs
