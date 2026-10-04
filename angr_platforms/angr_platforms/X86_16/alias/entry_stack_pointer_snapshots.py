"""Entry-prefix narrowing of the shared stack-pointer snapshot owner.

Layer: Alias.
Responsibility: own entry-SP-relative frame coordinates AND typed producer
evidence for one entry-block prefix. This is a bounded subclass of the shared
``StackPointerSnapshots8616`` owner: the inherited ``offsets`` table remains the
single coordinate store, and ``value_offset`` remains the register-resolution
path. What this owner adds is strictly typed production evidence — destination
width, producing op, and the exact descriptor a legitimate later read
re-presents — so borrowed or forged temporary views refuse instead of
inheriting coordinates they did not earn.

Contract narrowing vs the shared owner: the shared ``value_offset`` accepts
any ``size >= word`` temporary and ignores consumer decorations. For an
entry-prefix proof, only word-exact (16-bit) producers whose recorded
descriptor the consumer re-presents exactly earn a coordinate; a matching
``source_tmp`` integer alone is insufficient. Coordinates are canonical byte
offsets modulo 2**16. BP starts unknown; SP starts at coordinate 0.

Owns storage identity coordinates and their exact producing-value evidence.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ir.core import IRAddress, IRInstr, IRValue, MemSpace
from ..ir.vex_integer_displacement import (
    canonical_vex_integer_displacement_8616,
)
from ..semantics.register_value_preservation import (
    register_value_family_8616,
)
from .stack_pointer_snapshots import (
    FrameRegister8616,
    StackFrameBase8616,
    StackPointerSnapshots8616,
)

_WORD_BYTES = 2
_MOD16 = 1 << 16
_BINARY_OPERAND_COUNT = 2
_ENTRY_FRAME_REGISTERS = frozenset({"sp", "bp"})
_AFFINE_OPS = frozenset({"Iop_Add16", "Iop_Sub16"})
_SP_FAMILY = register_value_family_8616("sp")
_BP_FAMILY = register_value_family_8616("bp")


def _undecorated_8616(value: IRValue) -> bool:
    """Return whether an operand carries no structural decorations.

    ``expr`` is deliberately absent here: tmp-refs legitimately re-present the
    producing expression's label and are validated by producer-view equality,
    while plain register reads refuse ``expr`` through the inherited
    ``value_offset`` gate.
    """
    return value.index_shift == 0 and all(
        field is None
        for field in (
            value.const,
            value.index,
            value.version,
            value.call_output,
            value.memory_access_size,
        )
    )


def _bare_constant_8616(value: IRValue) -> bool:
    """Return whether ``value`` is an undecorated CONST operand.

    Affine producers accept a constant displacement only when the operand is
    a plain constant: no expression label, name, index, version, call-output,
    temporary identity, or memory-access decoration may be smuggled in.
    """
    return (
        value.space is MemSpace.CONST
        and value.const is not None
        and value.offset == 0
        and value.index_shift == 0
        and not value.expr
        and value.name is None
        and value.index is None
        and value.version is None
        and value.call_output is None
        and value.source_tmp is None
        and value.memory_access_size is None
    )


@dataclass(frozen=True, slots=True)
class EntryProducerEvidence8616:
    """Exact production evidence for one immutable temporary.

    ``view`` is the descriptor fields a legitimate later read of this
    temporary re-presents (``IRValue`` equality deliberately ignores
    ``source_tmp`` and ``memory_access_insn``). ``None`` records an opaque
    production with no re-presentation contract; consumers of it refuse.
    ``dst_size`` is the producing instruction's declared destination width so
    a wide destination can never be borrowed as a word frame value.
    """

    tmp: int
    instr_index: int
    op: str
    dst_size: int
    view: IRValue | None


@dataclass(slots=True)
class EntryStackPointerSnapshots8616(StackPointerSnapshots8616):
    """Single owner for entry-prefix frame coordinates and producer evidence.

    Entry SP is coordinate 0 and entry BP is unknown. Every TMP-destination
    instruction records producer evidence and re-writes the inherited
    ``offsets`` entry with the strict result: a word-exact earned coordinate
    or ``None``. Redefinitions therefore invalidate stale captures instead of
    leaving them readable. Register transfers poison the whole storage family
    on narrow, wide, decorated, or unearned writes.
    """

    current_sp: int | None = 0
    current_bp: int | None = None
    producers: dict[int, EntryProducerEvidence8616] = field(default_factory=dict)

    def observe_entry_instruction(
        self, instruction: IRInstr, instruction_index: int
    ) -> None:
        """Record strict producer evidence and advance current frame registers.

        TMP destinations record evidence and a strict coordinate; REG
        destinations transfer or poison ``current_sp``/``current_bp`` through
        the frame families. All operand reads use the pre-instruction state.
        This is a stateful entry-prefix API, deliberately named apart
        from the inherited stateless ``observe(instruction, sp, bp)``.
        """
        destination = instruction.dst
        if (
            isinstance(destination, IRValue)
            and destination.space is MemSpace.TMP
            and destination.source_tmp is not None
        ):
            coordinate, view = self._production(instruction, destination)
            self.offsets[destination.source_tmp] = coordinate
            self.producers[destination.source_tmp] = EntryProducerEvidence8616(
                tmp=destination.source_tmp,
                instr_index=instruction_index,
                op=instruction.op,
                dst_size=destination.size,
                view=view,
            )
            return
        self._register_transfer(instruction)

    def strict_value_coordinate(self, value: IRValue) -> int | None:
        """Resolve one operand to a canonical entry-SP coordinate, or refuse.

        A tmp-decorated read resolves only through recorded producer evidence:
        the producer must have earned a word coordinate, and the consumer must
        re-present the producer's exact descriptor (space, name, offset, const,
        size, expr, version). A decoration the producer did not earn — including
        an unearned ``Iop_*`` label — is inconsistent evidence and refuses; a
        plain register-name fallback is never attempted.
        """
        if value.size != _WORD_BYTES or not _undecorated_8616(value):
            return None
        if value.source_tmp is not None:
            producer = self.producers.get(value.source_tmp)
            if (
                producer is None
                or producer.view is None
                or producer.dst_size != _WORD_BYTES
                or value != producer.view
            ):
                return None
            coordinate = self.offsets.get(value.source_tmp)
            return None if coordinate is None else coordinate % _MOD16
        coordinate = self.value_offset(value, self.current_sp, self.current_bp)
        return None if coordinate is None else coordinate % _MOD16

    def strict_address_base(self, address: IRAddress) -> StackFrameBase8616 | None:
        """Resolve an SS address base to a captured frame coordinate, or refuse.

        A bare register base reads the current live frame register. A captured
        temporary base must satisfy the strict producer contract, including
        descriptor consistency; the inherited ``base.offset == 0`` gate is kept
        for undecorated register reads, while decorated tmp-refs prove their
        displacement through view equality instead.
        """
        if len(address.base) != 1 or address.base[0] not in _ENTRY_FRAME_REGISTERS:
            return None
        register: FrameRegister8616 = "sp" if address.base[0] == "sp" else "bp"
        if not address.base_values:
            current = self.current_sp if register == "sp" else self.current_bp
            return None if current is None else StackFrameBase8616(register, current)
        if len(address.base_values) != 1:
            return None
        base = address.base_values[0]
        if base.space is not MemSpace.REG or base.name != register:
            return None
        if base.source_tmp is None and base.offset != 0:
            return None
        coordinate = self.strict_value_coordinate(base)
        return None if coordinate is None else StackFrameBase8616(register, coordinate)

    def _production(
        self, instruction: IRInstr, destination: IRValue
    ) -> tuple[int | None, IRValue | None]:
        """Compute one producer's strict coordinate and re-presentation view.

        Only word-width productions earn coordinates: destination, instruction,
        and operand widths must all be exactly 16-bit, so a wide destination can
        never be borrowed as a word frame value and no implicit narrowing or
        widening occurs. The view records what the importer will re-present to
        later reads — the source's own fields for ``MOV``, and the
        importer-equivalent ``REG name / canonical offset / (op,)`` descriptor
        for supported affine producers.
        """
        args: tuple[object, ...] = instruction.args
        if instruction.op == "MOV" and len(args) == 1 and isinstance(args[0], IRValue):
            source = args[0]
            coordinate = None
            if (
                destination.size == _WORD_BYTES
                and instruction.size == _WORD_BYTES
                and source.size == _WORD_BYTES
                and _undecorated_8616(destination)
                and not destination.expr
            ):
                coordinate = self.strict_value_coordinate(source)
            return coordinate, source
        if instruction.op in _AFFINE_OPS and len(args) == _BINARY_OPERAND_COUNT:
            return self._affine_production(instruction, destination)
        return None, None

    def _affine_production(
        self, instruction: IRInstr, destination: IRValue
    ) -> tuple[int | None, IRValue | None]:
        """Resolve a supported Add16/Sub16 frame producer strictly.

        The consumer-facing descriptor mirrors exactly the importer's
        documented affine shape: a REG value keeping the left operand's name
        and width, the width-canonical displacement, and the ``(op,)``
        decoration the producing expression earned. Any other operand shape is
        an opaque production whose consumers refuse.
        """
        left, right = instruction.args
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return None, None
        if instruction.op == "Iop_Add16" and left.space is MemSpace.CONST:
            left, right = right, left
        if left.space is not MemSpace.REG or not _bare_constant_8616(right):
            return None, None
        assert right.const is not None
        delta = right.const if instruction.op == "Iop_Add16" else -right.const
        view = IRValue(
            MemSpace.REG,
            name=left.name,
            offset=canonical_vex_integer_displacement_8616(
                instruction.op, left.offset + delta, left.size
            ),
            size=left.size,
            expr=(instruction.op,),
        )
        base = self.strict_value_coordinate(left)
        if (
            base is None
            or destination.size != _WORD_BYTES
            or instruction.size != _WORD_BYTES
            or left.size != _WORD_BYTES
            or right.size != _WORD_BYTES
        ):
            return None, view
        return (base + delta) % _MOD16, view

    def _register_transfer(self, instruction: IRInstr) -> None:
        """Advance current SP/BP coordinates through strict register writes."""
        destination = instruction.dst
        if (
            not isinstance(destination, IRValue)
            or destination.space is not MemSpace.REG
            or destination.name is None
        ):
            return
        if destination.name in _SP_FAMILY:
            self.current_sp = self._strict_updated_register("sp", instruction)
        if destination.name in _BP_FAMILY:
            self.current_bp = self._strict_updated_register("bp", instruction)

    def _strict_updated_register(
        self, register: FrameRegister8616, instruction: IRInstr
    ) -> int | None:
        """Return the new register coordinate, or ``None`` to poison it.

        Only a word-exact undecorated ``MOV`` destination whose instruction
        width agrees and whose source resolves through the strict producer
        contract earns a coordinate; wide full-parent writes, narrow writes,
        decorated or shifted destinations, non-MOV writes, mismatched
        instruction widths, and unearned sources all poison the register.
        """
        destination = instruction.dst
        assert isinstance(destination, IRValue)
        args: tuple[object, ...] = instruction.args
        exact_word = (
            destination.name == register
            and destination.size == _WORD_BYTES
            and destination.offset == 0
            and destination.index_shift == 0
            and not destination.expr
            and destination.const is None
            and destination.index is None
            and destination.call_output is None
            and destination.version is None
            and destination.source_tmp is None
            and destination.memory_access_size is None
        )
        if (
            instruction.op != "MOV"
            or instruction.size != _WORD_BYTES
            or not exact_word
            or len(args) != 1
            or not isinstance(args[0], IRValue)
        ):
            return None
        return self.strict_value_coordinate(args[0])
