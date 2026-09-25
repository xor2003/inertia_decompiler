"""Typed condition-domain representation and constructors.

Layer: IR.
Responsibility: owns typed Condition representation and constructors.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Literal

from .condition_fingerprint_masks import normalize_condition_full_width_masks_8616
from .core import IRBinaryValue, IRCondition, IRValue

__all__ = (
    "JCC_EQ_MNEMONICS_8616",
    "JCC_NE_MNEMONICS_8616",
    "JCC_SGE_MNEMONICS_8616",
    "JCC_SGT_MNEMONICS_8616",
    "JCC_SLE_MNEMONICS_8616",
    "JCC_SLT_MNEMONICS_8616",
    "JCC_TO_COND_8616",
    "JCC_UGE_MNEMONICS_8616",
    "JCC_UGT_MNEMONICS_8616",
    "JCC_ULE_MNEMONICS_8616",
    "JCC_ULT_MNEMONICS_8616",
    "ConditionEdgeEvidence",
    "ConditionFailure",
    "ConditionIR",
    "ConditionOp",
    "ConditionRegisterBindingIR",
    "ConditionRegisterUpdateIR",
    "ConditionResult",
    "ConditionSource",
    "build_condition_from_cmp_8616",
    "build_condition_from_compare_8616",
    "build_condition_from_test_8616",
    "build_condition_ir_8616",
    "canonicalize_condition_storage_fingerprint_8616",
    "coerce_condition_value_size_8616",
    "condition_compare_symbol_8616",
    "condition_sort_key_8616",
    "deduplicate_conditions_8616",
    "harmonize_condition_args_8616",
    "invert_condition_fingerprint_string_8616",
    "inverted_comparison_op_8616",
    "is_condition_compare_family_8616",
    "is_condition_truth_test_8616",
    "is_signed_condition_8616",
    "is_unsigned_condition_8616",
    "normalize_condition_fingerprint_algebraic_8616",
    "normalize_condition_fingerprint_string_8616",
    "normalize_condition_op_8616",
)

_STACK_ARG_STORAGE_FINGERPRINT_RE_8616 = re.compile(
    r"stack_arg:[A-Za-z_][A-Za-z0-9_]*"
    r"(?::size(?P<size>\d+))?:bp(?P<offset>[+-]0x[0-9a-fA-F]+)"
)

type ConditionOp = Literal[
    "and",
    "carry_compare",
    "compare",
    "eq",
    "ne",
    "not",
    "or",
    "slt",
    "sle",
    "sgt",
    "sge",
    "ult",
    "ule",
    "ugt",
    "uge",
    "zero",
    "nonzero",
]

_COMPARE_SYMBOLS_8616: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "slt": "<",
    "sle": "<=",
    "sgt": ">",
    "sge": ">=",
    "ult": "<",
    "ule": "<=",
    "ugt": ">",
    "uge": ">=",
}

# ── JCC mnemonic families (flag aliases normalized) ──

JCC_EQ_MNEMONICS_8616: frozenset[str] = frozenset({"je", "jz"})
JCC_NE_MNEMONICS_8616: frozenset[str] = frozenset({"jne", "jnz"})
JCC_ULT_MNEMONICS_8616: frozenset[str] = frozenset({"jb", "jnae", "jc"})
JCC_UGE_MNEMONICS_8616: frozenset[str] = frozenset({"jae", "jnb", "jnc"})
JCC_ULE_MNEMONICS_8616: frozenset[str] = frozenset({"jbe", "jna"})
JCC_UGT_MNEMONICS_8616: frozenset[str] = frozenset({"ja", "jnbe"})
JCC_SLT_MNEMONICS_8616: frozenset[str] = frozenset({"jl", "jnge"})
JCC_SGE_MNEMONICS_8616: frozenset[str] = frozenset({"jge", "jnl"})
JCC_SLE_MNEMONICS_8616: frozenset[str] = frozenset({"jle", "jng"})
JCC_SGT_MNEMONICS_8616: frozenset[str] = frozenset({"jg", "jnle"})

_JCC_COMPARISON_MNEMONICS_8616: frozenset[str] = frozenset({"jo", "jno", "js", "jns", "jp", "jpe", "jpo", "jnp"})

JCC_TO_COND_8616: dict[str, ConditionOp] = dict.fromkeys(JCC_EQ_MNEMONICS_8616, "eq")
JCC_TO_COND_8616.update(dict.fromkeys(JCC_NE_MNEMONICS_8616, "ne"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_ULT_MNEMONICS_8616, "ult"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_UGE_MNEMONICS_8616, "uge"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_ULE_MNEMONICS_8616, "ule"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_UGT_MNEMONICS_8616, "ugt"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_SLT_MNEMONICS_8616, "slt"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_SGE_MNEMONICS_8616, "sge"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_SLE_MNEMONICS_8616, "sle"))
JCC_TO_COND_8616.update(dict.fromkeys(JCC_SGT_MNEMONICS_8616, "sgt"))
JCC_TO_COND_8616.update(dict.fromkeys(_JCC_COMPARISON_MNEMONICS_8616, "compare"))

# Canonical list of all supported jcc synonyms, used for coverage checks.
_SUPPORTED_JCC_MNEMONICS_8616: frozenset[str] = frozenset(JCC_TO_COND_8616.keys())


# ── Condition builders from CMP/TEST sources ──


def _condition_width_size_8616(width_bits: int) -> int:
    if not isinstance(width_bits, int) or width_bits <= 0:
        return 0
    return max(1, (width_bits + 7) // 8)


def _harmonize_condition_pair_8616(lhs: Any, rhs: Any, width_bits: int) -> tuple[Any, Any]:
    """Normalize typed condition operand sizes in the IR layer.

    Mixed-width condition operands are a semantic input issue, not a rewrite
    concern.  Keep the proof on IRValue operands only; opaque AST/text objects
    are left untouched for their owning layer.
    """
    if not isinstance(lhs, IRValue) or not isinstance(rhs, IRValue):
        return lhs, rhs
    # Keep the wider storage identity in the condition operands.  The
    # explicit instruction width is retained on ConditionIR and the owning
    # lowering layer materializes the required word projection from it.
    target_size = max(_condition_width_size_8616(width_bits), int(lhs.size or 0), int(rhs.size or 0))
    if target_size <= 0:
        return lhs, rhs
    normalized = harmonize_condition_args_8616(lhs, rhs, size=target_size)
    return normalized[0], normalized[1]


@dataclass(frozen=True, slots=True)
class ConditionRegisterUpdateIR:
    """Describe one exact full-register update feeding a condition view."""

    instruction_addr: int
    target_register: str
    op: str
    rhs: IRValue | IRBinaryValue


@dataclass(frozen=True, slots=True)
class ConditionRegisterBindingIR:
    """Bind one register to an exact typed value at a condition producer."""

    register_name: str
    value: IRValue | IRBinaryValue
    update: ConditionRegisterUpdateIR | None = None


@dataclass(frozen=True, slots=True)
class ConditionIR:
    """Typed condition IR object — the canonical form for branches.

    Forbidden: flags-based conditions, tmp-based conditions.
    AGENTS rule: Conditions must be explicit (``x < y``, not ``flags & ZF``).
    """

    op: ConditionOp
    lhs: Any
    rhs: Any | None = None
    width_bits: int = 16
    source: tuple[str, ...] = ()
    src_insn: int | None = None
    block_addr: int | None = None
    producer_insn: int | None = None
    taken_target: int | None = None
    fallthrough_target: int | None = None
    operand_bind_insn: int | None = None
    producer_semantics: tuple[Any, ...] | None = None
    register_bindings: tuple[ConditionRegisterBindingIR, ...] = ()

    @property
    def is_comparison(self) -> bool:
        """Return whether this condition has two comparison operands."""
        return self.op in {
            "eq",
            "ne",
            "slt",
            "sle",
            "sgt",
            "sge",
            "ult",
            "ule",
            "ugt",
            "uge",
        }

    @property
    def is_zero_test(self) -> bool:
        """Return whether this condition tests one value against zero."""
        return self.op in {"zero", "nonzero"}

    @property
    def is_signed(self) -> bool:
        """Return whether this condition uses signed ordering semantics."""
        return self.op in {"slt", "sle", "sgt", "sge"}

    @property
    def is_unsigned(self) -> bool:
        """Return whether this condition uses unsigned ordering semantics."""
        return self.op in {"ult", "ule", "ugt", "uge"}


@dataclass(frozen=True, slots=True)
class ConditionFailure:
    """Typed refusal for unsupported condition recovery in the IR layer."""

    reason: str
    source: tuple[str, ...] = ()
    detail: str = ""

    @property
    def is_failure(self) -> bool:
        """Return True so callers can branch on condition/failure results."""
        return True


# Type alias for condition-or-failure returns
type ConditionResult = ConditionIR | ConditionFailure


def build_condition_from_cmp_8616(
    lhs: Any,
    rhs: Any,
    jcc: str,
    *,
    width_bits: int = 16,
    src_insn: int | None = None,
    block_addr: int | None = None,
    producer_insn: int | None = None,
    taken_target: int | None = None,
    fallthrough_target: int | None = None,
    operand_bind_insn: int | None = None,
    producer_semantics: tuple[Any, ...] | None = None,
    register_bindings: tuple[ConditionRegisterBindingIR, ...] = (),
) -> ConditionResult:
    """Build a ConditionIR from CMP operands + JCC mnemonic.

    CMP lhs, rhs
    JCC label  →  ConditionIR(op, lhs, rhs)
    """
    normalized_jcc = jcc.lower()
    op = JCC_TO_COND_8616.get(normalized_jcc)
    if producer_semantics and producer_semantics[0] == "dec_reg16":
        if normalized_jcc == "jns":
            op = "sge"
        elif normalized_jcc == "js":
            op = "slt"
    if op is None:
        return ConditionFailure(
            "unsupported_jcc",
            source=("cmp", jcc),
            detail=f"JCC mnemonic '{jcc}' not in JCC_TO_COND_8616",
        )
    lhs, rhs = _harmonize_condition_pair_8616(lhs, rhs, width_bits)
    return ConditionIR(
        op=op,
        lhs=lhs,
        rhs=rhs,
        width_bits=width_bits,
        source=("cmp", jcc),
        src_insn=src_insn,
        block_addr=block_addr,
        producer_insn=producer_insn,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
        operand_bind_insn=operand_bind_insn,
        producer_semantics=producer_semantics,
        register_bindings=register_bindings,
    )


def build_condition_from_test_8616(
    value: Any,
    jcc: str,
    *,
    width_bits: int = 16,
    src_insn: int | None = None,
    block_addr: int | None = None,
    producer_insn: int | None = None,
    taken_target: int | None = None,
    fallthrough_target: int | None = None,
    operand_bind_insn: int | None = None,
    producer_semantics: tuple[Any, ...] | None = None,
    register_bindings: tuple[ConditionRegisterBindingIR, ...] = (),
) -> ConditionResult:
    """Build a ConditionIR from TEST/OR/AND self-test + JCC mnemonic.

    test ax, ax  (or: or ax, ax / and ax, ax where both operands same)
    jz label  →  ConditionIR(ZERO, ax)
    """
    if (
        isinstance(value, IRBinaryValue)
        and value.op in {"and", "or"}
        and value.lhs == value.rhs
    ):
        value = value.lhs
    jcc = jcc.lower()
    if jcc in {"je", "jz"}:
        return ConditionIR(
            op="zero",
            lhs=value,
            width_bits=width_bits,
            source=("test", jcc),
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=producer_insn,
            taken_target=taken_target,
            fallthrough_target=fallthrough_target,
            operand_bind_insn=operand_bind_insn,
            producer_semantics=producer_semantics,
            register_bindings=register_bindings,
        )
    if jcc in {"jne", "jnz"}:
        return ConditionIR(
            op="nonzero",
            lhs=value,
            width_bits=width_bits,
            source=("test", jcc),
            src_insn=src_insn,
            block_addr=block_addr,
            producer_insn=producer_insn,
            taken_target=taken_target,
            fallthrough_target=fallthrough_target,
            operand_bind_insn=operand_bind_insn,
            producer_semantics=producer_semantics,
            register_bindings=register_bindings,
        )
    return ConditionFailure(
        "unsupported_test_jcc",
        source=("test", jcc),
        detail=f"TEST JCC '{jcc}' not supported (only je/jz/jne/jnz)",
    )


def build_condition_from_compare_8616(
    op: ConditionOp,
    lhs: Any,
    rhs: Any,
    *,
    width_bits: int = 16,
    source: tuple[str, ...] = (),
    src_insn: int | None = None,
    block_addr: int | None = None,
    producer_insn: int | None = None,
    taken_target: int | None = None,
    fallthrough_target: int | None = None,
    operand_bind_insn: int | None = None,
    producer_semantics: tuple[Any, ...] | None = None,
    register_bindings: tuple[ConditionRegisterBindingIR, ...] = (),
) -> ConditionIR:
    """Direct ConditionIR constructor from known op and operands."""
    lhs, rhs = _harmonize_condition_pair_8616(lhs, rhs, width_bits)
    return ConditionIR(
        op=op,
        lhs=lhs,
        rhs=rhs,
        width_bits=width_bits,
        source=source,
        src_insn=src_insn,
        block_addr=block_addr,
        producer_insn=producer_insn,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
        operand_bind_insn=operand_bind_insn,
        producer_semantics=producer_semantics,
        register_bindings=register_bindings,
    )


# ── Condition source tracking (on emulator) ──


@dataclass(slots=True)
class ConditionSource:
    """Lightweight record of last CMP/TEST for JCC consumption."""

    kind: str  # "cmp" or "test"
    lhs: Any | None = None
    rhs: Any | None = None
    normalized_lhs: Any | None = None
    normalized_rhs: Any | None = None
    semantics: tuple[Any, ...] | None = None
    fallthrough_from_jcc: str | None = None
    width_bits: int = 16
    addr: int | None = None
    block_addr: int | None = None
    bind_operand_at_jcc: bool = False
    register_bindings: tuple[ConditionRegisterBindingIR, ...] = ()


@dataclass(frozen=True, slots=True)
class ConditionEdgeEvidence:
    """Typed condition evidence for a control-flow edge, not an AST guard yet."""

    edge_block_addr: int
    condition: ConditionIR
    edge_kind: str
    source_jcc: str
    producer_insn: int | None = None
    producer_semantics: tuple[Any, ...] | None = None


# ── Condition sorting/deduplication ──


def condition_sort_key_8616(
    cond: ConditionIR,
) -> tuple[int, int, int, int, int, int, str, str, int, str, str, str, int]:
    """Deterministic sort key for ConditionIR."""
    return (
        cond.block_addr if isinstance(cond.block_addr, int) else -1,
        cond.src_insn if isinstance(cond.src_insn, int) else -1,
        cond.producer_insn if isinstance(cond.producer_insn, int) else -1,
        cond.operand_bind_insn if isinstance(cond.operand_bind_insn, int) else -1,
        cond.taken_target if isinstance(cond.taken_target, int) else -1,
        cond.fallthrough_target if isinstance(cond.fallthrough_target, int) else -1,
        "".join(cond.source),
        cond.op,
        int(cond.producer_semantics is None),
        str(cond.producer_semantics),
        str(cond.lhs) if cond.lhs is not None else "",
        str(cond.rhs) if cond.rhs is not None else "",
        cond.width_bits,
    )


def deduplicate_conditions_8616(conditions: list[ConditionIR]) -> list[ConditionIR]:
    """Return deduplicated, deterministically sorted conditions."""
    seen: set[
        tuple[int, int, int, int, int, int, str, str, int, str, str, str, int]
    ] = set()
    unique: list[ConditionIR] = []
    for cond in sorted(conditions, key=condition_sort_key_8616):
        key = condition_sort_key_8616(cond)
        if key not in seen:
            seen.add(key)
            unique.append(cond)
    return unique


# ── IRValue-based builders (for use with the core IR types) ──


def build_condition_ir_8616(
    op: ConditionOp,
    *args: IRValue,
    expr: tuple[str, ...] | None = None,
    width_bits: int | None = None,
) -> IRCondition:
    """Build an IRCondition from typed op and value args.

    This is the existing IR-layer builder — kept for compatibility.
    Preference: use ConditionIR and its builders above for semantic recovery.
    """
    if width_bits is None:
        width_bits = max((int(arg.size or 0) for arg in args), default=0) * 8 or None
    return IRCondition(op=op, args=tuple(args), expr=expr, width_bits=width_bits)


def coerce_condition_value_size_8616(value: IRValue, size: int) -> IRValue:
    """Return an IRValue with a proven condition width, preserving identity otherwise."""
    if size <= 0 or value.size == size:
        return value
    return replace(value, size=size)


def harmonize_condition_args_8616(*args: IRValue, size: int = 0) -> tuple[IRValue, ...]:
    """Coerce condition operands to a shared byte width before semantic use."""
    target_size = int(size or 0)
    if target_size <= 0:
        target_size = max((int(arg.size or 0) for arg in args), default=0)
    if target_size <= 0:
        return tuple(args)
    return tuple(coerce_condition_value_size_8616(arg, target_size) for arg in args)


def normalize_condition_op_8616(op: str) -> ConditionOp:
    """Normalize condition spellings into the IR condition operator vocabulary."""
    if op in {"and", "or", "not"}:
        return op  # type: ignore[return-value]
    if op in {"masked_nonzero", "nonzero"}:
        return "nonzero"
    if op in {"masked_zero", "zero"}:
        return "zero"
    if op in {
        "eq",
        "ne",
        "slt",
        "sle",
        "sgt",
        "sge",
        "ult",
        "ule",
        "ugt",
        "uge",
        "compare",
    }:
        return op  # type: ignore[return-value]
    if op in {"lt", "le", "gt", "ge"}:
        return f"s{op}"  # type: ignore[return-value]
    if op in {"lt_u", "le_u", "gt_u", "ge_u"}:
        return f"u{op[:-2]}"  # type: ignore[return-value]
    return "compare"


def is_condition_truth_test_8616(op: str) -> bool:
    """Return whether an operator is a truth/zero-style condition test."""
    return normalize_condition_op_8616(op) in {"zero", "nonzero", "and", "or", "not"}


def is_condition_compare_family_8616(op: str) -> bool:
    """Return whether an operator belongs to the explicit comparison family."""
    return normalize_condition_op_8616(op) in {
        "compare",
        "eq",
        "ne",
        "slt",
        "sle",
        "sgt",
        "sge",
        "ult",
        "ule",
        "ugt",
        "uge",
    }


def condition_compare_symbol_8616(op: str) -> str | None:
    """Return the C comparison symbol for normalized compare operators."""
    return _COMPARE_SYMBOLS_8616.get(normalize_condition_op_8616(op))


def is_signed_condition_8616(op: str) -> bool:
    """Return whether an operator represents signed ordering."""
    return normalize_condition_op_8616(op) in {"slt", "sle", "sgt", "sge"}


def is_unsigned_condition_8616(op: str) -> bool:
    """Return whether an operator represents unsigned ordering."""
    return normalize_condition_op_8616(op) in {"ult", "ule", "ugt", "uge"}


_INVERTED_COMPARISON_OPS_8616: dict[str, str] = {
    "CmpEQ": "CmpNE",
    "CmpNE": "CmpEQ",
    "CmpLT": "CmpGE",
    "CmpLE": "CmpGT",
    "CmpGT": "CmpLE",
    "CmpGE": "CmpLT",
}


def inverted_comparison_op_8616(op: str) -> str | None:
    """Return the inverted comparison op name, e.g. ``CmpEQ`` → ``CmpNE``.

    This lives in the IR layer because condition-op inversion is a semantic
    identity that belongs to typed condition representation, not to
    late-rewrite or validation-string normalization.
    """
    return _INVERTED_COMPARISON_OPS_8616.get(op)


def canonicalize_condition_storage_fingerprint_8616(value: str) -> str:
    """Canonicalize explicitly proven BP and DS storage identities.

    Input tokens already carry exact BP offsets or a DS-relative linear
    address.  This is lossless Condition IR fingerprint normalization, not
    recovery from rendered C or a variable name, and it never merges segment
    spaces.
    """

    def _replace(match: re.Match[str]) -> str:
        size = match.group("size")
        size_text = f":size{size}" if size else ""
        return (
            f"stack_slot:SS:BP{match.group('offset')}"
            f"{size_text}"
        )

    stack_normalized = _STACK_ARG_STORAGE_FINGERPRINT_RE_8616.sub(
        _replace,
        value,
    )
    return _canonicalize_ds_storage_fingerprint_8616(stack_normalized)


def _canonicalize_ds_storage_fingerprint_8616(
    value: str,
    *,
    preserve_global_address: bool = False,
) -> str:
    """Project exact DS-relative values onto one segmented storage token."""
    call = _split_fingerprint_call_8616(value)
    if call is None:
        if not preserve_global_address and value.startswith("global:"):
            return f"ds_global:{value[len('global:') :]}"
        return value
    op, args_text = call
    args = _split_fingerprint_args_8616(args_text)
    if op == "Dereference" and len(args) == 1:
        parsed = _linear_ds_offset_fingerprint_8616(args[0])
        if parsed is not None and parsed[0] and parsed[1] >= 0:
            return f"ds_global:{parsed[1]:#x}"
    normalized = [
        _canonicalize_ds_storage_fingerprint_8616(
            arg,
            preserve_global_address=op == "Reference",
        )
        for arg in args
    ]
    if op == "Or":
        normalized = list(dict.fromkeys(normalized))
        # Deduplicating identical proven storage views must retain their
        # scalar identity, not introduce a synthetic unary OR operation.
        if len(normalized) == 1 and normalized[0].startswith(("stack_slot:", "ds_global:")):
            return normalized[0]
    return f"{op}({','.join(normalized)})"


def normalize_condition_fingerprint_string_8616(
    value: str,
    *,
    control_flow_prefixes: tuple[str, ...] | None = None,
) -> str:
    """Canonicalize a condition fingerprint string by inverting ``Not(CmpEQ(...))`` → ``CmpNE(...)``.

    This operates on fingerprint-string representations of conditions.
    The normalization is driven by the IR-layer ``inverted_comparison_op_8616``
    mapping, but the string parsing is fingerprint-format specific.
    """
    if not isinstance(value, str) or not value:
        return value

    if control_flow_prefixes is None:
        control_flow_prefixes = (
            "if:",
            "ifbreak:",
            "while:",
            "dowhile:",
            "for:",
            "switch:",
        )

    for prefix in control_flow_prefixes:
        if value.startswith(prefix):
            return prefix + normalize_condition_fingerprint_string_8616(
                value[len(prefix) :],
                control_flow_prefixes=control_flow_prefixes,
            )

    call = _split_fingerprint_call_8616(value)
    if call is None:
        return value
    op, inner = call
    if op == "Not":
        inner_call = _split_fingerprint_call_8616(inner)
        if inner_call is None:
            return value
        inner_op, inner_args = inner_call
        inverted = inverted_comparison_op_8616(inner_op)
        if inverted is not None:
            return f"{inverted}({inner_args})"
    return value


def invert_condition_fingerprint_string_8616(value: str) -> str | None:
    """Invert a comparison fingerprint while preserving its arguments."""
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return None
    op, inner = call
    if op == "Not":
        return inner
    inverted = inverted_comparison_op_8616(op)
    if inverted is None:
        return None
    return f"{inverted}({inner})"


def _split_fingerprint_call_8616(value: str) -> tuple[str, str] | None:
    """Split ``CmpEQ(reg:ax,#0x0)`` into (``CmpEQ``, ``reg:ax,#0x0``)."""
    if not isinstance(value, str) or not value.endswith(")"):
        return None
    open_idx = value.find("(")
    if open_idx <= 0:
        return None
    return value[:open_idx], value[open_idx + 1 : -1]


def _split_fingerprint_args_8616(args_str: str) -> list[str]:
    """Split fingerprint arguments by top-level commas, respecting nested parens."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in args_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts


def _normalize_segmented_index_duplicate_displacement_8616(value: str) -> str:
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return value
    op, args_str = call
    args = [
        _normalize_segmented_index_duplicate_displacement_8616(arg) for arg in _split_fingerprint_args_8616(args_str)
    ]
    if op != "Add" or len(args) < 3 or args[0] not in {"Mul(reg:ds,const:16)", "Mul(reg:es,const:16)"}:
        return f"{op}({','.join(args)})"

    const_positions = {
        arg: idx for idx, arg in enumerate(args[1:], start=1) if isinstance(arg, str) and arg.startswith("const:")
    }
    for idx, arg in enumerate(args[1:], start=1):
        merged = _merged_duplicate_displacement_args_8616(args, const_positions, idx, arg)
        if merged is not None:
            return f"Add({','.join(merged)})"
    return f"{op}({','.join(args)})"


def _merged_duplicate_displacement_args_8616(
    args: list[str],
    const_positions: dict[str, int],
    idx: int,
    arg: str,
) -> list[str] | None:
    """Merge one inner Add's duplicated const displacement into the outer args."""
    inner = _split_fingerprint_call_8616(arg)
    if inner is None:
        return None
    inner_op, inner_args_str = inner
    if inner_op != "Add":
        return None
    inner_args = _split_fingerprint_args_8616(inner_args_str)
    inner_consts = [part for part in inner_args if part.startswith("const:")]
    if len(inner_consts) != 1:
        return None
    duplicate_idx = const_positions.get(inner_consts[0])
    if duplicate_idx is None or duplicate_idx == idx:
        return None
    merged_args = [args[0]]
    for pos, part in enumerate(args[1:], start=1):
        if pos == duplicate_idx:
            continue
        if pos == idx:
            merged_args.extend(inner_args)
        else:
            merged_args.append(part)
    return merged_args


def normalize_condition_fingerprint_algebraic_8616(value: str) -> str:
    """Apply deterministic algebraic normalization to a condition fingerprint string.

    Rules (validation-only, deterministic, side-effect-free):

        CmpEQ(Sub(x,const:c),const:0) -> CmpEQ(x,const:c)
        CmpNE(Sub(x,const:c),const:0) -> CmpNE(x,const:c)
        CmpEQ(Sub(x,y),const:0) -> CmpEQ(x,y)
        CmpNE(Sub(x,y),const:0) -> CmpNE(x,y)
        Add(x,Neg(y)) -> Sub(x,y)
        Add(Neg(y),x) -> Sub(x,y)

    Also handles doubled Sub nesting:

        CmpEQ(Sub(Sub(x,const:a),const:b),const:0) -> CmpEQ(x,const:a+b)

    This is a pure string-level normalization that preserves the fingerprint
    format. It does not mutate IR or feed results back into recovery.
    """

    return _normalize_algebraic_impl_8616(value)


def _algebraic_zero_cancellation_8616(op: str, args: list[str]) -> str | None:
    """Fold ``x - x`` and ``x + (-x)`` to the exact zero constant."""
    if op == "Sub" and len(args) == 2 and args[0] == args[1]:
        return "const:0"
    if op == "Add" and len(args) == 2:
        for value_arg, negated_arg in ((args[0], args[1]), (args[1], args[0])):
            negated_call = _split_fingerprint_call_8616(negated_arg)
            if negated_call is not None and negated_call[0] == "Neg":
                negated_args = _split_fingerprint_args_8616(negated_call[1])
                if negated_args == [value_arg]:
                    return "const:0"
    return None


def _cmp_sub_zero_rewrite_8616(
    op: str,
    args: list[str],
    normalized_value: str,
) -> str | None:
    """Rewrite ``Cmp(Sub(x, y), const:0)`` to a direct operand comparison."""
    if op not in ("CmpEQ", "CmpNE") or len(args) != 2 or args[1] != "const:0":
        return None
    lhs_call = _split_fingerprint_call_8616(_normalize_arg_fingerprint_8616(args[0]))
    if lhs_call is None:
        return None
    lhs_op, lhs_args = lhs_call
    if lhs_op != "Sub":
        return None
    sub_args = _split_fingerprint_args_8616(lhs_args)
    if len(sub_args) == 2:
        # Sub(x, const:c) == 0  →  x == const:c ; Sub(x, y) == 0  →  x == y
        return f"{op}({sub_args[0]},{sub_args[1]})"
    # Handle nested Sub: Sub(Sub(x, a), b) == 0  →  x == a+b
    if len(sub_args) == 2:
        inner_call = _split_fingerprint_call_8616(sub_args[0])
        if inner_call is not None and inner_call[0] == "Sub":
            inner_args = _split_fingerprint_args_8616(inner_call[1])
            if (
                len(inner_args) == 2
                and inner_args[1].startswith("const:")
                and sub_args[1].startswith("const:")
            ):
                try:
                    a = (
                        int(inner_args[1].split(":")[-1], 0)
                        if inner_args[1].startswith("const:")
                        else 0
                    )
                    b = (
                        int(sub_args[1].split(":")[-1], 0)
                        if sub_args[1].startswith("const:")
                        else 0
                    )
                except (ValueError, IndexError):
                    return normalized_value
                c_sum = a + b
                c_str = f"const:{c_sum:#x}" if c_sum >= 0 else f"const:{c_sum}"
                return f"{op}({inner_args[0]},{c_str})"
    return None


def _normalize_algebraic_impl_8616(value: str) -> str:
    """Apply the algebraic fingerprint rules to one normalized value string."""
    if not isinstance(value, str) or not value:
        return value

    # Handle control-flow prefixes
    for prefix in ("if:", "ifbreak:", "while:", "dowhile:", "for:", "switch:"):
        if value.startswith(prefix):
            return prefix + normalize_condition_fingerprint_algebraic_8616(value[len(prefix) :])

    normalized_value = _normalize_segmented_index_duplicate_displacement_8616(
        normalize_condition_full_width_masks_8616(value)
    )

    call = _split_fingerprint_call_8616(normalized_value)
    if call is None:
        return normalized_value

    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)

    zero = _algebraic_zero_cancellation_8616(op, args)
    if zero is not None:
        return zero

    rewritten = _cmp_sub_zero_rewrite_8616(op, args, normalized_value)
    if rewritten is not None:
        return rewritten

    # Recurse into args for nested normalization
    normalized_args = [_normalize_arg_fingerprint_8616(a) for a in args]
    canonical = _canonicalize_add_neg_fingerprint_8616(op, normalized_args)
    if canonical is not None:
        return canonical
    if normalized_args != args:
        return f"{op}({','.join(normalized_args)})"

    return normalized_value


def _normalize_arg_fingerprint_8616(arg: str) -> str:
    """Recursively normalize a fingerprint arg, handling nested calls."""
    word_pair = _normalize_global_word_pair_arg_fingerprint_8616(arg)
    if word_pair is not None:
        return word_pair
    call = _split_fingerprint_call_8616(arg)
    if call is None:
        return arg
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    normalized_args = [_normalize_arg_fingerprint_8616(a) for a in args]
    canonical = _canonicalize_add_neg_fingerprint_8616(op, normalized_args)
    if canonical is not None:
        return canonical
    return f"{op}({','.join(normalized_args)})"


def _canonicalize_add_neg_fingerprint_8616(
    op: str,
    args: list[str],
) -> str | None:
    """Return canonical subtraction for one exact addition of a negation."""
    if op != "Add" or len(args) != 2:
        return None
    for value, negated in ((args[0], args[1]), (args[1], args[0])):
        # Unit decrement is exact at every width, including modular wraparound.
        if negated == "const:-1":
            return f"Sub({value},const:1)"
        negated_call = _split_fingerprint_call_8616(negated)
        if negated_call is None or negated_call[0] != "Neg":
            continue
        negated_args = _split_fingerprint_args_8616(negated_call[1])
        if len(negated_args) == 1:
            return f"Sub({value},{negated_args[0]})"
    return None


def _normalize_global_word_pair_arg_fingerprint_8616(arg: str) -> str | None:
    call = _split_fingerprint_call_8616(arg)
    if call is None or call[0] != "Or":
        return None
    args = _split_fingerprint_args_8616(call[1])
    if len(args) != 2:
        return None
    low = _global_offset_fingerprint_8616(args[0])
    high = _shifted_ds_byte_offset_fingerprint_8616(args[1])
    if not isinstance(low, int) or not isinstance(high, int):
        low = _global_offset_fingerprint_8616(args[1])
        high = _shifted_ds_byte_offset_fingerprint_8616(args[0])
    if not isinstance(low, int) or not isinstance(high, int):
        return None
    if high != low + 1:
        return None
    return f"global:{low:#x}"


def _global_offset_fingerprint_8616(value: str) -> int | None:
    if not isinstance(value, str) or not value.startswith("global:"):
        return None
    try:
        return int(value[len("global:") :], 0)
    except ValueError:
        return None


def _shifted_ds_byte_offset_fingerprint_8616(value: str) -> int | None:
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return None
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    if op == "Shl" and len(args) == 2 and args[1] == "const:8":
        return _ds_byte_deref_offset_fingerprint_8616(args[0])
    if op == "Mul" and len(args) == 2:
        if args[0] == "const:256":
            return _ds_byte_deref_offset_fingerprint_8616(args[1])
        if args[1] == "const:256":
            return _ds_byte_deref_offset_fingerprint_8616(args[0])
    return None


def _ds_byte_deref_offset_fingerprint_8616(value: str) -> int | None:
    call = _split_fingerprint_call_8616(value)
    if call is None or call[0] != "Dereference":
        return None
    parsed = _linear_ds_offset_fingerprint_8616(call[1])
    if parsed is None:
        return None
    has_ds, offset = parsed
    return offset if has_ds else None


def _linear_ds_offset_fingerprint_8616(value: str) -> tuple[bool, int] | None:
    if value.startswith("const:"):
        try:
            return False, int(value[len("const:") :], 0)
        except ValueError:
            return None
    if value == "reg:ds":
        return True, 0
    call = _split_fingerprint_call_8616(value)
    if call is None:
        return None
    op, args_str = call
    args = _split_fingerprint_args_8616(args_str)
    if op == "Mul" and len(args) == 2 and (args[0], args[1]) in {("reg:ds", "const:16"), ("const:16", "reg:ds")}:
        return True, 0
    if op == "Shl" and len(args) == 2 and args[0] == "reg:ds" and args[1] == "const:4":
        return True, 0
    if op not in {"Add", "Sub"} or not args:
        return None
    return _fold_linear_ds_args_8616(op, args)


def _fold_linear_ds_args_8616(op: str, args: list[str]) -> tuple[bool, int] | None:
    """Fold Add/Sub argument offsets into one linear ds+offset result."""
    has_ds = False
    offset = 0
    for index, arg in enumerate(args):
        parsed = _linear_ds_offset_fingerprint_8616(arg)
        if parsed is None:
            return None
        arg_has_ds, arg_offset = parsed
        sign = -1 if op == "Sub" and index > 0 else 1
        if arg_has_ds:
            if has_ds or sign < 0:
                return None
            has_ds = True
        offset += sign * arg_offset
    return has_ds, offset
