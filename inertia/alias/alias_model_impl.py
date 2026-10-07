"""Canonical alias storage facts and identity model.

Layer: Alias.
Responsibility: owns storage identity for registers, stack slots, and memory views.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
Dynamic boundary: this module reads third-party angr SimVariable attributes
through getattr when translating them into owned alias facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .domains import register_pair_name


def _simvariable_attr_8616(variable: object, name: str, default: object = None) -> object:
    """Dynamic third-party angr boundary: read optional SimVariable attributes."""
    return getattr(variable, name, default)


def _simvariable_int_attr_8616(variable: object, name: str, default: int = 0) -> int:
    """Dynamic third-party angr boundary: read an integer SimVariable attribute."""
    value = _simvariable_attr_8616(variable, name, default)
    return value if isinstance(value, int) else default


def _simvariable_optional_int_attr_8616(variable: object, name: str) -> int | None:
    """Dynamic third-party angr boundary: read an optional integer SimVariable attribute."""
    value = _simvariable_attr_8616(variable, name)
    return value if isinstance(value, int) else None


def _simvariable_optional_str_attr_8616(variable: object, name: str) -> str | None:
    """Dynamic third-party angr boundary: read an optional string SimVariable attribute."""
    value = _simvariable_attr_8616(variable, name)
    return value if isinstance(value, str) else None


def _canonical_stack_base(base: str | None) -> str:
    """Normalize stack-base spelling without inventing a frame relation."""
    if not isinstance(base, str) or not base:
        return "bp"
    return base.lower()


@dataclass(frozen=True)
class _StorageView:
    bit_offset: int = 0
    bit_width: int | None = None

    def is_full_width(self) -> bool:
        """Return whether this view starts at bit zero with a known width."""
        return self.bit_offset == 0 and self.bit_width is not None

    def end_bit(self) -> int | None:
        """Return the exclusive ending bit offset when width is known."""
        if self.bit_width is None:
            return None
        return self.bit_offset + self.bit_width

    def can_join(self, other: _StorageView) -> bool:
        """Return whether two bit views are adjacent and fully bounded."""
        if self.bit_width is None or other.bit_width is None:
            return False
        return self.end_bit() == other.bit_offset or other.end_bit() == self.bit_offset

    def contains(self, other: _StorageView) -> bool:
        """Return whether this bounded bit view fully contains another view."""
        end_bit = self.end_bit()
        other_end_bit = other.end_bit()
        if end_bit is None or other_end_bit is None:
            return False
        return self.bit_offset <= other.bit_offset and other_end_bit <= end_bit

    def join(self, other: _StorageView) -> _StorageView | None:
        """Return a combined bit view when two storage views are adjacent."""
        bit_width = self.bit_width
        other_bit_width = other.bit_width
        if bit_width is None or other_bit_width is None:
            return None
        if self.bit_offset <= other.bit_offset:
            first, second = self, other
        else:
            first, second = other, self
        if first.end_bit() != second.bit_offset:
            return None
        first_width = first.bit_width
        second_width = second.bit_width
        if first_width is None or second_width is None:
            return None
        return _StorageView(first.bit_offset, first_width + second_width)


@dataclass(frozen=True)
class _StackSlotIdentity:
    base: str
    offset: int
    width: int | None = None
    region: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "base", _canonical_stack_base(self.base))

    def end_offset(self) -> int | None:
        """Return the exclusive ending byte offset when width is known."""
        if self.width is None:
            return None
        return self.offset + self.width

    def can_join(self, other: _StackSlotIdentity) -> bool:
        """Return whether two stack slots are adjacent within one frame region."""
        if self.base != other.base:
            return False
        if self.region is not None and other.region is not None and self.region != other.region:
            return False
        if self.width is None or other.width is None:
            return False
        return self.end_offset() == other.offset or other.end_offset() == self.offset

    def contains(self, other: _StackSlotIdentity) -> bool:
        """Return whether this stack slot fully contains another frame view."""
        if self.base != other.base:
            return False
        if self.region is not None and other.region is not None and self.region != other.region:
            return False
        end_offset = self.end_offset()
        other_end_offset = other.end_offset()
        if end_offset is None or other_end_offset is None:
            return False
        return self.offset <= other.offset and other_end_offset <= end_offset

    def join(self, other: _StackSlotIdentity) -> _StackSlotIdentity | None:
        """Return a combined stack slot identity when adjacent slots match."""
        if not self.can_join(other):
            return None
        if self.offset <= other.offset:
            first, second = self, other
        else:
            first, second = other, self
        if first.end_offset() != second.offset:
            return None
        region = first.region if first.region == second.region else first.region or second.region
        first_width = first.width
        second_width = second.width
        if first_width is None or second_width is None:
            return None
        return _StackSlotIdentity(first.base, first.offset, first_width + second_width, region=region)


def _storage_view_for_variable(variable: object) -> _StorageView:
    def _impl() -> _StorageView:
        size = _simvariable_int_attr_8616(variable, "size")
        width_bits = size * 8 if size else None
        name = (
            _simvariable_optional_str_attr_8616(variable, "ident")
            or _simvariable_optional_str_attr_8616(variable, "name")
            or ""
        ).lower()
        if isinstance(variable, SimRegisterVariable):
            low_high_offsets = {
                "al": 0,
                "ah": 8,
                "bl": 0,
                "bh": 8,
                "cl": 0,
                "ch": 8,
                "dl": 0,
                "dh": 8,
            }
            if name in low_high_offsets:
                return _StorageView(low_high_offsets[name], width_bits)
            reg = _simvariable_attr_8616(variable, "reg")
            if isinstance(reg, int) and size in {1, 2}:
                if size == 1:
                    return _StorageView(8 if reg % 2 else 0, 8)
                return _StorageView(0, width_bits)
        if isinstance(variable, SimStackVariable):
            return _StorageView(_simvariable_int_attr_8616(variable, "offset") * 8, width_bits)
        if isinstance(variable, SimMemoryVariable):
            addr = _simvariable_attr_8616(variable, "addr", 0)
            if isinstance(addr, int):
                return _StorageView(addr * 8, width_bits)
        return _StorageView(0, width_bits)

    return _impl()


@dataclass(frozen=True)
class _StorageDomainSignature:
    space: str
    width: int | None = None
    view: _StorageView | None = None
    stack_slot: _StackSlotIdentity | None = field(default=None, compare=False)

    def is_mixed(self) -> bool:
        """Return whether this domain combines incompatible storage identities."""
        return self.space == "mixed"

    def is_unknown(self) -> bool:
        """Return whether this domain lacks a proven storage identity."""
        return self.space == "unknown"

    def is_const(self) -> bool:
        """Return whether this domain represents a constant value."""
        return self.space == "const"

    def __str__(self) -> str:
        if self.width is None:
            return self.space
        return f"{self.space}:{self.width}"

    def can_join(self, other: _StorageDomainSignature) -> bool:
        """Return whether two storage domains can join without changing identity."""
        if self.space != other.space:
            return False
        if self.view is None or other.view is None:
            return False
        if self.space == "stack":
            if self.stack_slot is None or other.stack_slot is None:
                return self.view.can_join(other.view)
            if not self.stack_slot.can_join(other.stack_slot):
                return False
        return self.view.can_join(other.view)

    def contains(self, other: _StorageDomainSignature) -> bool:
        """Return whether this storage domain fully contains another domain."""
        if self.space != other.space:
            return False
        if self.view is None or other.view is None:
            return False
        if self.space == "stack":
            if self.stack_slot is None or other.stack_slot is None:
                return False
            if not self.stack_slot.contains(other.stack_slot):
                return False
        return self.view.contains(other.view)

    def join(self, other: _StorageDomainSignature) -> _StorageDomainSignature | None:
        """Return a joined storage domain when identity and views agree."""
        if not self.can_join(other):
            return None
        view = self.view
        other_view = other.view
        if view is None or other_view is None:
            return None
        joined_view = view.join(other_view)
        if joined_view is None:
            return None
        width = self.width or 0
        other_width = other.width or 0
        stack_slot = None
        if self.space == "stack" and self.stack_slot is not None and other.stack_slot is not None:
            stack_slot = self.stack_slot.join(other.stack_slot)
        return _StorageDomainSignature(self.space, width + other_width, joined_view, stack_slot=stack_slot)


@dataclass(frozen=True)
class _CopyAliasState:
    domain: _StorageDomainSignature
    expr: object
    needs_synthesis: bool = False

    def can_inline(self) -> bool:
        """Return whether this copy alias can be inlined without synthesis."""
        return not self.domain.is_mixed() and not self.needs_synthesis

    def merge(self, other: _CopyAliasState) -> _CopyAliasState:
        """Merge two copy-alias states while preserving synthesis requirements."""
        merged_domain = _merge_storage_domains(self.domain, other.domain)
        merged_expr = self.expr if self.expr is not None else other.expr
        merged_needs_synthesis = self.needs_synthesis or other.needs_synthesis
        if merged_domain.is_mixed():
            merged_needs_synthesis = True
            merged_expr = other.expr
        return _CopyAliasState(merged_domain, merged_expr, needs_synthesis=merged_needs_synthesis)


@dataclass(frozen=True)
class _StackPointerAliasState:
    base: structured_c.CVariable
    offset: int = 0

    def shifted(self, delta: int) -> _StackPointerAliasState:
        """Return this stack-pointer alias state shifted by a byte delta."""
        return _StackPointerAliasState(self.base, self.offset + delta)


@dataclass(frozen=True)
class AliasStorageFacts:
    """Alias domain, identity, and view facts for one recovered storage expression."""

    domain: _StorageDomainSignature
    identity: tuple[str, object] | None = None

    def same_domain(self, other: AliasStorageFacts) -> bool:
        """Return whether two facts refer to the same alias storage domain."""
        if self.domain.space != other.domain.space:
            return False
        if self.identity is None or other.identity is None:
            return True
        kind, value = self.identity
        other_kind, other_value = other.identity
        if kind != other_kind:
            return False
        if kind == "register":
            return value == other_value
        if kind == "stack":
            return value == other_value or (
                isinstance(value, _StackSlotIdentity)
                and isinstance(other_value, _StackSlotIdentity)
                and value.can_join(other_value)
            )
        if kind in {"memory", "far_pointer"}:
            return value == other_value
        return value == other_value

    def compatible_view(self, other: AliasStorageFacts) -> bool:
        """Return whether two facts describe adjacent or compatible storage views."""
        if self.domain.view is None or other.domain.view is None:
            return False
        return self.domain.view.can_join(other.domain.view)

    def contains(self, other: AliasStorageFacts) -> bool:
        """Return whether this proven storage identity contains another view."""
        if self.needs_synthesis() or other.needs_synthesis():
            return False
        if self.identity is None or other.identity is None:
            return False
        kind, value = self.identity
        other_kind, other_value = other.identity
        if kind != other_kind:
            return False
        if kind == "stack":
            if not isinstance(value, _StackSlotIdentity) or not isinstance(other_value, _StackSlotIdentity):
                return False
            if not value.contains(other_value):
                return False
        elif value != other_value:
            return False
        return self.domain.contains(other.domain)

    def needs_synthesis(self) -> bool:
        """Return whether this storage fact must remain explicitly synthesized."""
        return self.domain.is_mixed() or self.domain.is_unknown()

    def can_join(self, other: AliasStorageFacts) -> bool:
        """Return whether two facts can be joined without guessing storage identity."""
        return (
            self.same_domain(other)
            and self.compatible_view(other)
            and not self.needs_synthesis()
            and not other.needs_synthesis()
        )


@dataclass(frozen=True)
class AliasRecoveryAPISpec:
    """Documented alias recovery API surface exported to architecture checks."""

    name: str
    purpose: str
    helpers: tuple[str, ...]


def _storage_domain_for_variable(variable: object) -> _StorageDomainSignature:
    if isinstance(variable, SimStackVariable):
        width = _simvariable_int_attr_8616(variable, "size")
        base = _canonical_stack_base(_simvariable_optional_str_attr_8616(variable, "base"))
        offset = _simvariable_int_attr_8616(variable, "offset")
        region = _simvariable_optional_int_attr_8616(variable, "region")
        return _StorageDomainSignature(
            "stack",
            width,
            _storage_view_for_variable(variable),
            stack_slot=_StackSlotIdentity(base, offset, width, region=region),
        )
    if isinstance(variable, SimRegisterVariable):
        width = _simvariable_int_attr_8616(variable, "size")
        return _StorageDomainSignature("register", width, _storage_view_for_variable(variable))
    if isinstance(variable, SimMemoryVariable):
        width = _simvariable_int_attr_8616(variable, "size")
        return _StorageDomainSignature("memory", width, _storage_view_for_variable(variable))
    return _StorageDomainSignature("unknown")


def _alias_identity_for_variable(variable: object) -> tuple[str, object] | None:
    def _impl() -> tuple[str, object] | None:
        if isinstance(variable, SimStackVariable):
            slot = _stack_slot_identity_for_variable(variable)
            if slot is not None:
                return ("stack", slot)
        if isinstance(variable, SimRegisterVariable):
            name = _simvariable_optional_str_attr_8616(variable, "name")
            reg = _simvariable_attr_8616(variable, "reg")
            size = _simvariable_int_attr_8616(variable, "size")
            if isinstance(reg, int) and size in {1, 2}:
                pair_index = reg // 2
                pair_names = ("ax", "cx", "dx", "bx")
                if 0 <= pair_index < len(pair_names):
                    return ("register", pair_names[pair_index])
            pair_name = register_pair_name(name)
            if pair_name is not None:
                return ("register", pair_name)
        if isinstance(variable, SimMemoryVariable):
            addr = _simvariable_attr_8616(variable, "addr")
            if isinstance(addr, int):
                return ("memory", addr)
        return None

    return _impl()


def _canonical_stack_offset(offset: object) -> object:
    if not isinstance(offset, int):
        return offset
    # 16-bit stack slots may surface through wrapped unsigned offsets such as
    # 0xfffe for BP-2. Canonicalize those identities before local/materialized
    # consumers compare slots.
    if 0x8000 <= offset <= 0xFFFF:
        return offset - 0x10000
    return offset


def _stack_slot_identity_for_variable(variable: object) -> _StackSlotIdentity | None:
    """Classify an exact stack variable, refusing other boundary objects."""
    if not isinstance(variable, SimStackVariable):
        return None
    base = _canonical_stack_base(_simvariable_optional_str_attr_8616(variable, "base"))
    offset = _canonical_stack_offset(_simvariable_attr_8616(variable, "offset", 0))
    if not isinstance(offset, int):
        return None
    width_value = _simvariable_int_attr_8616(variable, "size")
    width = width_value or None
    region = _simvariable_optional_int_attr_8616(variable, "region")
    return _StackSlotIdentity(base, offset, width, region=region)


def _stack_storage_facts_for_segmented_address_8616(
    segment_name: str | None,
    offset: int | None,
    width: int | None,
    *,
    base: str = "bp",
    region: int | None = None,
) -> AliasStorageFacts | None:
    """Build stack facts while preserving the evidence-proven address base."""
    if not isinstance(segment_name, str) or segment_name.lower() != "ss":
        return None
    if not isinstance(offset, int):
        return None

    stack_width = width if isinstance(width, int) and width > 0 else None
    bit_width = stack_width * 8 if stack_width is not None else None
    stack_slot = _StackSlotIdentity(base, offset, stack_width, region=region)
    domain = _StorageDomainSignature(
        "stack",
        stack_width,
        _StorageView(offset * 8, bit_width),
        stack_slot=stack_slot,
    )
    return AliasStorageFacts(domain=domain, identity=("stack", stack_slot))


def _same_stack_slot_identity(lhs: object, rhs: object) -> bool:
    if not isinstance(lhs, SimStackVariable) or not isinstance(rhs, SimStackVariable):
        return False
    lhs_identity = _stack_slot_identity_for_variable(lhs)
    rhs_identity = _stack_slot_identity_for_variable(rhs)
    if lhs_identity is None or rhs_identity is None:
        return False
    return lhs_identity == rhs_identity


def _stack_slot_identity_can_join(lhs: object, rhs: object) -> bool:
    if not isinstance(lhs, SimStackVariable) or not isinstance(rhs, SimStackVariable):
        return False
    lhs_identity = _stack_slot_identity_for_variable(lhs)
    rhs_identity = _stack_slot_identity_for_variable(rhs)
    if lhs_identity is None or rhs_identity is None:
        return False
    return lhs_identity.can_join(rhs_identity)


def _derived_stack_high_byte_follows_slot(
    address_base: object,
    address_byte_offset: int,
    low_byte: object,
) -> bool:
    """Prove that an alias-derived stack byte immediately follows a low byte slot.

    Address expressions may retain an angr stack carrier such as ``&v1 - 1``
    after the byte at ``BP-2`` has already become a named stack CVariable.  The
    carrier and the named variable still share one Alias-owned frame coordinate;
    widening may join them only when this proof establishes the exact low/high
    byte order in the same base and region.
    """
    if not isinstance(address_byte_offset, int):
        return False
    base_identity = _stack_slot_identity_for_variable(address_base)
    low_identity = _stack_slot_identity_for_variable(low_byte)
    if base_identity is None or low_identity is None or low_identity.width != 1:
        return False
    derived_high = _StackSlotIdentity(
        base_identity.base,
        base_identity.offset + address_byte_offset,
        1,
        region=base_identity.region,
    )
    if derived_high.base != low_identity.base:
        return False
    if (
        derived_high.region is not None
        and low_identity.region is not None
        and derived_high.region != low_identity.region
    ):
        return False
    return derived_high.offset == low_identity.offset + 1


def _storage_domain_for_expr(expr: object) -> _StorageDomainSignature:
    """Delegate storage-domain classification to the typed query owner."""
    from inertia.semantics.alias_query import _storage_domain_for_expr as _impl

    return _impl(expr)


@dataclass(frozen=True)
class AliasFailure:
    """Explicit failure record when alias recovery cannot resolve a proven address.

    AGENTS rule: proven SS must become stack slot, never silently fallback to memory.
    """

    reason: str
    address: object | None = None
    space: str | None = None
    offset: int | None = None


def alias_facts_for_ir_address_8616(addr: object) -> AliasStorageFacts | AliasFailure | None:
    """Build alias storage facts from a typed IRAddress.

    This is the canonical IR to Alias entry point. It must be called at IR
    creation time, not later in the pipeline.

    Returns `AliasStorageFacts` on success, `AliasFailure` when the address
    cannot be classified yet, and `None` for genuinely unclassifiable values.
    Raises `PipelineHardError` for proven addresses that cannot be resolved.
    """

    def _impl() -> AliasStorageFacts | AliasFailure | None:
        from inertia.pipeline.errors import PipelineHardError

        from inertia.ir.core import AddressStatus, IRAddress, MemSpace, is_stack_address_8616

        if not isinstance(addr, IRAddress):
            return None

        if addr.space == MemSpace.SS:
            # Only create stable stack facts when all conditions are met:
            #   1. Base contains "bp"
            #   2. Status is STABLE
            #   3. Offset is an integer (not symbolic)
            # IMPORTANT:
            # ("sp",) alone is NOT sufficient.
            # Stability additionally requires:
            #   - proven SP delta
            #   - stable offset
            #
            # Dynamic SP traffic must remain PROVISIONAL.
            has_stack_base = addr.base in {("bp",), ("sp",)}
            has_stable_offset = isinstance(addr.offset, int) and addr.status == AddressStatus.STABLE

            if is_stack_address_8616(addr) and has_stack_base and has_stable_offset:
                stack_base = addr.base[0]
                return _stack_storage_facts_for_segmented_address_8616(
                    "ss",
                    addr.offset,
                    addr.size,
                    base=stack_base,
                    region=None,
                )

            # Hard-fail only for STABLE SS addresses without a recognized BP base.
            # PROVISIONAL SS addresses (e.g. SP-relative push/pop during prologue
            # before BP is set up, or symbolic offsets not yet resolved) are expected
            # and must not block decompilation.
            if addr.status == AddressStatus.STABLE:
                raise PipelineHardError(
                    f"unresolved SS address: base={addr.base} offset={addr.offset} status={addr.status}",
                    layer="alias",
                )
            # PROVISIONAL SS: return explicit AliasFailure — not silently hidden
            return AliasFailure(
                reason="provisional SS address cannot be classified",
                address=addr,
                space="SS",
                offset=addr.offset if isinstance(addr.offset, int) else None,
            )

        # DS/ES memory
        if addr.space in {MemSpace.DS, MemSpace.ES}:
            if addr.base or addr.base_values:
                return AliasFailure(
                    reason="indexed DS/ES address requires symbolic Alias projection",
                    address=addr,
                    space=addr.space.value.upper(),
                    offset=addr.offset if isinstance(addr.offset, int) else None,
                )
            return AliasStorageFacts(
                domain=_StorageDomainSignature(
                    "memory",
                    addr.size,
                    _StorageView(
                        addr.offset * 8 if isinstance(addr.offset, int) else 0, addr.size * 8 if addr.size else None
                    ),
                ),
                identity=("memory", addr.offset) if isinstance(addr.offset, int) else None,
            )

        return None

    return _impl()


def describe_alias_storage(expr: object) -> AliasStorageFacts:
    """Describe alias storage for a decompiler expression."""
    from inertia.semantics.alias_query import describe_alias_storage as _impl

    return _impl(expr)


def same_alias_storage_domain(lhs: object, rhs: object) -> bool:
    """Return whether two expressions belong to the same alias storage domain."""
    from inertia.semantics.alias_query import same_alias_storage_domain as _impl

    return bool(_impl(lhs, rhs))


def compatible_alias_storage_views(lhs: object, rhs: object) -> bool:
    """Return whether two expression storage views are compatible."""
    from inertia.semantics.alias_query import compatible_alias_storage_views as _impl

    return bool(_impl(lhs, rhs))


def needs_alias_synthesis(expr: object) -> bool:
    """Return whether an expression requires synthesized alias storage."""
    from inertia.semantics.alias_query import needs_alias_synthesis as _impl

    return bool(_impl(expr))


def can_join_alias_storage(lhs: object, rhs: object) -> bool:
    """Return whether two expression storage facts can be joined."""
    from inertia.semantics.alias_query import can_join_alias_storage as _impl

    return bool(_impl(lhs, rhs))


def contains_alias_storage(container: object, subview: object) -> bool:
    """Return whether one expression's proven storage contains another view."""
    from inertia.semantics.alias_query import contains_alias_storage as _impl

    return bool(_impl(container, subview))


ALIAS_RECOVERY_API: tuple[AliasRecoveryAPISpec, ...] = (
    AliasRecoveryAPISpec(
        name="same_domain",
        purpose="Determine whether two expressions belong to the same storage family.",
        helpers=("same_alias_storage_domain",),
    ),
    AliasRecoveryAPISpec(
        name="compatible_view",
        purpose="Determine whether two expressions can join as adjacent or compatible slices.",
        helpers=("compatible_alias_storage_views",),
    ),
    AliasRecoveryAPISpec(
        name="needs_synthesis",
        purpose="Detect mixed or unknown storage that should remain explicitly synthesized.",
        helpers=("needs_alias_synthesis",),
    ),
    AliasRecoveryAPISpec(
        name="can_join",
        purpose="Check the downstream-ready join condition used by widening and object recovery.",
        helpers=("can_join_alias_storage",),
    ),
    AliasRecoveryAPISpec(
        name="contains",
        purpose="Prove that a wider storage identity contains a narrower view before projection folding.",
        helpers=("contains_alias_storage",),
    ),
)


def describe_x86_16_alias_recovery_api() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Return documented alias recovery API entries for reports and guards."""
    return tuple((spec.name, spec.purpose, spec.helpers) for spec in ALIAS_RECOVERY_API)


def _merge_storage_domains(
    existing: _StorageDomainSignature | None, incoming: _StorageDomainSignature
) -> _StorageDomainSignature:
    if existing is None:
        return incoming
    if existing == incoming:
        return existing
    joined = existing.join(incoming)
    if joined is not None:
        return joined
    return _StorageDomainSignature("mixed")


def _unwrap_c_casts(expr: object) -> object:
    from inertia.semantics.expression_analysis import _unwrap_c_casts as _impl

    return _impl(expr)


__all__ = [
    "ALIAS_RECOVERY_API",
    "AliasFailure",
    "AliasRecoveryAPISpec",
    "AliasStorageFacts",
    "_CopyAliasState",
    "_StackPointerAliasState",
    "_StackSlotIdentity",
    "_StorageDomainSignature",
    "_StorageView",
    "_derived_stack_high_byte_follows_slot",
    "_merge_storage_domains",
    "_same_stack_slot_identity",
    "_stack_slot_identity_can_join",
    "_stack_slot_identity_for_variable",
    "_stack_storage_facts_for_segmented_address_8616",
    "_storage_domain_for_expr",
    "_storage_domain_for_variable",
    "_storage_view_for_variable",
    "alias_facts_for_ir_address_8616",
    "can_join_alias_storage",
    "compatible_alias_storage_views",
    "contains_alias_storage",
    "describe_alias_storage",
    "describe_x86_16_alias_recovery_api",
    "needs_alias_synthesis",
    "same_alias_storage_domain",
]
