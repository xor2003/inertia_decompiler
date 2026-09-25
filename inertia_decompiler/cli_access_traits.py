"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia_decompiler.cli_access_profiles import (
    AccessTraitStrideEvidence,
    build_access_trait_evidence_profiles,
    infer_induction_variable,
)
from inertia_decompiler.cli_induction_rewrite import (
    BuildAccessTraitEvidenceProfiles,
    InferInductionVariable,
    rewrite_for_loop_conditions_from_access_traits,
)
from inertia_decompiler.cli_induction_rewrite import (
    _CodegenLike as InductionCodegenLike,
)
from inertia_decompiler.cli_induction_rewrite import (
    _ProjectLike as InductionProjectLike,
)

type BaseKey = tuple[object, ...]
type TraitBucket = dict[BaseKey, object]
type Traits = dict[str, TraitBucket]
type AddressSummary = tuple[list[object], int, list[tuple[BaseKey, int]]]
type AddressSummarizer = Callable[[object], AddressSummary]
type BaseKeyResolver = Callable[[object], BaseKey | None]
type TraitRecorder = Callable[[str, BaseKey], None]
type NodeIterator = Callable[[object], Iterable[object]]
type CastUnwrapper = Callable[[object], object]
type ConstantResolver = Callable[[object], int | None]
type StackIdentityResolver = Callable[[object], "_StackSlotIdentityLike | None"]
type StrideEvidenceRecorder = Callable[..., None]


class _ArchLike(Protocol):
    """Architecture width surface used to size C dereference nodes."""

    byte_width: int


class _ProjectLike(Protocol):
    """angr project surface used by access-trait collection."""

    arch: _ArchLike
    _inertia_access_traits: object


class _StackSlotIdentityLike(Protocol):
    """Stack-slot identity contract returned by the owning stack helper."""

    base: object


class _SegmentedDereferenceLike(Protocol):
    """Classified segmented dereference contract supplied by CLI C AST rewrites."""

    addr_expr: object
    seg_name: str


def _prune_sparse_trait_counts(traits: Traits) -> None:
    for key, count in list(traits["repeated_offsets"].items()):
        if isinstance(count, int) and count < 2:
            del traits["repeated_offsets"][key]
    for key, count in list(traits["base_stride"].items()):
        if isinstance(count, int) and count < 2:
            del traits["base_stride"][key]


def _node_access_size(project: _ProjectLike, node: object) -> int:
    # Dynamic codegen boundary: angr structured-C nodes may omit type metadata.
    type_ = getattr(node, "type", None)
    # Dynamic codegen boundary: angr type objects expose size only when available.
    bits = getattr(type_, "size", None)
    return max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)


def _record_plain_base_evidence(
    *,
    node: object,
    access_size: int,
    summarize_address: AddressSummarizer,
    stable_base_key: BaseKeyResolver,
    record: TraitRecorder,
) -> None:
    # Dynamic codegen boundary: dereference operands are supplied by angr structured C.
    plain_base_terms, plain_offset, plain_stride_terms = summarize_address(getattr(node, "operand", None))
    if len(plain_base_terms) != 1 or not isinstance(plain_base_terms[0], structured_c.CVariable):
        return
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    plain_base_var = getattr(plain_base_terms[0], "variable", None)
    if not isinstance(plain_base_var, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
        return
    plain_base_key = stable_base_key(plain_base_var)
    if plain_base_key is None:
        return
    if plain_offset != 0:
        record("member_evidence", (plain_base_key, plain_offset, access_size))
    for index_key, stride in plain_stride_terms:
        if index_key is None or stride not in {2, 4, 8}:
            continue
        record("array_evidence", (plain_base_key, index_key, stride, plain_offset, access_size))


def _record_segmented_evidence(
    *,
    project: _ProjectLike,
    node: object,
    access_size: int,
    classify_segmented_dereference: Callable[[object, _ProjectLike], _SegmentedDereferenceLike | None],
    summarize_address: AddressSummarizer,
    access_trait_variable_key: BaseKeyResolver,
    record: TraitRecorder,
    record_stride_evidence: StrideEvidenceRecorder,
) -> None:
    def _impl() -> None:
        classified = classify_segmented_dereference(node, project)
        if classified is None:
            return
        base_terms, offset, stride_terms = summarize_address(classified.addr_expr)
        base_key: BaseKey | None = None
        if len(base_terms) == 1 and isinstance(base_terms[0], structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            base_var = getattr(base_terms[0], "variable", None)
            base_key = access_trait_variable_key(base_var)
            if base_key is not None:
                record("base_const", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offsets", (classified.seg_name, base_key, offset))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
        for index_key, stride in stride_terms:
            if index_key is None or base_key is None:
                continue
            record("base_stride", (classified.seg_name, index_key, stride, offset, access_size))
            record("base_stride_widths", (classified.seg_name, index_key, stride, offset, access_size))
            if index_key[0] in {"reg", "stack"}:
                record_stride_evidence(
                    kind="induction_like",
                    seg_name=classified.seg_name,
                    base_key=base_key,
                    index_key=index_key,
                    stride=stride,
                    offset=offset,
                    access_size=access_size,
                )
            if stride in {2, 4, 8}:
                evidence_bucket = "array_evidence" if offset == 0 else "member_evidence"
                record(
                    evidence_bucket,
                    (classified.seg_name, index_key, stride, offset, access_size),
                )
                record_stride_evidence(
                    kind="array_like" if offset == 0 else "member_like",
                    seg_name=classified.seg_name,
                    base_key=base_key,
                    index_key=index_key,
                    stride=stride,
                    offset=offset,
                    access_size=access_size,
                )

    return _impl()

def _new_traits_8616() -> Traits:
    """Return the empty per-function access-trait buckets."""
    return {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }


@dataclass(slots=True)
class _AccessTraitCollector:
    """Collect one function's access-trait evidence from structured C."""

    project: _ProjectLike
    codegen: InductionCodegenLike
    cfunc: object
    cache: object
    iter_c_nodes_deep: NodeIterator
    unwrap_c_casts: CastUnwrapper
    c_constant_value: ConstantResolver
    classify_segmented_dereference: Callable[
        [object, _ProjectLike], _SegmentedDereferenceLike | None
    ]
    stack_slot_identity_for_variable: StackIdentityResolver
    access_trait_variable_key: BaseKeyResolver
    stride_evidence_type: type[AccessTraitStrideEvidence]
    traits: Traits = field(default_factory=_new_traits_8616)

    def record(self, bucket: str, key: BaseKey) -> None:
        """Bump one bucket count, tolerating a cached non-int value."""
        store = self.traits[bucket]
        existing = store.get(key, 0)
        store[key] = (existing if isinstance(existing, int) else 0) + 1

    def record_stride_evidence(
        self,
        *,
        kind: str,
        seg_name: str,
        base_key: tuple[object, ...] | None,
        index_key: tuple[object, ...] | None,
        stride: int,
        offset: int,
        access_size: int,
    ) -> None:
        """Accumulate typed stride evidence for one index carrier."""
        if index_key is None:
            return
        evidence_key = (kind, seg_name, base_key, index_key, stride, offset, access_size)
        bucket_name = "induction_evidence" if kind == "induction_like" else "stride_evidence"
        existing = self.traits[bucket_name].get(evidence_key)
        existing_count = existing.count if isinstance(existing, self.stride_evidence_type) else existing
        if not isinstance(existing_count, int):
            existing_count = None
        count = 1 if existing_count is None else int(existing_count) + 1
        self.traits[bucket_name][evidence_key] = self.stride_evidence_type(
            segment=seg_name,
            base_key=base_key,
            index_key=index_key,
            stride=stride,
            offset=offset,
            width=access_size,
            count=count,
            kind=kind,
        )

    def stable_base_key(self, variable: object) -> BaseKey | None:
        """Map one angr variable onto a stable storage-identity key."""
        if isinstance(variable, SimRegisterVariable):
            return ("reg", variable.reg)
        if isinstance(variable, SimStackVariable):
            identity = self.stack_slot_identity_for_variable(variable)
            if identity is None:
                return None
            return ("stack", identity.base, variable.offset, variable.region)
        if isinstance(variable, SimMemoryVariable):
            return ("mem", variable.addr)
        return None

    def expr_index_key(self, expr: object) -> BaseKey | None:
        """Resolve one expression to a stack-carried index identity."""
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
            return self.access_trait_variable_key(getattr(expr, "variable", None))
        if isinstance(expr, structured_c.CUnaryOp) and expr.op == "Dereference":
            # Dynamic codegen boundary: unary operands are supplied by angr structured C.
            operand = self.unwrap_c_casts(getattr(expr, "operand", None))
            if isinstance(operand, structured_c.CUnaryOp) and operand.op == "Reference":
                # Dynamic codegen boundary: reference operands are supplied by angr structured C.
                expr = self.unwrap_c_casts(getattr(operand, "operand", None))
            else:
                return None
        if isinstance(expr, structured_c.CIndexedVariable):
            return self._indexed_expr_key(expr)
        return None

    def _indexed_expr_key(self, expr: object) -> BaseKey | None:
        """Resolve an indexed-variable base+offset identity."""
        # Dynamic codegen boundary: indexed variable bases are supplied by angr structured C.
        base_expr = self.unwrap_c_casts(getattr(expr, "variable", None))
        if isinstance(base_expr, structured_c.CUnaryOp) and base_expr.op == "Reference":
            # Dynamic codegen boundary: reference operands are supplied by angr structured C.
            base_expr = self.unwrap_c_casts(getattr(base_expr, "operand", None))
        # Dynamic codegen boundary: indexed variable indexes are supplied by angr structured C.
        index = self.c_constant_value(self.unwrap_c_casts(getattr(expr, "index", None)))
        if not isinstance(index, int) or not isinstance(base_expr, structured_c.CVariable):
            return None
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        base_var = getattr(base_expr, "variable", None)
        if not isinstance(base_var, SimStackVariable):
            return None
        identity = self.stack_slot_identity_for_variable(base_var)
        if identity is None:
            return None
        base_offset = base_var.offset
        if not isinstance(base_offset, int):
            return None
        return ("stack", identity.base, base_offset + index, base_var.region)

    def _product_stride_term(self, inner: object) -> tuple[BaseKey, int] | None:
        """Extract (index_key, stride) from a Mul/Shl term, if proven."""
        for maybe_index, maybe_stride in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
            stride_value = self.c_constant_value(self.unwrap_c_casts(maybe_stride))
            if inner.op == "Shl":
                if not isinstance(stride_value, int):
                    continue
                stride = 1 << stride_value
            else:
                if stride_value is None:
                    continue
                stride = stride_value
            index = self.unwrap_c_casts(maybe_index)
            index_key = self.expr_index_key(index)
            if index_key is not None:
                return index_key, stride
        return None

    def summarize_address(self, addr_expr: object) -> AddressSummary:
        """Decompose one address into base terms, offset, and stride terms."""
        from_terms: list[object] = []
        offset = 0
        stride_terms: list[tuple[BaseKey, int]] = []

        for term in self.flatten_c_add_terms(addr_expr):
            inner = self.unwrap_c_casts(term)
            const_value = self.c_constant_value(inner)
            if const_value is not None:
                offset += const_value
                continue
            if isinstance(inner, structured_c.CBinaryOp) and inner.op in {"Mul", "Shl"}:
                stride_term = self._product_stride_term(inner)
                if stride_term is not None:
                    stride_terms.append(stride_term)
                else:
                    from_terms.append(inner)
                continue

            index_key = self.expr_index_key(inner)
            if index_key is not None:
                stride_terms.append((index_key, 1))
                continue

            if isinstance(inner, structured_c.CVariable):
                from_terms.append(inner)
                continue

            from_terms.append(inner)

        return from_terms, offset, stride_terms

    def flatten_c_add_terms(self, expr: object) -> list[object]:
        """Flatten a chain of Add nodes into its term list."""
        if expr is None:
            return []
        expr = self.unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Add":
            return [
                *self.flatten_c_add_terms(expr.lhs),
                *self.flatten_c_add_terms(expr.rhs),
            ]
        return [expr]

    def merge_cached_traits(self) -> None:
        """Fold any existing project-cache traits into the fresh buckets."""
        # Dynamic compatibility boundary: older callers may not have initialized the project cache yet.
        if not isinstance(self.cache, dict):
            return
        existing = self.cache.get(self.cfunc.addr)
        if isinstance(existing, dict):
            for bucket, bucket_data in existing.items():
                if bucket not in self.traits or not isinstance(bucket_data, dict):
                    continue
                self.traits[bucket].update(bucket_data)

    def visit_node(self, node: structured_c.CUnaryOp) -> None:
        """Record trait evidence for one dereference node."""
        access_size = _node_access_size(self.project, node)

        direct_index_key = self.expr_index_key(node)
        if direct_index_key is not None and access_size >= 2:
            self.record_stride_evidence(
                kind="induction_like",
                seg_name="expr",
                base_key=None,
                index_key=direct_index_key,
                stride=1,
                offset=0,
                access_size=access_size,
            )
        _record_plain_base_evidence(
            node=node,
            access_size=access_size,
            summarize_address=self.summarize_address,
            stable_base_key=self.stable_base_key,
            record=self.record,
        )
        _record_segmented_evidence(
            project=self.project,
            node=node,
            access_size=access_size,
            classify_segmented_dereference=self.classify_segmented_dereference,
            summarize_address=self.summarize_address,
            access_trait_variable_key=self.access_trait_variable_key,
            record=self.record,
            record_stride_evidence=self.record_stride_evidence,
        )

    def publish(self) -> bool:
        """Write collected traits to the project cache and apply rewrites."""
        _prune_sparse_trait_counts(self.traits)

        cache = self.cache
        if not isinstance(cache, dict):
            cache = {}
            # Dynamic compatibility boundary: project cache is attached to the third-party angr Project.
            self.project._inertia_access_traits = cache
        if any(isinstance(bucket, dict) and bucket for bucket in self.traits.values()):
            cache[self.cfunc.addr] = self.traits
        else:
            cache.pop(self.cfunc.addr, None)
        return rewrite_for_loop_conditions_from_access_traits(
            cast(InductionProjectLike, self.project),
            self.codegen,
            build_access_trait_evidence_profiles=cast(
                BuildAccessTraitEvidenceProfiles, build_access_trait_evidence_profiles
            ),
            infer_induction_variable=cast(InferInductionVariable, infer_induction_variable),
            iter_c_nodes_deep=self.iter_c_nodes_deep,
        )


def _collect_access_traits(
    project: _ProjectLike,
    codegen: InductionCodegenLike,
    *,
    iter_c_nodes_deep: NodeIterator,
    unwrap_c_casts: CastUnwrapper,
    c_constant_value: ConstantResolver,
    classify_segmented_dereference: Callable[[object, _ProjectLike], _SegmentedDereferenceLike | None],
    stack_slot_identity_for_variable: StackIdentityResolver,
    access_trait_variable_key: BaseKeyResolver,
    AccessTraitStrideEvidence: type[AccessTraitStrideEvidence],
) -> bool:
    """Collect access-trait evidence for one function's structured C body."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return False

    # Dynamic compatibility boundary: older callers may not have initialized the project cache yet.
    cache = getattr(project, "_inertia_access_traits", None)
    collector = _AccessTraitCollector(
        project=project,
        codegen=codegen,
        cfunc=cfunc,
        cache=cache,
        iter_c_nodes_deep=iter_c_nodes_deep,
        unwrap_c_casts=unwrap_c_casts,
        c_constant_value=c_constant_value,
        classify_segmented_dereference=classify_segmented_dereference,
        stack_slot_identity_for_variable=stack_slot_identity_for_variable,
        access_trait_variable_key=access_trait_variable_key,
        stride_evidence_type=AccessTraitStrideEvidence,
    )
    collector.merge_cached_traits()
    for node in iter_c_nodes_deep(cfunc.statements):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue
        collector.visit_node(node)
    return collector.publish()
