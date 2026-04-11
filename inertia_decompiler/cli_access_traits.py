from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable


def _collect_access_traits(
    project,
    codegen,
    *,
    iter_c_nodes_deep,
    unwrap_c_casts,
    c_constant_value,
    classify_segmented_dereference,
    stack_slot_identity_for_variable,
    access_trait_variable_key,
    AccessTraitStrideEvidence,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    traits: dict[str, dict[tuple[object, ...], object]] = {
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

    cache = getattr(project, "_inertia_access_traits", None)
    if isinstance(cache, dict):
        existing = cache.get(getattr(codegen.cfunc, "addr", None))
        if isinstance(existing, dict):
            for bucket, bucket_data in existing.items():
                if bucket not in traits or not isinstance(bucket_data, dict):
                    continue
                traits[bucket].update(bucket_data)

    def record(bucket: str, key: tuple[object, ...]) -> None:
        store = traits[bucket]
        store[key] = store.get(key, 0) + 1

    def record_stride_evidence(
        *,
        kind: str,
        seg_name: str,
        base_key: tuple[object, ...] | None,
        index_key: tuple[object, ...] | None,
        stride: int,
        offset: int,
        access_size: int,
    ) -> None:
        if index_key is None:
            return
        evidence_key = (kind, seg_name, base_key, index_key, stride, offset, access_size)
        bucket_name = "induction_evidence" if kind == "induction_like" else "stride_evidence"
        existing = traits[bucket_name].get(evidence_key)
        existing_count = getattr(existing, "count", existing if isinstance(existing, int) else None)
        count = 1 if existing_count is None else int(existing_count) + 1
        traits[bucket_name][evidence_key] = AccessTraitStrideEvidence(
            segment=seg_name,
            base_key=base_key,
            index_key=index_key,
            stride=stride,
            offset=offset,
            width=access_size,
            count=count,
            kind=kind,
        )

    def stable_base_key(variable) -> tuple[object, ...] | None:
        if isinstance(variable, SimRegisterVariable):
            return ("reg", getattr(variable, "reg", None))
        if isinstance(variable, SimStackVariable):
            identity = stack_slot_identity_for_variable(variable)
            if identity is None:
                return None
            return ("stack", identity.base, getattr(variable, "offset", None), getattr(variable, "region", None))
        if isinstance(variable, SimMemoryVariable):
            return ("mem", getattr(variable, "addr", None))
        return None

    def summarize_address(addr_expr):
        from_terms: list[object] = []
        offset = 0
        stride_terms: list[tuple[object, int]] = []

        for term in _flatten_c_add_terms(addr_expr):
            inner = unwrap_c_casts(term)
            const_value = c_constant_value(inner)
            if const_value is not None:
                offset += const_value
                continue

            if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
                for maybe_index, maybe_stride in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                    stride = c_constant_value(unwrap_c_casts(maybe_stride))
                    if stride is None:
                        continue
                    index = unwrap_c_casts(maybe_index)
                    if isinstance(index, structured_c.CVariable):
                        stride_terms.append((index, stride))
                        break
                else:
                    from_terms.append(inner)
                continue

            if isinstance(inner, structured_c.CVariable):
                from_terms.append(inner)
                continue

            from_terms.append(inner)

        return from_terms, offset, stride_terms

    def _flatten_c_add_terms(expr):
        if expr is None:
            return []
        expr = unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Add":
            return [* _flatten_c_add_terms(expr.lhs), * _flatten_c_add_terms(expr.rhs)]
        return [expr]

    for node in iter_c_nodes_deep(codegen.cfunc.statements):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            continue

        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        access_size = max((bits // project.arch.byte_width) if isinstance(bits, int) and bits > 0 else 1, 1)

        plain_base_terms, plain_offset, plain_stride_terms = summarize_address(getattr(node, "operand", None))
        if len(plain_base_terms) == 1 and isinstance(plain_base_terms[0], structured_c.CVariable):
            plain_base_var = getattr(plain_base_terms[0], "variable", None)
            if isinstance(plain_base_var, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                plain_base_key = stable_base_key(plain_base_var)
                if plain_base_key is None:
                    continue
                if plain_offset != 0:
                    record("member_evidence", (plain_base_key, plain_offset, access_size))
                for index_expr, stride in plain_stride_terms:
                    index_var = getattr(index_expr, "variable", None)
                    index_key = access_trait_variable_key(index_var)
                    if index_key is None or stride not in {2, 4, 8}:
                        continue
                    record("array_evidence", (plain_base_key, index_key, stride, plain_offset, access_size))

        classified = classify_segmented_dereference(node, project)
        if classified is None:
            continue

        base_terms, offset, stride_terms = summarize_address(classified.addr_expr)
        base_key = None
        if len(base_terms) == 1 and isinstance(base_terms[0], structured_c.CVariable):
            base_var = getattr(base_terms[0], "variable", None)
            base_key = access_trait_variable_key(base_var)
            if base_key is not None:
                record("base_const", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offsets", (classified.seg_name, base_key, offset))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
                record("repeated_offset_widths", (classified.seg_name, base_key, offset, access_size))
        for index_expr, stride in stride_terms:
            index_var = getattr(index_expr, "variable", None)
            index_key = access_trait_variable_key(index_var)
            if index_key is None or base_key is None:
                continue
            record("base_stride", (classified.seg_name, index_key, stride, offset, access_size))
            record("base_stride_widths", (classified.seg_name, index_key, stride, offset, access_size))
            if index_key[0] == "reg":
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

    for key, count in list(traits["repeated_offsets"].items()):
        if count < 2:
            del traits["repeated_offsets"][key]

    for key, count in list(traits["base_stride"].items()):
        if count < 2:
            del traits["base_stride"][key]

    if not isinstance(cache, dict):
        cache = {}
        setattr(project, "_inertia_access_traits", cache)
    cache[getattr(codegen.cfunc, "addr", 0)] = traits
    return False
