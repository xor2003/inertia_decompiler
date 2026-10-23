"""Red/green tests for the array-expression-matching applicability probe.

The probe may report ``False`` only when ``apply_x86_16_array_expression_matching``
is a proven no-op: a missing ``cfunc``, or a completed read-only traversal of
``cfunc.statements`` (the same ``_replace_c_children_8616`` walk the rewrite
performs) that visits no ``CForLoop``/``CWhileLoop``. Unknown input stays
applicable. These tests cross-check the probe against the real pass on
identical fixtures and verify metadata, AST, and error-path parity.
"""



from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CSwitchCase,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering import type_array_matching
from inertia.lowering.access_profiles import InductionSummary
from inertia.lowering.array_matching_applicability_8616 import array_expression_matching_applicable_8616
from inertia.lowering.c_ast_utils import _structured_codegen_node_8616, _structured_slot_names_8616
from inertia.lowering.type_array_matching import apply_x86_16_array_expression_matching

FUNCTION_ADDR = 0x4010


class _DummyCodegen:
    def __init__(self, *, project: object | None = "default") -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16()) if project == "default" else project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _ast_fingerprint(node: object, _active: frozenset[int] = frozenset()) -> object:
    """Serialize a structured C AST subtree by shape, attrs and identity."""
    if not _structured_codegen_node_8616(node):
        if isinstance(node, dict):
            return (
                "dict",
                *(
                    (repr(key), _ast_fingerprint(value, _active))
                    for key, value in sorted(node.items(), key=lambda item: repr(item[0]))
                ),
            )
        if isinstance(node, (list, tuple)):
            return (type(node).__name__, *(_ast_fingerprint(item, _active) for item in node))
        return ("leaf", type(node).__name__, repr(node))
    marker = id(node)
    if marker in _active:
        return ("cycle", type(node).__name__)
    active = _active | {marker}
    children: list[object] = []
    for attr in _structured_slot_names_8616(node):
        try:
            value = getattr(node, attr)
        except AttributeError:
            value = "<unreadable>"
        children.append((attr, _ast_fingerprint(value, active)))
    return (type(node).__name__, marker, tuple(children))


def _ast_shape(node: object, _active: frozenset[int] = frozenset()) -> object:
    """Serialize a structured C AST subtree by shape and attrs, without identity."""
    fingerprint = _ast_fingerprint(node, _active)

    def _strip(value: object) -> object:
        if isinstance(value, tuple) and len(value) == 3 and value[0] not in {
            "dict",
            "list",
            "tuple",
            "leaf",
            "cycle",
        } and isinstance(value[1], int):
            return (value[0], "<id>", _strip(value[2]))
        if isinstance(value, tuple):
            return tuple(_strip(item) for item in value)
        return value

    return _strip(fingerprint)


def _array_matching_metadata(codegen: object) -> dict[str, object]:
    """Snapshot the diagnostics the array-matching pass publishes."""
    return {
        name: value
        for name, value in vars(codegen).items()
        if isinstance(name, str) and name.startswith("_inertia_array_matching")
    }


def _constant(value: int, codegen: _DummyCodegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg_var(reg_offset: int, name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimRegisterVariable(reg_offset, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _stack_var(offset: int, size: int, name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=FUNCTION_ADDR),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _prime(codegen: _DummyCodegen) -> _DummyCodegen:
    """Mark the one-shot validation priming window as discharged."""
    codegen._inertia_structuring_validation_semantics_primed = True
    return codegen


def _flat_fixture() -> tuple[_DummyCodegen, CStatements]:
    """Loop-free flat body: assignments plus a break guard."""
    codegen = _DummyCodegen()
    first = _stack_var(-4, 2, "first", codegen)
    second = _stack_var(-6, 2, "second", codegen)
    assign_a = CAssignment(first, _constant(3, codegen), codegen=codegen)
    assign_b = CAssignment(second, _constant(9, codegen), codegen=codegen)
    guard = CIfBreak(
        CBinaryOp("CmpLE", _reg_var(0, "ax", codegen), _reg_var(6, "v_cx", codegen), codegen=codegen),
        codegen=codegen,
        cstyle_ifs=True,
    )
    root = CStatements([assign_a, assign_b, guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)
    return codegen, root


def _while_loop_fixture(*, with_evidence: bool) -> tuple[_DummyCodegen, CWhileLoop]:
    """Build while(1) { if (si < 100) break; si += 2; }."""
    codegen = _DummyCodegen()
    index = _reg_var(6, "si", codegen)
    guard_cond = CBinaryOp("CmpLT", index, _constant(100, codegen), codegen=codegen)
    guard = CIfElse(
        [(guard_cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    update = CAssignment(
        index,
        CBinaryOp("Add", index, _constant(2, codegen), codegen=codegen),
        codegen=codegen,
    )
    body = CStatements([guard, update], codegen=codegen)
    loop = CWhileLoop(_constant(1, codegen), body, codegen=codegen)
    root = CStatements([loop], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)
    if with_evidence:
        codegen._inertia_induction_summaries = (
            InductionSummary(
                base_key=None,
                index_key=("reg", 6),
                stride=2,
                direction="up",
                bound_candidate=None,
                width=16,
                offset=0,
                count=3,
            ),
        )
    return codegen, loop


# ---------------------------------------------------------------------------
# Positive cases: any reachable loop node keeps the pass applicable.
# ---------------------------------------------------------------------------


def test_applicable_true_for_proven_while_loop_rewrite() -> None:
    codegen, loop = _while_loop_fixture(with_evidence=True)
    _prime(codegen)

    assert array_expression_matching_applicable_8616(codegen) is True
    # The real pass agrees a rewrite is available and mutates the loop.
    assert apply_x86_16_array_expression_matching(codegen) is True
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpGE"


def test_applicable_true_for_while_loop_without_evidence() -> None:
    codegen, _loop = _while_loop_fixture(with_evidence=False)
    _prime(codegen)
    before_ast = _ast_fingerprint(codegen.cfunc.statements)

    # Conservative: the loop node exists, so the pass stays applicable even
    # though this fixture carries no induction evidence.
    assert array_expression_matching_applicable_8616(codegen) is True
    assert _ast_fingerprint(codegen.cfunc.statements) == before_ast
    assert apply_x86_16_array_expression_matching(codegen) is False


def test_applicable_true_for_for_loop() -> None:
    codegen = _prime(_DummyCodegen())
    body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    loop = CForLoop(None, _constant(1, codegen), None, body, codegen=codegen)
    root = CStatements([loop], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert array_expression_matching_applicable_8616(codegen) is True


def test_applicable_true_for_loop_nested_inside_ifelse_condition_pairs() -> None:
    """A loop reachable only through condition_and_nodes list/tuple children."""
    codegen = _prime(_DummyCodegen())
    inner_loop = CWhileLoop(
        _constant(1, codegen),
        CStatements([CBreak(codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    branch = CIfElse(
        [(_constant(1, codegen), CStatements([inner_loop], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert array_expression_matching_applicable_8616(codegen) is True


def test_applicable_true_for_loop_nested_inside_switch_case_tuples() -> None:
    """A loop reachable only through switch-case (value, body) tuples."""
    codegen = _prime(_DummyCodegen())
    inner_loop = CWhileLoop(
        _constant(1, codegen),
        CStatements([CBreak(codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    case_body = CStatements([inner_loop], addr=0x4020, codegen=codegen)
    switch = CSwitchCase(_reg_var(0, "ax", codegen), [(69, case_body)], None, codegen=codegen)
    root = CStatements([switch], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert array_expression_matching_applicable_8616(codegen) is True


def test_applicable_true_when_root_itself_is_a_loop() -> None:
    """The rewrite applies transform to the root node; the probe must too."""
    codegen = _prime(_DummyCodegen())
    loop = CWhileLoop(
        _constant(1, codegen),
        CStatements([CBreak(codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=loop, body=loop)

    assert array_expression_matching_applicable_8616(codegen) is True


# ---------------------------------------------------------------------------
# Proven no-op cases: applicable is False, the AST is untouched, and the
# published diagnostics match an executed no-op pass exactly.
# ---------------------------------------------------------------------------


def test_applicable_false_for_loop_free_ast_with_metadata_parity() -> None:
    probe_codegen, probe_root = _flat_fixture()
    _prime(probe_codegen)
    before_ast = _ast_fingerprint(probe_root)

    assert array_expression_matching_applicable_8616(probe_codegen) is False
    assert _ast_fingerprint(probe_root) == before_ast

    pass_codegen, pass_root = _flat_fixture()
    assert apply_x86_16_array_expression_matching(pass_codegen) is False
    assert _ast_shape(probe_root) == _ast_shape(pass_root)

    probe_meta = _array_matching_metadata(probe_codegen)
    pass_meta = _array_matching_metadata(pass_codegen)
    assert probe_meta == pass_meta
    assert probe_meta["_inertia_array_matching_applied"] is True
    assert probe_meta["_inertia_array_matching_stats"] == {
        "induction_vars": 0,
        "array_patterns": 0,
        "recovered_arrays": 0,
        "refused_arrays": 0,
        "string_arrays": 0,
    }
    assert "_inertia_array_matching_error" not in probe_meta


def test_applicable_false_metadata_parity_with_string_candidates() -> None:
    """Non-empty evidence: probe-published diagnostics equal the real pass."""
    from inertia.ir import IRAddress, IRStringEffectArtifact, IRStringEffectRecord
    from inertia.ir.core import AddressStatus, MemSpace, SegmentOrigin

    def _fixture() -> _DummyCodegen:
        codegen, _root = _flat_fixture()
        _prime(codegen)
        codegen._inertia_string_effect_artifact = IRStringEffectArtifact(
            records=(
                IRStringEffectRecord(
                    index=0,
                    family="movs",
                    repeat_kind="rep",
                    width=2,
                    direction_mode="forward",
                    source=IRAddress(
                        space=MemSpace.DS,
                        base=("si",),
                        size=2,
                        status=AddressStatus.STABLE,
                        segment_origin=SegmentOrigin.PROVEN,
                    ),
                    destination=IRAddress(
                        space=MemSpace.ES,
                        base=("di",),
                        size=2,
                        status=AddressStatus.STABLE,
                        segment_origin=SegmentOrigin.PROVEN,
                    ),
                    zf_sensitive=False,
                    zero_seeded_accumulator=None,
                ),
            )
        )
        return codegen

    probe_codegen = _fixture()
    pass_codegen = _fixture()

    assert array_expression_matching_applicable_8616(probe_codegen) is False
    assert apply_x86_16_array_expression_matching(pass_codegen) is False
    assert _array_matching_metadata(probe_codegen) == _array_matching_metadata(pass_codegen)
    assert probe_codegen._inertia_array_matching_stats["string_arrays"] == 2


def test_applicable_false_metadata_parity_with_bridge_facts() -> None:
    """Bridge-backed diagnostics: probe publishes identical lowered/refused sets."""
    from inertia.lowering.access_profiles import AccessTraitEvidenceProfile
    from inertia.lowering.object_lowering import AccessTraitObjectHint

    stable_key = ("ss", ("stack", "bp", -4))
    refused_key = ("ds", ("mem", 0x40))

    def _fixture() -> _DummyCodegen:
        codegen, _root = _flat_fixture()
        _prime(codegen)
        codegen.project = SimpleNamespace(
            arch=codegen.project.arch,
            _inertia_access_traits={FUNCTION_ADDR: {"member_evidence": {}}},
        )
        codegen.cfunc.addr = FUNCTION_ADDR
        codegen._inertia_segmented_memory_lowering = {
            "SS": {
                "classification": "const",
                "associated_space": "stack",
                "allow_linear_lowering": True,
                "allow_object_lowering": True,
                "reason": "constant stack segment",
            },
            "DS": {
                "classification": "over_associated",
                "associated_space": "data",
                "allow_linear_lowering": False,
                "allow_object_lowering": False,
                "reason": "segment space is over-associated",
            },
        }
        return codegen

    bridge_loader = type_array_matching.load_storage_object_bridge

    def _patched(_project: object, _addr: object, *, codegen: object = None) -> object:
        return bridge_loader(
            _project,
            _addr,
            codegen=codegen,
            build_access_trait_evidence_profiles=lambda _traits: {
                stable_key: AccessTraitEvidenceProfile(array_like=((0, 2, 3),)),
                refused_key: AccessTraitEvidenceProfile(array_like=((0, 2, 2),)),
            },
            build_stable_access_object_hints=lambda _traits: {
                stable_key: AccessTraitObjectHint(stable_key, "array", ((0, 2, 3),)),
                refused_key: AccessTraitObjectHint(refused_key, "array", ((0, 2, 2),)),
            },
        )

    type_array_matching.load_storage_object_bridge = _patched
    try:
        probe_codegen = _fixture()
        pass_codegen = _fixture()
        assert array_expression_matching_applicable_8616(probe_codegen) is False
        assert apply_x86_16_array_expression_matching(pass_codegen) is False
    finally:
        type_array_matching.load_storage_object_bridge = bridge_loader

    probe_meta = _array_matching_metadata(probe_codegen)
    pass_meta = _array_matching_metadata(pass_codegen)
    assert probe_meta["_inertia_array_matching_stats"] == pass_meta["_inertia_array_matching_stats"]
    assert probe_meta["_inertia_array_matching_stats"] == {
        "induction_vars": 0,
        "array_patterns": 2,
        "recovered_arrays": 1,
        "refused_arrays": 1,
        "string_arrays": 0,
    }
    # Bridges are distinct artifact instances; compare their public surface.
    probe_bridge = probe_meta["_inertia_array_matching_bridge"]
    pass_bridge = pass_meta["_inertia_array_matching_bridge"]
    assert probe_bridge.stats() == pass_bridge.stats()
    assert (
        probe_meta["_inertia_array_matching_lowerable_arrays"]
        == pass_meta["_inertia_array_matching_lowerable_arrays"]
    )
    assert (
        probe_meta["_inertia_array_matching_refused_arrays"]
        == pass_meta["_inertia_array_matching_refused_arrays"]
    )


def test_applicable_false_for_missing_cfunc() -> None:
    codegen = _DummyCodegen()
    # The real pass early-returns before any publication; skipping is exact parity.
    assert array_expression_matching_applicable_8616(codegen) is False
    assert apply_x86_16_array_expression_matching(codegen) is False
    assert _array_matching_metadata(codegen) == {}


# ---------------------------------------------------------------------------
# Unknown input stays applicable.
# ---------------------------------------------------------------------------


def test_applicable_false_when_tail_validation_disabled() -> None:
    """Disabled tail validation skips the whole prep window; the scan is exact."""
    codegen, root = _flat_fixture()
    codegen.project._inertia_tail_validation_enabled = False

    assert array_expression_matching_applicable_8616(codegen) is False
    assert codegen._inertia_array_matching_applied is True
    # The real pass on the same AST is a no-op.
    twin, twin_root = _flat_fixture()
    twin.project._inertia_tail_validation_enabled = False
    assert apply_x86_16_array_expression_matching(twin) is False
    assert _ast_shape(root) == _ast_shape(twin_root)


def test_applicable_true_for_missing_statements_attribute() -> None:
    codegen = _prime(_DummyCodegen())
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR)  # no .statements

    assert array_expression_matching_applicable_8616(codegen) is True
    # The real pass records the same failure through its own error path.
    assert apply_x86_16_array_expression_matching(codegen) is False
    assert codegen._inertia_array_matching_error


def test_applicable_true_for_container_cycle() -> None:
    """A cyclic child container refuses the coverage proof, not the pass."""
    codegen, root = _flat_fixture()
    _prime(codegen)
    cyclic: list[object] = []
    cyclic.append(cyclic)
    root.statements = [CStatements(cyclic, codegen=codegen)]

    assert array_expression_matching_applicable_8616(codegen) is True
    assert apply_x86_16_array_expression_matching(codegen) is False
    assert codegen._inertia_array_matching_error


def test_applicable_true_when_metadata_publication_fails() -> None:
    """A metadata failure keeps the pass applicable to own its error path."""
    codegen, _root = _flat_fixture()
    _prime(codegen)

    def _raising_loader(_project: object, _addr: object, *, codegen: object = None) -> object:
        raise RuntimeError("bridge construction failed")

    bridge_loader = type_array_matching.load_storage_object_bridge
    type_array_matching.load_storage_object_bridge = _raising_loader
    try:
        assert array_expression_matching_applicable_8616(codegen) is True
    finally:
        type_array_matching.load_storage_object_bridge = bridge_loader
    # The probe already recorded the publication failure; the stage then runs
    # the real pass, which re-enters the same error path under validation.
    assert codegen._inertia_array_matching_error == "bridge construction failed"

    twin, _twin_root = _flat_fixture()
    _prime(twin)
    type_array_matching.load_storage_object_bridge = _raising_loader
    try:
        assert apply_x86_16_array_expression_matching(twin) is False
    finally:
        type_array_matching.load_storage_object_bridge = bridge_loader
    assert twin._inertia_array_matching_error == "bridge construction failed"


# ---------------------------------------------------------------------------
# Probe read-only and determinism guarantees.
# ---------------------------------------------------------------------------


def test_probe_is_deterministic_and_read_only_on_applicable_ast() -> None:
    codegen, _loop = _while_loop_fixture(with_evidence=True)
    _prime(codegen)
    before_ast = _ast_fingerprint(codegen.cfunc.statements)
    before_meta = _array_matching_metadata(codegen)

    assert array_expression_matching_applicable_8616(codegen) is True
    assert array_expression_matching_applicable_8616(codegen) is True
    assert _ast_fingerprint(codegen.cfunc.statements) == before_ast
    assert _array_matching_metadata(codegen) == before_meta


def test_probe_does_not_rewrite_when_applicable() -> None:
    """Probe True must leave a rewriteable loop completely untouched."""
    codegen, loop = _while_loop_fixture(with_evidence=True)
    _prime(codegen)

    assert array_expression_matching_applicable_8616(codegen) is True
    assert isinstance(loop.condition, CConstant)
    assert len(loop.body.statements) == 2


@pytest.mark.parametrize("mutation", ["insert_loop", "replace_root", "replace_cfunc"])
def test_metadata_mutation_keeps_pass_applicable(monkeypatch, mutation: str) -> None:
    """Metadata callbacks cannot invalidate a previously scanned no-op AST."""
    codegen, root = _flat_fixture()

    def mutate(_project, _addr, *, codegen):
        if mutation == "insert_loop":
            root.statements.append(CWhileLoop(
                _constant(1, codegen), CStatements([], codegen=codegen), codegen=codegen,
            ))
        elif mutation == "replace_root":
            codegen.cfunc.statements = CStatements([], codegen=codegen)
        else:
            codegen.cfunc = SimpleNamespace(
                addr=FUNCTION_ADDR, statements=root, body=root,
            )
        return None

    monkeypatch.setattr(type_array_matching, "load_storage_object_bridge", mutate)
    assert array_expression_matching_applicable_8616(codegen) is True


def test_wired_array_callback_waits_for_priming() -> None:
    """The actual scheduler keeps unprimed inputs on the validated pass path."""
    from inertia.structuring.decompiler_structuring_stage import _build_decompiler_structuring_passes

    spec = next(item for item in _build_decompiler_structuring_passes()
                if item.name == "_array_expression_matching_8616")
    assert spec.func is apply_x86_16_array_expression_matching
    assert spec.applicable is not None
    codegen, _root = _flat_fixture()
    assert spec.applicable(codegen) is True
    assert _array_matching_metadata(codegen) == {}
    _prime(codegen)
    assert spec.applicable(codegen) is False
