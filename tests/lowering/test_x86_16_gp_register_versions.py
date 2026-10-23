"""Architectural register publication must not merge distinct captured values."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.function_ssa_registry import FunctionSSAArtifactStage8616
from inertia.lowering import c_ast_utils, gp_register_versions
from inertia.lowering.gp_register_state import (
    _c_register_identity_8616,
    lower_architectural_gp_register_state_8616,
)
from inertia.pipeline.errors import PipelineHardError
from tests.lowering.test_x86_16_gp_register_state import _gp_live_in_artifact


def _fixture(register):
    arch = Arch86_16()
    address = 0x10E85
    project = SimpleNamespace(
        arch=arch, _inertia_function_ssa_artifacts_8616={address: _gp_live_in_artifact(register)},
        _inertia_function_ssa_stages_8616={address: FunctionSSAArtifactStage8616.IR},
    )
    codegen = SimpleNamespace(project=project, cstyle_null_cmp=False, next_idx=lambda _: 1,
                              next_node_idx=lambda: 1, next_ident=lambda name: name)
    offset, width = arch.registers[register]
    type_ = (SimTypeLong(False) if width == arch.bytes else SimTypeShort(False)).with_arch(arch)
    before = CVariable(SimRegisterVariable(offset, width, ident="before", region=address), variable_type=type_, codegen=codegen)
    after = CVariable(SimRegisterVariable(offset, width, ident="after", region=address), variable_type=type_, codegen=codegen)
    first = CAssignment(before, CConstant(0x1234, type_, codegen=codegen), codegen=codegen)
    second = CAssignment(after, CConstant(0x5678, type_, codegen=codegen), codegen=codegen)
    returned = CReturn(before, codegen=codegen)
    types = {}
    codegen.cfunc = SimpleNamespace(
        addr=address, statements=CStatements([first, second, returned], codegen=codegen),
        variables_in_use={before.variable: before, after.variable: after}, unified_local_vars={},
        variable_manager=SimpleNamespace(set_variable_type=lambda variable, type_: types.__setitem__(variable, type_)),
        refresh=lambda: None,
    )
    return codegen, returned, types


@pytest.mark.parametrize("register", ["si", "di", "ax", "eax"])
def test_defined_register_value_survives_later_version(register):
    codegen, returned, types = _fixture(register)
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval, CVariable)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)
    assert returned.retval.variable in types
    assert returned.retval.variable in codegen.cfunc.variables_in_use
    capture, publication, restore, _ = codegen.cfunc.statements.statements
    assert capture.lhs is returned.retval
    assert isinstance(publication.lhs.variable, SimMemoryVariable)
    assert publication.lhs.variable == restore.lhs.variable
    stats = codegen._inertia_gp_register_version_capture_stats_8616
    assert stats.raw_fact_count == stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0
    first_snapshot = returned.retval.variable
    lower_architectural_gp_register_state_8616(codegen)
    assert returned.retval.variable is first_snapshot


def test_version_capture_refuses_use_before_definition_without_mutation():
    codegen, returned, _ = _fixture("si")
    statements = codegen.cfunc.statements.statements
    statements.insert(0, CReturn(returned.retval, codegen=codegen))
    original = tuple(statements)
    with pytest.raises(PipelineHardError, match=r"function=0x10e85.*does not dominate"):
        lower_architectural_gp_register_state_8616(codegen)
    assert tuple(codegen.cfunc.statements.statements) == original
    assert isinstance(returned.retval.variable, SimRegisterVariable)
    assert codegen._inertia_gp_register_version_capture_stats_8616.failure_count == 1


def test_version_capture_proves_order_through_nested_statement_groups():
    codegen, returned, _ = _fixture("si")
    statements = codegen.cfunc.statements.statements
    codegen.cfunc.statements.statements = [CStatements(statements[:-1], codegen=codegen), returned]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)


def test_version_capture_keeps_value_across_call_and_preserves_call_order():
    codegen, returned, _ = _fixture("si")
    call = CExpressionStatement(CFunctionCall("opaque", None, args=[], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements.insert(1, call)
    assert lower_architectural_gp_register_state_8616(codegen)
    capture, publication, observed_call, restore, _ = codegen.cfunc.statements.statements
    assert observed_call is call
    assert capture.lhs is returned.retval
    assert publication.lhs.variable == restore.lhs.variable


def test_word_snapshot_survives_high_byte_architectural_write():
    codegen, returned, _ = _fixture("ax")
    register, size = codegen.project.arch.registers["ah"]
    byte_type = SimTypeChar(False).with_arch(codegen.project.arch)
    byte = CVariable(SimRegisterVariable(register, size, ident="high", region=codegen.cfunc.addr),
                     variable_type=byte_type, codegen=codegen)
    codegen.cfunc.statements.statements[1] = CAssignment(
        byte, CConstant(0x56, byte_type, codegen=codegen), codegen=codegen,
    )
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)
    assert returned.retval.variable.size == codegen.project.arch.registers["ax"][1]


@pytest.mark.parametrize("loop", [False, True])
def test_version_capture_proves_branch_or_loop_local_definition(loop):
    codegen, returned, _ = _fixture("si")
    body = codegen.cfunc.statements
    condition = CConstant(1, returned.retval.variable_type, codegen=codegen)
    nested = (CWhileLoop(condition, body, codegen=codegen) if loop
              else CIfElse([(condition, body)], codegen=codegen))
    codegen.cfunc.statements = CStatements([nested], codegen=codegen)
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)


def test_version_capture_refuses_branch_local_definition_with_escaping_read():
    codegen, returned, _ = _fixture("si")
    statements = codegen.cfunc.statements.statements
    condition = CConstant(1, returned.retval.variable_type, codegen=codegen)
    branch = CIfElse([(condition, CStatements(statements[:-1], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([branch, returned], codegen=codegen)
    with pytest.raises(PipelineHardError, match="GP version capture"):
        lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimRegisterVariable)


def test_pointer_capture_projects_guest_offset_before_scalar_assignment():
    codegen, returned, _ = _fixture("si")
    pointer_type = SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch)
    pointer = CVariable(SimStackVariable(4, 2, base="bp"), variable_type=pointer_type, codegen=codegen)
    codegen.cfunc.statements.statements[0].rhs = pointer
    assert lower_architectural_gp_register_state_8616(codegen)
    capture = codegen.cfunc.statements.statements[0]
    assert capture.lhs is returned.retval
    assert isinstance(capture.rhs, CFunctionCall)
    assert capture.rhs.callee_target == "PTR_U16"
    assert capture.rhs.args == [pointer]


def test_version_consumed_before_overwrite_does_not_need_snapshot():
    codegen, returned, _ = _fixture("si")
    first, restore, _ = codegen.cfunc.statements.statements
    local = CVariable(SimStackVariable(-2, 2, base="bp"),
                      variable_type=returned.retval.variable_type, codegen=codegen)
    use = CAssignment(local, returned.retval, codegen=codegen)
    codegen.cfunc.statements.statements = [first, use, restore]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert codegen._inertia_gp_register_version_capture_stats_8616.materialized_count == 0


def _many_version_capture_fixture(lanes=("si", "di", "ax"), repeat_reads=1):
    """Build one many-version tree: two candidate identities per lane.

    Every lane defines ``v1`` and ``v2`` once, an effectful call follows all
    definitions, and linear tail reads use every version, so each of the
    ``2 * len(lanes)`` identities produces one capture plan.
    """
    arch = Arch86_16()
    address = 0x10E85
    project = SimpleNamespace(arch=arch)
    codegen = SimpleNamespace(
        project=project, cstyle_null_cmp=False, next_idx=lambda _: 1,
        next_node_idx=lambda: 1, next_ident=lambda name: name,
    )
    types = {}
    codegen.cfunc = SimpleNamespace(
        addr=address, statements=None, variables_in_use={}, unified_local_vars={},
        variable_manager=SimpleNamespace(
            set_variable_type=lambda variable, type_: types.__setitem__(variable, type_)),
        refresh=lambda: None,
    )
    short = SimTypeShort(False).with_arch(arch)
    versions = {}
    definitions = []
    for lane in lanes:
        offset, width = arch.registers[lane]
        lane_type = (SimTypeLong(False) if width == arch.bytes else short).with_arch(arch)
        for version in ("v1", "v2"):
            carrier = CVariable(
                SimRegisterVariable(offset, width, ident=f"{lane}_{version}", region=address),
                variable_type=lane_type, codegen=codegen,
            )
            versions[(lane, version)] = carrier
            definitions.append(CAssignment(
                carrier, CConstant(len(definitions), lane_type, codegen=codegen), codegen=codegen,
            ))
    call = CExpressionStatement(
        CFunctionCall("opaque", None, args=[], codegen=codegen), codegen=codegen,
    )
    reads = [
        CAssignment(
            CVariable(SimStackVariable(-2 * index - 2, 2, base="bp"),
                      variable_type=short, codegen=codegen),
            carrier, codegen=codegen,
        )
        for _repeat in range(repeat_reads)
        for index, carrier in enumerate(versions.values())
    ]
    codegen.cfunc.statements = CStatements(
        [CStatements([*definitions, call], codegen=codegen), CStatements(reads, codegen=codegen)],
        codegen=codegen,
    )
    state_names = frozenset(
        _c_register_identity_8616(carrier, project)[1] for carrier in versions.values()
    )
    return codegen, state_names


@pytest.mark.parametrize("repeat_reads", [1, 12])
def test_capture_planning_shares_one_root_occurrence_census(monkeypatch, repeat_reads):
    """Per-candidate planning must not re-scan the whole tree per identity."""
    codegen, state_names = _many_version_capture_fixture(repeat_reads=repeat_reads)
    root = codegen.cfunc.statements
    real_occurrences = c_ast_utils._iter_c_node_occurrences_8616
    real_deep = c_ast_utils._iter_c_nodes_deep_8616
    control_edges = sum(1 for _ in real_occurrences(root))
    walks = {"occurrence_root": 0, "occurrence_yields": 0, "deep_root": 0}

    def counting_occurrences(node, *args, **kwargs):
        if node is root:
            walks["occurrence_root"] += 1
        for item in real_occurrences(node, *args, **kwargs):
            walks["occurrence_yields"] += 1
            yield item

    def counting_deep(node, *args, **kwargs):
        if node is root:
            walks["deep_root"] += 1
        yield from real_deep(node, *args, **kwargs)

    monkeypatch.setattr(gp_register_versions, "_iter_c_node_occurrences_8616", counting_occurrences)
    monkeypatch.setattr(gp_register_versions, "_iter_c_nodes_deep_8616", counting_deep)
    assert gp_register_versions.capture_gp_register_versions_8616(
        codegen, state_names, lambda node: _c_register_identity_8616(node, codegen.project),
    )
    stats = codegen._inertia_gp_register_version_capture_stats_8616
    assert stats == gp_register_versions.GPVersionCaptureStats8616(6, 6, 6, 6, 0)
    # One lazy whole-root occurrence census serves every candidate identity;
    # the rejected shape re-walked the occurrence tree once per candidate.
    assert walks["occurrence_root"] == 1
    # Definition/scope inventory, captured-tag census, and tmp-id census.
    assert walks["deep_root"] == 3
    # Per-statement occurrence summaries stay bounded by a small multiple of
    # the tree's edge count instead of scaling with candidate count.
    assert walks["occurrence_yields"] <= 3 * control_edges


@pytest.mark.parametrize("repeat_reads", [1, 12])
def test_capture_replacement_batches_full_root_walks(monkeypatch, repeat_reads):
    """Independent captures must not each revisit the complete function tree."""
    codegen, state_names = _many_version_capture_fixture(repeat_reads=repeat_reads)
    root = codegen.cfunc.statements
    original = gp_register_versions._replace_c_children_8616
    roots = []

    def counted(node, *args, **kwargs):
        if node is root:
            roots.append(node)
        return original(node, *args, **kwargs)

    monkeypatch.setattr(gp_register_versions, "_replace_c_children_8616", counted)
    assert gp_register_versions.capture_gp_register_versions_8616(
        codegen, state_names, lambda node: _c_register_identity_8616(node, codegen.project),
    )
    assert len(roots) == 1
    assert codegen._inertia_gp_register_version_capture_stats_8616.materialized_count == 6


def test_batched_capture_projects_rhs_after_prior_capture():
    """Dependent RHSs consume prior scalar snapshots before pointer projection."""
    codegen, state_names = _many_version_capture_fixture()
    group = codegen.cfunc.statements.statements[0]
    definitions = tuple(group.statements[:-1])
    original_sources = tuple(statement.lhs for statement in definitions)
    effect = group.statements[-1]
    pointer_type = SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch)
    pointer = CVariable(
        SimStackVariable(4, 2, base="bp"), variable_type=pointer_type, codegen=codegen,
    )
    definitions[0].rhs = pointer
    definitions[1].rhs = definitions[0].lhs
    def classify(node):
        return _c_register_identity_8616(node, codegen.project)

    assert gp_register_versions.capture_gp_register_versions_8616(codegen, state_names, classify)
    assert definitions[0].rhs.callee_target == "PTR_U16"
    assert definitions[0].rhs.args == [pointer]
    assert definitions[1].rhs is definitions[0].lhs
    for index, (definition, source) in enumerate(zip(definitions, original_sources, strict=True)):
        publication = group.statements[2 * index + 1]
        assert group.statements[2 * index] is definition
        assert isinstance(definition.lhs.variable, SimTemporaryVariable)
        assert publication.lhs is source
        assert publication.rhs is definition.lhs
    assert group.statements[-1] is effect
    assert not gp_register_versions.capture_gp_register_versions_8616(codegen, state_names, classify)


def test_nested_statement_census_retains_linear_identity_storage():
    """Overlapping nested subtrees must not retain quadratic histograms."""
    codegen, _, _ = _fixture("ax")
    arch = codegen.project.arch
    offset, width = arch.registers["ax"]
    word = SimTypeShort(False).with_arch(arch)
    scopes = []
    child = CStatements([], codegen=codegen)
    for index in range(40):
        carrier = CVariable(
            SimRegisterVariable(offset, width, ident=f"nested_{index}", region=codegen.cfunc.addr),
            variable_type=word, codegen=codegen,
        )
        child = CStatements([CReturn(carrier, codegen=codegen), child], codegen=codegen)
        scopes.append(child)
    def classify(node):
        return _c_register_identity_8616(node, codegen.project)

    identity = classify(carrier)[0]
    scan = gp_register_versions._CaptureScan8616(child, classify, tuple(reversed(scopes)))
    assert scan.total(identity) == 1
    for scope in reversed(scopes):
        expected = sum(classify(node) is not None and classify(node)[0] == identity
                       for node in c_ast_utils._iter_c_node_occurrences_8616(scope))
        assert scan.statement_reads(scope, identity) == expected
        retained = sum(len(histogram) for _, histogram in scan._statement_occurrences.values())
        assert retained <= 2 * len(scopes)


def test_version_capture_counts_shared_statement_occurrences_per_edge():
    """A statement shared by two groups keeps both of its read edges."""
    codegen, returned, _ = _fixture("si")
    first, second, _ = codegen.cfunc.statements.statements
    shared_use = CAssignment(
        CVariable(SimStackVariable(-4, 2, base="bp"),
                  variable_type=returned.retval.variable_type, codegen=codegen),
        returned.retval, codegen=codegen,
    )
    codegen.cfunc.statements.statements = [
        first, second,
        CStatements([shared_use], codegen=codegen),
        CStatements([shared_use], codegen=codegen),
        returned,
    ]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)
    stats = codegen._inertia_gp_register_version_capture_stats_8616
    assert stats.materialized_count == 1


def test_version_capture_refuses_ambiguous_definition_owner_without_mutation():
    """One definition listed by two groups has no unique owner group."""
    codegen, returned, _ = _fixture("si")
    first, second, _ = codegen.cfunc.statements.statements
    codegen.cfunc.statements = CStatements(
        [CStatements([first], codegen=codegen),
         CStatements([first, second, returned], codegen=codegen)],
        codegen=codegen,
    )
    with pytest.raises(PipelineHardError, match="ambiguous definition owner"):
        lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval.variable, SimRegisterVariable)
    assert codegen._inertia_gp_register_version_capture_stats_8616.failure_count == 1


def test_loop_local_version_consumed_before_restore_needs_no_snapshot():
    codegen, returned, _ = _fixture("si")
    first, restore, _ = codegen.cfunc.statements.statements
    local = CVariable(SimStackVariable(-2, 2, base="bp"),
                      variable_type=returned.retval.variable_type, codegen=codegen)
    use = CAssignment(local, returned.retval, codegen=codegen)
    loop = CWhileLoop(CConstant(1, local.type, codegen=codegen),
                      CStatements([first, use], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements = [loop, restore]
    assert lower_architectural_gp_register_state_8616(codegen)
    assert codegen._inertia_gp_register_version_capture_stats_8616.materialized_count == 0


def _dirty_sp_capture_fixture():
    from tests.lowering.test_x86_16_gp_register_state import _entry_dirty, _scoped_codegen, _scoped_entry_project
    codegen = _scoped_codegen(_scoped_entry_project(), None)
    definition = CAssignment(
        _entry_dirty(codegen, 9, "sp"),
        CBinaryOp("Sub", _entry_dirty(codegen, 2, "sp"),
                  CConstant(2, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    returned = CReturn(_entry_dirty(codegen, 9, "sp"), codegen=codegen)
    codegen.cfunc.statements = CStatements([definition, returned], codegen=codegen)
    return codegen, definition, returned


def test_dirty_sp_definition_materializes_without_another_register_write():
    """One defined SSA register needs an emit-able local at its exact width."""
    codegen, definition, returned = _dirty_sp_capture_fixture()
    assert lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval, CVariable)
    assert isinstance(returned.retval.variable, SimTemporaryVariable)
    assert returned.retval.variable.size == 2
    assert returned.retval.variable_type.size == 16
    assert definition.lhs is returned.retval
    assert not any(isinstance(n, CDirtyExpression)
                   for n in c_ast_utils._iter_c_nodes_deep_8616(codegen.cfunc.statements))
    capture, publication, final = codegen.cfunc.statements.statements
    assert capture is definition and final is returned
    assert publication.rhs.op == "Or"
    assert publication.rhs.lhs.op == "And"
    assert publication.rhs.lhs.rhs.value == 0xffff0000
    assert publication.rhs.rhs.op == "And"
    assert publication.rhs.rhs.rhs.value == 0xffff
    assert publication.rhs.rhs.lhs is returned.retval
    snapshot = returned.retval
    lower_architectural_gp_register_state_8616(codegen)
    assert returned.retval is snapshot


def test_dirty_sp_definition_refuses_read_before_definition_without_mutation():
    """An undefined read cannot be repaired by moving a later definition."""
    codegen, definition, returned = _dirty_sp_capture_fixture()
    codegen.cfunc.statements.statements = [returned, definition]
    with pytest.raises(PipelineHardError, match="does not dominate"):
        lower_architectural_gp_register_state_8616(codegen)
    assert codegen.cfunc.statements.statements == [returned, definition]
    assert isinstance(returned.retval, CDirtyExpression)

@pytest.mark.parametrize("loop", [False, True])
def test_dirty_definition_does_not_dominate_read_outside_branch_or_loop(loop):
    """A possibly unexecuted definition must not initialize an escaping value."""
    codegen, definition, returned = _dirty_sp_capture_fixture()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    body = CStatements([definition], codegen=codegen)
    branch = (CWhileLoop(condition, body, codegen=codegen) if loop
              else CIfElse([(condition, body)], codegen=codegen))
    codegen.cfunc.statements = CStatements([branch, returned], codegen=codegen)
    with pytest.raises(PipelineHardError, match="does not dominate"):
        lower_architectural_gp_register_state_8616(codegen)
    assert body.statements == [definition]
    assert isinstance(returned.retval, CDirtyExpression)


def test_dirty_definition_keeps_ambiguous_multiple_writes_unlowered():
    """Multiple writes to one SSA identity cannot justify one value snapshot."""
    codegen, definition, returned = _dirty_sp_capture_fixture()
    duplicate = CAssignment(
        returned.retval, CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements = [definition, duplicate, returned]
    lower_architectural_gp_register_state_8616(codegen)
    assert isinstance(returned.retval, CDirtyExpression)
    assert isinstance(definition.lhs, CDirtyExpression)
    assert codegen.cfunc.statements.statements == [definition, duplicate, returned]
