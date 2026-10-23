"""Initial production callbacks consume declared native leaves conditionally."""
import hashlib
import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir.entry_domain_call_preservation import install_real16_invocation_source_8616
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.function_ssa_registry import registered_function_ssa_artifact_8616
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616, real16_native_census_import_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.structuring.decompiler_structuring_stage import _build_decompiler_structuring_passes
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.ir.test_declared_function_entry_domain import _world
from tests.ir.test_declared_function_entry_intake import _install
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


@pytest.fixture
def installed_leaf():
    apply_x86_16_bootstrap()
    _project, original, original_link = _world()
    body = bytes.fromhex('b83412c3')
    source = bytearray(original.source)
    source[0x40:0x44] = body
    boot = program_from_mz_bytes(bytes(source), original.environment,
                                code_ranges=(LinearRange(0x1000, 2), LinearRange(0x1020, 4)))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        'backend': 'blob', 'arch': Arch86_16(), 'base_addr': 0x1000, 'entry_point': 0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1020, 0x1024)
    assert boundary is not None
    artifact = real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    spec = replace(original_link.admission.spec, source_sha256=hashlib.sha256(boot.source).hexdigest(),
                   relocated_sha256=hashlib.sha256(module).hexdigest(),
                   native_sha256=hashlib.sha256(body).hexdigest(), range_end=0x1024)
    admission = admit_declared_function_entry_8616(spec, source=boot.source, loaded_module=module,
                                                environment_sha256=spec.environment_sha256)
    link = DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    installed = _install(project, boot, link)
    project.kb.functions.function(addr=0x1020, create=True)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1020))
    return project, codegen, installed


def _run_initial_callbacks(project, codegen):
    selected = ('_vex_ir_artifact_8616', '_segment_state_artifact_8616')
    callbacks = {spec.name: spec.func for spec in _build_decompiler_structuring_passes()}
    for name in selected:
        callbacks[name](project, codegen)


def _run_full_prefix(project, codegen):
    running = False
    for spec in _build_decompiler_structuring_passes():
        if spec.name == '_vex_ir_artifact_8616':
            running = True
        if running:
            spec.func(project, codegen) if spec.needs_project else spec.func(codegen)
        if spec.name == '_segment_state_artifact_8616':
            break


def test_normal_pipeline_attaches_declared_leaf_without_startup_or_publication(installed_leaf, monkeypatch):
    from inertia.ir import entry_domain_call_preservation as owner
    project, codegen, _ = installed_leaf
    before = registered_function_ir_artifact_8616(project, 0x1020)
    monkeypatch.setattr(owner, '_request_raw_boot_premise_8616', lambda *args, **kwargs: pytest.fail('startup walk'))
    _run_initial_callbacks(project, codegen)
    state = codegen._inertia_segment_state_artifact
    entry = codegen._inertia_declared_entry_pipeline_8616
    assert state.invocation_scope is entry.scope
    assert state.scoped_view is entry.view
    assert state.source_artifact is entry.bundle.artifact is codegen._inertia_vex_ir_artifact
    assert state.scoped_view.complete_for(state.invocation_scope)
    assert not state.scoped_view.complete
    assert state.scoped_view.materialized_count == 0
    assert state.scoped_view.failure_count == 0
    assert registered_function_ir_artifact_8616(project, 0x1020) == before
    _run_initial_callbacks(project, codegen)
    assert codegen._inertia_segment_state_artifact.invocation_scope is entry.scope


@pytest.mark.parametrize('mutation', ['native', 'declaration', 'frame'])
def test_invalid_declared_pipeline_never_attaches_unscoped_state(installed_leaf, mutation):
    project, codegen, source = installed_leaf
    if mutation == 'native':
        project.loader.memory.store(0x1021, b'\x35')
    else:
        admission = source.function_entries[0]
        spec = replace(admission.spec, memory=()) if mutation == 'frame' else replace(admission.spec, native_sha256='0'*64)
        invalid = replace(source, function_entries=(replace(admission, spec=spec),))
        # Deliberately forged frontend receipts must fail at consumption.
        project._inertia_real16_invocation_source_8616 = invalid
    with pytest.raises(PipelineHardError):
        _run_initial_callbacks(project, codegen)
    assert not hasattr(codegen, '_inertia_segment_state_artifact')


def test_removed_consumed_declaration_cannot_fall_back(installed_leaf):
    project, codegen, _ = installed_leaf
    _run_initial_callbacks(project, codegen)
    install_real16_invocation_source_8616(project, None)
    with pytest.raises(PipelineHardError, match='declaration changed'):
        _run_initial_callbacks(project, codegen)


def test_same_object_native_mutation_refuses_on_normal_refresh(installed_leaf):
    project, codegen, _ = installed_leaf
    _run_initial_callbacks(project, codegen)
    previous = codegen._inertia_segment_state_artifact
    project.loader.memory.store(0x1021, b'\x35')
    with pytest.raises(PipelineHardError, match='binding refused'):
        _run_initial_callbacks(project, codegen)
    assert codegen._inertia_segment_state_artifact is previous


def test_non_head_declared_entry_refuses_explicitly(installed_leaf):
    project, codegen, source = installed_leaf
    original = source.function_entries[0]
    spec = replace(original.spec, entry_offset=0x23)
    admission = admit_declared_function_entry_8616(
        spec, source=original.source, loaded_module=original.loaded_module,
        environment_sha256=spec.environment_sha256,
    )
    install_real16_invocation_source_8616(project, replace(source, function_entries=(admission,)))
    project.kb.functions.function(addr=0x1023, create=True)
    codegen.cfunc.addr = 0x1023
    with pytest.raises(PipelineHardError, match='function-head entry'):
        _run_initial_callbacks(project, codegen)
    assert not hasattr(codegen, '_inertia_segment_state_artifact')


def test_absent_declaration_does_not_trigger_pending_startup_inventory():
    from inertia.ir.declared_entry_pipeline import prepare_declared_entry_pipeline_8616
    pending = SimpleNamespace(install=lambda project: pytest.fail('undeclared startup inventory'))
    project = SimpleNamespace(_inertia_mz_static_invocation_request_8616=pending)
    assert prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), 0x1020) is None


def test_complete_production_prefix_preserves_declared_leaf(installed_leaf):
    project, codegen, _ = installed_leaf
    before = registered_function_ir_artifact_8616(project, 0x1020)
    before_ssa = registered_function_ssa_artifact_8616(project, 0x1020)
    _run_full_prefix(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    state = codegen._inertia_segment_state_artifact
    assert state.invocation_scope is entry.scope
    assert state.source_artifact is entry.bundle.artifact
    assert registered_function_ir_artifact_8616(project, 0x1020) == before
    assert registered_function_ssa_artifact_8616(project, 0x1020) == before_ssa
    _run_full_prefix(project, codegen)
    assert codegen._inertia_segment_state_artifact.invocation_scope is entry.scope


def test_initial_jump_pipeline_keeps_scoped_ssa_cfg_coherent(native_scope):
    project, link, scope, _ = native_scope
    _install(project, scope.boot, link)
    project.kb.functions.function(addr=link.artifact.function_addr, create=True)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=link.artifact.function_addr))
    _run_full_prefix(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    projection = entry.view.cfg_projection_for(entry.scope)
    assert projection is not None
    assert codegen._inertia_vex_ir_function_ssa.predecessor_map == dict(projection.predecessors)


@pytest.mark.parametrize('mutation', ['current_ir', 'current_ssa', 'forged_output', 'input_summary', 'native'])
def test_conditional_semantic_projection_mutation_refuses(installed_leaf, mutation):
    from inertia.ir.declared_entry_pipeline import apply_pipeline_segment_state_8616
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    previous = codegen._inertia_segment_state_artifact
    projection = codegen._inertia_call_semantic_projection_8616
    if mutation == 'current_ir':
        codegen._inertia_vex_ir_artifact = replace(projection.outputs.function)
    elif mutation == 'current_ssa':
        codegen._inertia_vex_ir_function_ssa = replace(projection.function_ssa)
    elif mutation == 'input_summary':
        changed_input = replace(projection.scoped_input.input_ir, summary={})
        codegen._inertia_call_semantic_projection_8616 = replace(
            projection, scoped_input=replace(projection.scoped_input, input_ir=changed_input))
    elif mutation == 'native':
        project.loader.memory.store(0x1021, b'\x35')
    else:
        changed = replace(projection.outputs.function, blocks=())
        codegen._inertia_vex_ir_artifact = changed
        codegen._inertia_call_semantic_projection_8616 = replace(
            projection, outputs=replace(projection.outputs, function=changed))
    with pytest.raises(PipelineHardError, match='binding refused'):
        apply_pipeline_segment_state_8616(project, codegen)
    assert codegen._inertia_segment_state_artifact is previous


def test_semantic_consumption_replays_once_and_never_reuses_proof(installed_leaf, monkeypatch):
    import inertia.ir.ir_boundary_cfg as coverage
    from inertia.ir.scoped_function_ir_view import ScopedFunctionIRView8616
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    source = codegen._inertia_call_semantic_projection_8616.scoped_input
    counts = {'view': 0, 'native': 0}
    real_projection = ScopedFunctionIRView8616.cfg_projection_for
    real_native = coverage._scoped_native_failure_8616
    def projection(view, scope, **kwargs):
        counts['view'] += 1
        return real_projection(view, scope, **kwargs)
    def native(*args):
        counts['native'] += 1
        return real_native(*args)
    monkeypatch.setattr(ScopedFunctionIRView8616, 'cfg_projection_for', projection)
    monkeypatch.setattr(coverage, '_scoped_native_failure_8616', native)
    assert source.authenticate()
    assert counts == {'view': 1, 'native': 1}
    assert source.authenticate()
    assert counts == {'view': 2, 'native': 2}
    project.loader.memory.store(0x1021, b'\x35')
    assert not source.authenticate()


def test_semantic_consumption_reduces_canonical_traversals(installed_leaf, monkeypatch, record_property):
    """Paired validation shares traversals, while every consumption starts fresh."""
    import sys
    from time import perf_counter

    import inertia.ir.scoped_function_ir_view as view
    import inertia.ir.source_graph_binding as graph
    import inertia.semantics.scoped_call_projection as semantic

    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    source = codegen._inertia_call_semantic_projection_8616.scoped_input
    encoders = []
    comparisons = []
    # _SourceGraphEncoder8616 is an immutable Cython extension type, so its
    # __init__ cannot be instrumented. Every encoder construction goes through
    # exactly one of these public factories; count each call through every
    # bound module alias instead.
    encoder_factories = (
        'capture_immutable_source_graph_facts_8616',
        'source_graphs_equal_8616',
        'canonical_call_stack_effect_8616',
        'canonical_source_graph_8616',
        'canonical_ir_instruction_graph_8616',
    )
    originals = {name: getattr(graph, name) for name in encoder_factories}
    for module in list(sys.modules.values()):
        for name, original in originals.items():
            try:
                bound = getattr(module, name, None)
            except AttributeError:
                continue
            if bound is not original:
                continue

            def counted(*args, _original=original, **kwargs):
                encoders.append(_original)
                return _original(*args, **kwargs)

            monkeypatch.setattr(module, name, counted)

    def legacy(left_addr, left, right_addr, right):
        comparisons.append((left_addr, right_addr))
        return graph.canonical_source_graph_8616(left_addr, left) == graph.canonical_source_graph_8616(right_addr, right)
    with monkeypatch.context() as baseline:
        for module in (view, semantic, graph):
            baseline.setattr(module, 'source_graphs_equal_8616', legacy)
        started = perf_counter()
        assert source.authenticate()
        record_property('legacy_authenticate_s', perf_counter() - started)
    before = len(encoders)
    encoders.clear()
    started = perf_counter()
    assert source.authenticate()
    record_property('paired_authenticate_s', perf_counter() - started)
    after = len(encoders)
    record_property('legacy_encoder_count', before)
    record_property('paired_encoder_count', after)
    # The EMPTY identity view checks native coverage once itself and once at
    # the enclosing boundary, alongside view replay and semantic input pairs.
    # Scoped seals compare immutable canonical facts, so their two graph
    # comparisons no longer route through source_graphs_equal_8616; each seal
    # still runs its before/native/current captures as one encoder apiece.
    # Registry/domain source-revision authentication adds three fixed
    # traversals on top of that under the bound-block contract.
    assert len(comparisons) == 2
    assert before == 14
    assert after == 12
    assert after == before - len(comparisons)
    encoders.clear()
    assert source.authenticate()
    assert len(encoders) == after


@pytest.mark.parametrize('mutation', ['source', 'declaration'])
def test_semantic_consumption_rechecks_source_and_declaration(installed_leaf, mutation):
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    source = codegen._inertia_call_semantic_projection_8616.scoped_input
    assert source.authenticate()
    if mutation == 'source':
        changed = replace(source, source_ir=replace(source.source_ir))
    else:
        chain = source.scope.chain
        admission = replace(chain.admission, spec=replace(chain.admission.spec, native_sha256='0' * 64))
        scope = replace(source.scope, chain=replace(chain, admission=admission))
        changed = replace(source, scope=scope)
    assert not changed.authenticate()


def _fresh_input_args(project: object, codegen: object) -> tuple[object, object]:
    """Return the same ``(function, source_ir)`` the pipeline consumes."""
    projection = codegen._inertia_call_semantic_projection_8616
    source_ir = projection.source_ir
    function = project.kb.functions.function(addr=source_ir.function_addr, create=False)
    return function, source_ir


def test_scoped_input_construction_authenticates_view_once(installed_leaf: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """Construction must not validate the same view chain twice per operation."""
    import inertia.semantics.scoped_call_projection as semantic
    from inertia.ir.scoped_function_ir_view import ScopedFunctionIRView8616
    from inertia.semantics.scoped_call_projection import scoped_call_semantic_input_8616

    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    function, source_ir = _fresh_input_args(project, codegen)
    counts = {"view": 0, "consume": 0}
    real_projection = ScopedFunctionIRView8616.cfg_projection_for
    real_consume = semantic.consume_scoped_ir_boundary_projection_8616

    def counting_view(view: object, scope: object, **kwargs: object) -> object:
        counts["view"] += 1
        return real_projection(view, scope, **kwargs)

    def counting_consume(*args: object, **kwargs: object) -> object:
        counts["consume"] += 1
        return real_consume(*args, **kwargs)

    monkeypatch.setattr(ScopedFunctionIRView8616, "cfg_projection_for", counting_view)
    monkeypatch.setattr(
        semantic, "consume_scoped_ir_boundary_projection_8616", counting_consume
    )
    fresh = scoped_call_semantic_input_8616(project, codegen, function, source_ir)
    assert fresh is not None
    assert counts == {"view": 1, "consume": 1}


def test_scoped_input_construction_still_refuses_mutated_native(installed_leaf: object) -> None:
    """The single consumption keeps every fresh native/source mutation check."""
    from inertia.semantics.scoped_call_projection import scoped_call_semantic_input_8616

    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    function, source_ir = _fresh_input_args(project, codegen)
    project.loader.memory.store(0x1021, b"\x35")
    with pytest.raises(PipelineHardError):
        scoped_call_semantic_input_8616(project, codegen, function, source_ir)


def test_scoped_input_construction_still_refuses_forged_declaration(installed_leaf: object) -> None:
    """A forged retained entry scope still refuses at construction."""
    from dataclasses import replace

    from inertia.semantics.scoped_call_projection import scoped_call_semantic_input_8616

    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    function, source_ir = _fresh_input_args(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    chain = entry.scope.chain
    admission = replace(
        chain.admission, spec=replace(chain.admission.spec, native_sha256="0" * 64)
    )
    forged_scope = replace(entry.scope, chain=replace(chain, admission=admission))
    codegen._inertia_declared_entry_pipeline_8616 = replace(entry, scope=forged_scope)
    with pytest.raises(PipelineHardError):
        scoped_call_semantic_input_8616(project, codegen, function, source_ir)


def test_constructed_input_keeps_full_authenticate_contract(installed_leaf: object) -> None:
    """The constructed input still revalidates fully on later authenticate calls."""
    from inertia.semantics.scoped_call_projection import scoped_call_semantic_input_8616

    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    function, source_ir = _fresh_input_args(project, codegen)
    fresh = scoped_call_semantic_input_8616(project, codegen, function, source_ir)
    assert fresh is not None
    assert fresh.authenticate()
    project.loader.memory.store(0x1021, b"\x35")
    assert not fresh.authenticate()


@pytest.mark.parametrize("mutation", ["source", "view_source", "scope_project"])
def test_constructor_rejects_replaced_entry_context(installed_leaf: object, mutation: str) -> None:
    """Fresh consumption cannot borrow another source/view/project context."""
    from dataclasses import replace

    from inertia.semantics.scoped_call_projection import scoped_call_semantic_input_8616

    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    function, source_ir = _fresh_input_args(project, codegen)
    entry = codegen._inertia_declared_entry_pipeline_8616
    if mutation == "source":
        source_ir = replace(source_ir)
    elif mutation == "view_source":
        entry = replace(entry, view=replace(entry.view, source_artifact=replace(source_ir)))
    else:
        entry = replace(entry, scope=replace(entry.scope, project=object()))
    codegen._inertia_declared_entry_pipeline_8616 = entry
    with pytest.raises(PipelineHardError):
        scoped_call_semantic_input_8616(project, codegen, function, source_ir)


def test_repeat_skips_constructor_but_authenticates_outputs(installed_leaf: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """An unchanged second pass must reuse only after current output authentication."""
    from inertia.semantics import call_stack_effect_pipeline as owner
    from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    counts = {"constructor": 0, "outputs": 0}
    construct = owner.scoped_call_semantic_input_8616
    authenticate = ScopedCallSemanticInput8616.authenticates_outputs
    def counted_constructor(*args: object) -> object:
        counts["constructor"] += 1
        return construct(*args)
    def counted_outputs(*args: object) -> bool:
        counts["outputs"] += 1
        return authenticate(*args)
    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", counted_constructor)
    monkeypatch.setattr(ScopedCallSemanticInput8616, "authenticates_outputs", counted_outputs)
    assert owner.apply_x86_16_call_stack_effects_8616(project, codegen) is False
    assert counts == {"constructor": 0, "outputs": 1}
    project.loader.memory.store(0x1021, b"\x35")
    with pytest.raises(PipelineHardError):
        owner.apply_x86_16_call_stack_effects_8616(project, codegen)
    assert counts == {"constructor": 0, "outputs": 2}


@pytest.mark.parametrize("mutation", ["revoked", "project", "function", "source", "view", "scope", "bundle", "universal"])
def test_changed_context_cannot_reuse_scoped_projection(installed_leaf: object, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    """Changed context must enter ordinary rebuilding rather than consume old proof."""
    from inertia.semantics import call_stack_effect_pipeline as owner
    project, codegen, _ = installed_leaf
    _run_full_prefix(project, codegen)
    projection = codegen._inertia_call_semantic_projection_8616
    scoped = projection.scoped_input
    entry = codegen._inertia_declared_entry_pipeline_8616
    if mutation == "revoked":
        del codegen._inertia_declared_entry_pipeline_8616
    elif mutation == "project":
        projection = replace(projection, scoped_input=replace(scoped, project=object()))
    elif mutation == "function":
        projection = replace(projection, scoped_input=replace(scoped, function=object()))
    elif mutation == "source":
        projection = replace(projection, scoped_input=replace(scoped, source_ir=replace(scoped.source_ir)))
    elif mutation == "view":
        codegen._inertia_declared_entry_pipeline_8616 = replace(entry, view=replace(entry.view))
    elif mutation == "scope":
        codegen._inertia_declared_entry_pipeline_8616 = replace(entry, scope=replace(entry.scope))
    elif mutation == "bundle":
        codegen._inertia_declared_entry_pipeline_8616 = replace(entry, bundle=replace(entry.bundle, artifact=replace(entry.bundle.artifact)))
    else:
        projection = replace(projection, scoped_input=None)
    codegen._inertia_call_semantic_projection_8616 = projection
    def rebuilding(*args: object) -> object:
        raise LookupError("normal constructor reached")
    monkeypatch.setattr(owner, "scoped_call_semantic_input_8616", rebuilding)
    with pytest.raises(LookupError, match="normal constructor reached"):
        owner.apply_x86_16_call_stack_effects_8616(project, codegen)


def test_prepare_declared_head_constructs_once_before_bundle_callback(installed_leaf, monkeypatch):
    """The canonical fresh factory consumes one derivation before later callbacks."""
    import sys

    from inertia.ir import declared_entry_pipeline as pipeline
    from inertia.ir import real16_invocation_domain as domain
    from inertia.ir import vex_import
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    project, _codegen, source = installed_leaf
    returns = []
    observed = []
    original_bundle = vex_import.raw_x86_16_import_bundle_for_artifact_8616

    def trace(frame, event, _argument):
        if event == 'return' and frame.f_code is domain._derive_invocation_domain_8616.__code__:
            returns.append(frame.f_locals['callsite_addr'])
        return trace

    def bundle(*args, **kwargs):
        observed.append(tuple(returns))
        return original_bundle(*args, **kwargs)

    monkeypatch.setattr(vex_import, 'raw_x86_16_import_bundle_for_artifact_8616', bundle)
    previous = sys.gettrace()
    with segment_call_dependency_traversal_scope_8616():
        sys.settrace(trace)
        try:
            entry = pipeline._prepare_native_entry_8616(project, source, source.function_entries[0])
        finally:
            sys.settrace(previous)
    assert observed == [(0x1020,)]
    assert entry.scope.failure is None
    assert entry.scope.raw_fact_count == entry.scope.materialized_count
    # After the operation, ordinary public completeness still reauthenticates.
    project.loader.memory.store(0x1021, b'\x35')
    assert not entry.scope.complete


@pytest.mark.parametrize('exhausted', ['work', 'deadline', 'domains'])
def test_prepare_declared_head_preserves_current_construction_resource_refusal(installed_leaf, monkeypatch, exhausted):
    """Fresh routing does not fabricate a premise when construction admission fails."""
    from inertia.ir import declared_entry_pipeline as pipeline
    from inertia.ir import real16_invocation_domain as domain
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    project, _codegen, source = installed_leaf
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if exhausted == 'work':
            traversal.census_work_units = domain._CENSUS_WORK_LIMIT_8616 + 1
        elif exhausted == 'domains':
            traversal.remaining_domains = 0
        else:
            monkeypatch.setattr(domain, '_census_deadline_8616', lambda: 0.0)
        entry = pipeline._prepare_native_entry_8616(project, source, source.function_entries[0])
    assert type(entry) is pipeline.UnprovedDeclaredEntry8616
    assert entry.premise is pipeline.DeclaredEntryPremise8616.UNKNOWN_REFUSE
    assert entry.view.failure is not None
    assert entry.view.source_artifact is entry.bundle.artifact


def test_prepare_declared_head_reauthenticates_native_mutation_after_fresh_construction(installed_leaf, monkeypatch):
    """Later bundle callbacks cannot turn the fresh domain into a replay waiver."""
    from inertia.ir import declared_entry_pipeline as pipeline
    from inertia.ir import vex_import
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    project, _codegen, source = installed_leaf
    original = vex_import.raw_x86_16_import_bundle_for_artifact_8616

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        project.loader.memory.store(0x1021, b'\x35')
        return result

    monkeypatch.setattr(vex_import, 'raw_x86_16_import_bundle_for_artifact_8616', changed)
    with segment_call_dependency_traversal_scope_8616(), pytest.raises(PipelineHardError):
        pipeline._prepare_native_entry_8616(project, source, source.function_entries[0])
