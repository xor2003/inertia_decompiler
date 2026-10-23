"""Restartable local-variable allocation on the real native boundary.

Real angr CFGFast -> Clinic -> VariableRecoveryFast on a 16-bit blob, through
the production guard stack incl. ``guard_angr_clinic_stage_markers`` (the actual
hook site). The CONTROLLED allocator-input revision removes the stack
byte-stores from the pre-recovery AIL graph; no claim is made that those stores
were proven dead - the revision is a controlled input change, and parity is
measured against a fresh native run on the same final input.
"""

from __future__ import annotations

import contextlib
import io

import angr
import networkx
import pytest
from angr import ailment
from angr.analyses.decompiler.clinic import ClinicStage
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable

from inertia.cli.native_allocation_runtime import session_for
from inertia.cli.runtime_support import (
    guard_angr_ail_narrowing,
    guard_angr_clinic_stage_markers,
    guard_angr_variable_recovery_binop_sub_size_mismatch,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401  registers lifter
from inertia.frontend.x86_16.simos_86_16 import SimCC8616MSCsmall  # noqa: F401  registers cc
from inertia.frontend.x86_16.variable_allocation_convergence import (
    fingerprint_allocation_inputs,
)
from inertia.lowering.allocation_convergence import (
    AllocationConvergenceRefusal,
    AllocationFingerprintRefusal,
    AllocationRestartVerdict,
)
from inertia.pipeline.errors import PipelineHardError

# push bp; mov bp,sp; mov ax,[bp+4]; pop bp; ret
CODE = bytes.fromhex("5589e58b46045dc3")
BASE = 0x1000


@contextlib.contextmanager
def _native_guards(project):
    with contextlib.ExitStack() as stack:
        stack.enter_context(guard_angr_variable_recovery_binop_sub_size_mismatch(project))
        stack.enter_context(guard_angr_ail_narrowing(project))
        stack.enter_context(guard_angr_clinic_stage_markers(project))
        yield


def _project():
    arch = Arch86_16()
    arch.bits = 32  # loader-visible width like the MZ backend
    return angr.Project(
        io.BytesIO(CODE),
        main_opts={"backend": "blob", "arch": arch, "base_addr": BASE, "entry_point": BASE},
    )


def _clinic_at_recovery_boundary():
    project = _project()
    cfg = project.analyses.CFGFast(normalize=True)
    func = cfg.kb.functions[BASE]
    with _native_guards(project):
        clinic = project.analyses.Clinic(func, cfg=cfg, end_stage=ClinicStage.POST_SSA_LEVEL1_SIMPLIFICATIONS)
    return project, func, clinic


def _full_state(project, func, clinic):
    """Manager + link map + prototype surface (the affected publication)."""
    vm = project.kb.dec_variables[func.addr]
    vmap = clinic.variable_map
    return {
        "idents": sorted(v.ident for v in vm._variables),
        "stack_offsets": {
            off: sorted(v.ident for v in vm.find_variables_by_stack_offset(off))
            for off in sorted({v.offset for v in vm._variables if isinstance(v, SimStackVariable)})
        },
        "input_variables": sorted(v.ident for v in vm.input_variables()),
        "manual_types": sorted(v.ident for v in vm.variables_with_manual_types),
        "types": {v.ident: type(vm.variable_to_types.get(v)).__name__ for v in vm._variables},
        "unified": sorted((v.ident, u.ident) for v, u in vm._variables_to_unified_variables.items()),
        "vvar_links": sorted((k, v.ident) for k, v in vm._vvarid_to_variable.items()),
        "atom_links": sorted(
            (k, getattr(v, "ident", None)) for k, v in vmap._variables.items()
        ),
        "vvar_map": sorted((k, getattr(v, "ident", None)) for k, v in vmap._vvar_id_to_variable.items()),
    }


def _drop_store_statements(graph) -> networkx.DiGraph:
    """CONTROLLED revision: pre-recovery graph loses the stack byte-stores."""
    new_graph = networkx.DiGraph()
    for block in graph:
        kept = [s for s in block.statements if not isinstance(s, ailment.Stmt.Store)]
        new_graph.add_node(ailment.Block(block.addr, original_size=block.original_size, statements=kept, idx=block.idx))
    for u, v in graph.edges():
        nu = next(b for b in new_graph if (b.addr, b.idx) == (u.addr, u.idx))
        nv = next(b for b in new_graph if (b.addr, b.idx) == (v.addr, v.idx))
        new_graph.add_edge(nu, nv)
    return new_graph


def _fresh_native_full_state(revise: bool):
    """Single clean native run through the hook on the final input."""
    project, func, clinic = _clinic_at_recovery_boundary()
    if revise:
        clinic._ail_graph = _drop_store_statements(clinic._ail_graph)
    with _native_guards(project):
        clinic._stage_recover_variables()
    return _full_state(project, func, clinic)


def test_native_rerun_through_hook_matches_fresh_full_state() -> None:
    """Revised input -> transactional restart -> full parity with fresh native."""
    project, func, clinic = _clinic_at_recovery_boundary()
    with _native_guards(project):
        clinic._stage_recover_variables()  # first run through the real hook
    clinic._ail_graph = _drop_store_statements(clinic._ail_graph)
    with _native_guards(project):
        clinic._stage_recover_variables()  # revision restart through the hook
    actual = _full_state(project, func, clinic)
    expected = _fresh_native_full_state(revise=True)
    assert actual == expected
    session = session_for(project, func.addr)
    assert session.last_verdict is AllocationRestartVerdict.RESTARTED
    assert session.census().validate() == ()


def test_unchanged_inputs_do_not_rerun_recovery() -> None:
    project, func, clinic = _clinic_at_recovery_boundary()
    with _native_guards(project):
        clinic._stage_recover_variables()
    state1 = _full_state(project, func, clinic)
    with _native_guards(project):
        clinic._stage_recover_variables()
    session = session_for(project, func.addr)
    assert session.last_verdict is AllocationRestartVerdict.UNCHANGED
    assert _full_state(project, func, clinic) == state1


def test_failed_rerun_restores_all_native_surfaces() -> None:
    project, func, clinic = _clinic_at_recovery_boundary()
    with _native_guards(project):
        clinic._stage_recover_variables()
    manager = project.kb.dec_variables.function_managers[func.addr]
    state1 = _full_state(project, func, clinic)
    proto1 = (func.prototype, func.prototype_source, func.prototype_libname)

    revised = _drop_store_statements(clinic._ail_graph)
    clinic._ail_graph = revised

    def _boom(self, arg_list):  # late-stage failure: real partial work happened
        poisoned = next(iter(manager._variables))
        poisoned.name = "poisoned"
        poisoned.renamed = True
        raise RuntimeError("forced post-recovery failure")

    original = type(clinic)._make_function_prototype
    type(clinic)._make_function_prototype = _boom
    try:
        with pytest.raises(RuntimeError, match="forced post-recovery failure"), _native_guards(project):
            clinic._stage_recover_variables()
    finally:
        type(clinic)._make_function_prototype = original

    assert project.kb.dec_variables.function_managers[func.addr] is manager
    assert [b.addr for b in clinic._ail_graph] == [b.addr for b in revised]
    assert (func.prototype, func.prototype_source, func.prototype_libname) == proto1
    assert _full_state(project, func, clinic) == state1
    # in-place mutation of an existing variable object was rolled back too
    assert state1["idents"] == _full_state(project, func, clinic)["idents"]
    assert not any(v.name == "poisoned" for v in manager._variables)
    assert session_for(project, func.addr).census().failures == 1


def _proto_mutation(clinic, func, counter):
    """Install a wrapper that revises prototype evidence mid-stage each round."""
    original = type(clinic)._make_function_prototype

    def _mutating(self, arg_list):
        original(self, arg_list)
        counter[0] += 1
        func.prototype = SimTypeFunction(
            [SimTypeShort(signed=True)], SimTypeShort(signed=True),
            arg_names=[f"rev_{counter[0]}"],
        ).with_arch(clinic.project.arch)

    type(clinic)._make_function_prototype = _mutating
    return original


def test_round_budget_exhaustion_is_typed_refusal() -> None:
    """Distinct mid-run evidence revisions beyond budget -> typed refusal."""
    project, func, clinic = _clinic_at_recovery_boundary()
    session = session_for(project, func.addr, max_rounds=1)
    counter = [0]
    original = _proto_mutation(clinic, func, counter)
    try:
        with pytest.raises(PipelineHardError) as ei, _native_guards(project):
            clinic._stage_recover_variables()
    finally:
        type(clinic)._make_function_prototype = original
    failure = ei.value
    assert failure.details["verdict"] is AllocationRestartVerdict.EXHAUSTED
    assert failure.function_addr == func.addr
    assert isinstance(failure.__cause__, AllocationConvergenceRefusal)
    assert failure.__cause__.verdict is AllocationRestartVerdict.EXHAUSTED
    assert session.last_verdict is AllocationRestartVerdict.EXHAUSTED


def test_midrun_evidence_revision_converges() -> None:
    """A type discovered during recovery forces another bounded round."""
    project, func, clinic = _clinic_at_recovery_boundary()
    injected = [False]
    original = type(clinic)._make_function_prototype

    def _injecting(self, arg_list):
        original(self, arg_list)
        if not injected[0]:
            injected[0] = True
            vm = project.kb.dec_variables.function_managers[func.addr]
            var = next(iter(vm._variables))
            vm.set_variable_type(
                var, SimTypeShort(signed=False).with_arch(project.arch), mark_manual=True
            )

    type(clinic)._make_function_prototype = _injecting
    try:
        with _native_guards(project):
            clinic._stage_recover_variables()
    finally:
        type(clinic)._make_function_prototype = original
    session = session_for(project, func.addr)
    assert session.last_verdict is AllocationRestartVerdict.RESTARTED
    assert session.rounds_used >= 1
    vm = project.kb.dec_variables.function_managers[func.addr]
    assert any(v.ident for v in vm.variables_with_manual_types)


def test_new_clinic_generation_republishes_links() -> None:
    """Parent red: a second Clinic must not consume the old publication."""
    project, func, first = _clinic_at_recovery_boundary()
    with _native_guards(project):
        first._stage_recover_variables()
    assert len(first.variable_map._variables) > 0
    cfg = project.analyses.CFGFast(normalize=True)
    with _native_guards(project):
        second = project.analyses.Clinic(
            func, cfg=cfg, end_stage=ClinicStage.POST_SSA_LEVEL1_SIMPLIFICATIONS
        )
        second._stage_recover_variables()
    assert second._ail_graph is not first._ail_graph
    assert len(second.variable_map._variables) > 0


def test_fingerprint_refusal_gates_downstream() -> None:
    """Unsupported inputs raise a typed refusal; no dirty native run happens."""
    from inertia.frontend.x86_16 import variable_allocation_convergence as adapter

    project, func, clinic = _clinic_at_recovery_boundary()
    real_fp = adapter.fingerprint_allocation_inputs
    adapter.fingerprint_allocation_inputs = lambda c: (_ for _ in ()).throw(
        AllocationFingerprintRefusal("synthetic unsupported form")
    )
    try:
        with _native_guards(project), pytest.raises(PipelineHardError) as ei:
            clinic._stage_recover_variables()
    finally:
        adapter.fingerprint_allocation_inputs = real_fp
    failure = ei.value
    assert failure.details["verdict"] is AllocationRestartVerdict.REFUSED
    assert failure.function_addr == func.addr
    assert isinstance(failure.__cause__, AllocationConvergenceRefusal)
    session = session_for(project, func.addr)
    assert session.last_verdict is AllocationRestartVerdict.REFUSED
    # no publication was attempted: the manager stays untouched
    assert session.census().attempts == 0
    assert len(clinic.variable_map._variables) == 0


def test_reverted_evidence_after_convergence_reruns() -> None:
    """Converged A->B, then evidence reverted to A: must rerun, not reuse B."""
    project, func, clinic = _clinic_at_recovery_boundary()
    proto_a = SimTypeFunction(
        [SimTypeShort(signed=True)], SimTypeShort(signed=True)
    ).with_arch(project.arch)
    func.prototype = proto_a
    injected = [False]
    original = type(clinic)._make_function_prototype

    def _injecting(self, arg_list):
        original(self, arg_list)
        if not injected[0]:
            injected[0] = True
            func.prototype = SimTypeFunction(
                [SimTypeShort(signed=False)], SimTypeShort(signed=True)
            ).with_arch(project.arch)

    type(clinic)._make_function_prototype = _injecting
    try:
        with _native_guards(project):
            clinic._stage_recover_variables()
    finally:
        type(clinic)._make_function_prototype = original
    session = session_for(project, func.addr)
    assert session.last_verdict is AllocationRestartVerdict.RESTARTED

    # revert authoritative evidence to A under the same bound surfaces:
    # reuse of the B publication would be stale
    func.prototype = proto_a
    with _native_guards(project):
        clinic._stage_recover_variables()
    assert session.last_verdict is AllocationRestartVerdict.RESTARTED
    assert _full_state(project, func, clinic) != ()  # published, non-empty links
    assert len(clinic.variable_map._variables) > 0


def test_fingerprint_detects_cfg_edge_and_signedness() -> None:
    """Parent red: graph edges and type signedness are bound in fingerprints."""
    project, func, clinic = _clinic_at_recovery_boundary()
    before = fingerprint_allocation_inputs(clinic)
    block = next(iter(clinic._ail_graph))
    clinic._ail_graph.add_edge(block, block)
    assert fingerprint_allocation_inputs(clinic) != before
    clinic._ail_graph.remove_edge(block, block)
    assert fingerprint_allocation_inputs(clinic) == before

    func.prototype = SimTypeFunction([SimTypeShort(signed=True)], SimTypeShort(signed=True)).with_arch(project.arch)
    signed = fingerprint_allocation_inputs(clinic)
    func.prototype = SimTypeFunction([SimTypeShort(signed=False)], SimTypeShort(signed=True)).with_arch(project.arch)
    unsigned = fingerprint_allocation_inputs(clinic)
    assert signed != unsigned


if __name__ == "__main__":
    pytest.main([__file__, "-x"])


def test_call_and_phi_expression_keys_are_reachable() -> None:
    """Parent red: declared Call/Phi keyers must not be masked by Expression."""
    from inertia.frontend.x86_16.variable_allocation_convergence import _expr_key

    const_a = ailment.Expr.Const(0, 0x2000, 16)
    const_b = ailment.Expr.Const(3, 0x3000, 16)
    call_a = ailment.Expr.Call(1, const_a, args=[const_a], bits=16)
    call_b = ailment.Expr.Call(1, const_a, args=[const_b], bits=16)
    assert _expr_key(call_a)[0] == "call"
    assert _expr_key(call_a) != _expr_key(call_b)  # argument operands bound
    vvar_a = ailment.Expr.VirtualVariable(4, 5, 16, ailment.Expr.VirtualVariableCategory.REGISTER)
    vvar_b = ailment.Expr.VirtualVariable(6, 7, 16, ailment.Expr.VirtualVariableCategory.REGISTER)
    phi_a = ailment.Expr.Phi(2, 16, [((0x1000, None), vvar_a)])
    phi_b = ailment.Expr.Phi(2, 16, [((0x1000, None), vvar_b)])
    assert _expr_key(phi_a)[0] == "phi"
    assert _expr_key(phi_a) != _expr_key(phi_b)  # phi operands bound


def test_type_key_nested_layout_and_refusals() -> None:
    """Parent red: array element types bind; unknown forms refuse typed."""
    from angr.sim_type import SimTypeArray

    from inertia.frontend.x86_16.variable_allocation_convergence import (
        _type_hint_key,
        _type_key,
    )

    arch = Arch86_16()
    arch.bits = 32
    signed = SimTypeArray(SimTypeShort(signed=True), 2).with_arch(arch)
    unsigned = SimTypeArray(SimTypeShort(signed=False), 2).with_arch(arch)
    assert _type_key(signed) != _type_key(unsigned)
    wider = SimTypeArray(SimTypeShort(signed=True), 4).with_arch(arch)
    assert _type_key(signed) != _type_key(wider)
    with pytest.raises(AllocationFingerprintRefusal):
        _type_key(object())
    with pytest.raises(AllocationFingerprintRefusal):
        _type_hint_key(object(), "unsigned")


@pytest.mark.parametrize("mutation", ("drop_atoms", "replace_atom", "drop_vvars", "change_inferred_type"))
def test_same_objects_do_not_authorize_damaged_publication(mutation: str) -> None:
    """A damaged output cannot reach codegen through unchanged-input reuse."""
    from inertia.pipeline.errors import PipelineHardError

    project, func, clinic = _clinic_at_recovery_boundary()
    with _native_guards(project):
        clinic._stage_recover_variables()
    manager = project.kb.dec_variables.function_managers[func.addr]
    graph = clinic._ail_graph
    variable_map = clinic.variable_map
    if mutation == "drop_atoms":
        variable_map._variables.clear()
    elif mutation == "replace_atom":
        address, previous = next(iter(variable_map._variables.items()))
        replacement = next(v for v in manager._variables if v is not previous)
        variable_map._variables[address] = replacement
    elif mutation == "drop_vvars":
        variable_map._vvar_id_to_variable.clear()
    else:
        variable = next(v for v in manager._variables if v not in manager.variables_with_manual_types)
        from inertia.frontend.x86_16.variable_allocation_convergence import _type_key

        before = _type_key(manager.variable_to_types[variable])
        candidate = SimTypeShort(signed=False).with_arch(project.arch)
        if _type_key(candidate) == before:
            candidate = SimTypeShort(signed=True).with_arch(project.arch)
        assert _type_key(candidate) != before
        manager.variable_to_types[variable] = candidate
    with pytest.raises(PipelineHardError) as caught, _native_guards(project):
        clinic._stage_recover_variables()
    cause = caught.value.__cause__
    assert isinstance(cause, AllocationConvergenceRefusal)
    assert cause.verdict is AllocationRestartVerdict.REFUSED
    assert clinic.variable_map is variable_map and clinic._ail_graph is graph
    assert project.kb.dec_variables.function_managers[func.addr] is manager
    session = session_for(project, func.addr)
    assert session.census().attempts == 1
    assert session.census().refused == 1
    assert session.last_result is None
    assert session.census().validate() == ()


def test_non_graph_revision_consumes_retained_raw_input() -> None:
    """A revised prototype reuses original SSA input, never linked output."""
    project, func, clinic = _clinic_at_recovery_boundary()
    raw = fingerprint_allocation_inputs(clinic)
    with _native_guards(project):
        clinic._stage_recover_variables()
    func.prototype = SimTypeFunction(
        [SimTypeShort(signed=True)], SimTypeShort(signed=False),
    ).with_arch(project.arch)
    with _native_guards(project):
        clinic._stage_recover_variables()
    accepted = session_for(project, func.addr).accepted_fingerprint
    assert accepted is not None
    assert accepted.graph_nodes == raw.graph_nodes
    assert accepted.graph_edges == raw.graph_edges
    fresh_project, fresh_func, fresh_clinic = _clinic_at_recovery_boundary()
    fresh_func.prototype = SimTypeFunction(
        [SimTypeShort(signed=True)], SimTypeShort(signed=False),
    ).with_arch(fresh_project.arch)
    with _native_guards(fresh_project):
        fresh_clinic._stage_recover_variables()
    assert _full_state(project, func, clinic) == _full_state(fresh_project, fresh_func, fresh_clinic)
    from inertia.frontend.x86_16.variable_allocation_convergence import _type_key

    actual_types = {v.ident: _type_key(ty) for v, ty in project.kb.dec_variables[func.addr].variable_to_types.items()}
    expected_types = {v.ident: _type_key(ty) for v, ty in fresh_project.kb.dec_variables[fresh_func.addr].variable_to_types.items()}
    assert actual_types == expected_types


@pytest.mark.parametrize("architecture", ("AMD64", "X86"))
def test_foreign_architectures_keep_their_native_recovery(architecture: str) -> None:
    """The real16 adapter cannot replace another registered frontend's policy."""
    from inertia.cli.runtime_support import _converged_recover_variables_8616

    project = angr.Project(
        io.BytesIO(b"\xc3"),
        main_opts={"backend": "blob", "arch": architecture, "base_addr": BASE, "entry_point": BASE},
    )

    def native_stage() -> None:
        """Represent the original native stage without invoking real16 contracts."""

    assert _converged_recover_variables_8616(project, native_stage) is native_stage


def test_missing_native_input_graph_refuses_before_recovery() -> None:
    """Missing graph evidence is unknown, never an empty valid allocation."""
    from inertia.pipeline.errors import PipelineHardError

    project, func, clinic = _clinic_at_recovery_boundary()
    clinic._ail_graph = None
    with pytest.raises(PipelineHardError) as caught, _native_guards(project):
        clinic._stage_recover_variables()
    cause = caught.value.__cause__
    assert isinstance(cause, AllocationConvergenceRefusal)
    assert cause.verdict is AllocationRestartVerdict.REFUSED
    assert session_for(project, func.addr).census().attempts == 0
