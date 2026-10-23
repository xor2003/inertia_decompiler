"""Bounded native-fact rebind: retained canonical facts, never cloned graphs."""
import io
from copy import deepcopy
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import native_import_surface_cache as cache
from inertia.ir import source_graph_binding, vex_import
from inertia.ir.core import IRFunctionArtifact, IRInstr, IRRefusal

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", ["native", "caller", "configuration"])
def test_terminal_copy_callback_cannot_invalidate_binding(monkeypatch, mutation):
    """Late copying cannot publish a binding to changed source or caller facts."""
    project, boundary = _jump_world()
    original = vex_import._detached_terminal_evidence_8616
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)

        def mutate(surface):
            evidence = original(surface)
            if mutation == "native":
                project.loader.memory.store(boundary.addr, b"\x90")
            elif mutation == "caller":
                object.__setattr__(bundle.artifact.blocks[0].instrs[0], "op", "INVALID")
            else:
                project.selfmodifying_code = True
            return evidence

        monkeypatch.setattr(vex_import, "_detached_terminal_evidence_8616", mutate)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact,
        ) is None


def test_native_fact_producer_change_recaptures_private_facts(monkeypatch):
    """A replacement projection owner cannot reuse another owner's facts."""
    project, boundary = _jump_world()
    original = vex_import._native_surface_facts_8616
    calls = []

    def capture(surface):
        calls.append(1)
        return original(surface)

    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact,
        ) is not None
        monkeypatch.setattr(vex_import, "_native_surface_facts_8616", capture)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact,
        ) is not None
    assert calls == [1]


_JUMP_CODE = bytes(14) + bytes.fromhex('eb00c3')


def _jump_world(code=_JUMP_CODE):
    """Two-block native surface whose first block retains terminal evidence."""
    arch = Arch86_16()
    arch.bits = 32
    project = angr.Project(io.BytesIO(code),
        main_opts={'backend': 'blob', 'arch': arch, 'base_addr': 0x10000,
                   'entry_point': 0x10000}, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1000e, 0x1000e + 3)
    assert boundary is not None
    return project, boundary


def _counted(monkeypatch):
    """Instrument the native copy/encode work a raw rebind may repeat."""
    counts = {'lifts': 0, 'clones': 0, 'compares': 0, 'captures': 0}
    lift = vex_import._lift_x86_16_function_surface_8616
    clone = vex_import._copy_native_surface_8616
    equal = source_graph_binding.source_graphs_equal_8616
    capture = source_graph_binding.capture_immutable_source_graph_facts_8616

    def lifted(*args, **kwargs):
        counts['lifts'] += 1
        return lift(*args, **kwargs)

    def cloned(*args, **kwargs):
        counts['clones'] += 1
        return clone(*args, **kwargs)

    def compared(*args, **kwargs):
        counts['compares'] += 1
        return equal(*args, **kwargs)

    def captured(*args, **kwargs):
        counts['captures'] += 1
        return capture(*args, **kwargs)

    monkeypatch.setattr(vex_import, '_lift_x86_16_function_surface_8616', lifted)
    monkeypatch.setattr(vex_import, '_copy_native_surface_8616', cloned)
    monkeypatch.setattr(source_graph_binding, 'source_graphs_equal_8616', compared)
    monkeypatch.setattr(
        source_graph_binding, 'capture_immutable_source_graph_facts_8616', captured)
    return counts


def test_repeated_rebind_reuses_retained_native_facts(monkeypatch):
    """Repeat rebinds authenticate against retained facts, not a fresh clone."""
    project, boundary = _jump_world()
    counts = _counted(monkeypatch)
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert bundle.terminal_evidence
        for _ in range(3):
            rebound = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                project, boundary, bundle.artifact)
            assert rebound is not None and rebound.artifact is bundle.artifact
    # One lift and one private retain copy for the initial import. Repeat
    # rebinds add exactly one fresh caller-graph canonicalization each;
    # the retained native facts are encoded once and never re-encoded, and
    # no whole-surface clone or shared-encoder comparison runs per rebind.
    assert counts['lifts'] == 1
    assert counts['clones'] == 1
    assert counts['compares'] == 0
    assert counts['captures'] == 4


def test_rebind_selects_matching_variant_after_alternation(monkeypatch):
    """Raw variants must not evict the record a same-source rebind needs.

    Alternating unconditional and conditional-return imports of one address
    retain separate bounded records; a rebind authenticates the variant whose
    exact raw source matches instead of re-deriving a full lift.
    """
    from tests.ir.test_native_import_surface_cache import _conditional_boundary

    project, boundary = _jump_world()
    conditional = _conditional_boundary(boundary)
    counts = _counted(monkeypatch)
    with cache.native_import_request_8616():
        plain = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        bound = vex_import.raw_x86_16_function_bundle_8616(project, conditional)
        for _ in range(2):
            assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                project, boundary, plain.artifact) is not None
            rebound = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                project, conditional, bound.artifact)
            assert rebound is not None and rebound.artifact is bound.artifact
    assert counts['lifts'] == 2


def test_rebind_outside_request_reimports_and_recompares(monkeypatch):
    """Without a live request, every rebind runs the ordinary import path."""
    project, boundary = _jump_world()
    bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
    counts = _counted(monkeypatch)
    for _ in range(2):
        rebound = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact)
        assert rebound is not None and rebound.artifact is bundle.artifact
    assert counts['lifts'] == 2 and counts['compares'] == 2
    assert counts['captures'] == 0


def test_rebind_does_not_share_facts_across_requests(monkeypatch):
    """A second request re-authenticates the source before any fact reuse."""
    project, boundary = _jump_world()
    counts = _counted(monkeypatch)
    bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
    with cache.native_import_request_8616():
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        first = dict(counts)
    with cache.native_import_request_8616():
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
    # The second request's first rebind owned its own lift and comparison;
    # only then did retained facts serve that request's second rebind.
    assert counts['lifts'] == first['lifts'] + 1
    assert counts['compares'] == first['compares'] + 1
    assert counts['captures'] == first['captures'] + 2


def test_rebind_poisoned_caller_graph_refuses_after_reuse():
    """A mutated frozen caller node cannot bypass the fresh per-call capture."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        object.__setattr__(bundle.artifact.blocks[0].instrs[0], 'op', 'INJECTED')
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is None


def test_rebind_equal_detached_artifact_still_authenticates():
    """A structurally equal but rebuilt artifact rebinding matches old semantics."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        rebuilt = deepcopy(bundle.artifact)
        rebound = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, rebuilt)
        assert rebound is not None and rebound.artifact is rebuilt


def test_rebind_changed_function_refusals_refuse():
    """Function-level refusal evidence is compared explicitly, not by == alone."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        forged = replace(bundle.artifact, refusals=(IRRefusal('forged', 'forged'),))
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, forged) is None


def test_rebind_changed_block_refusals_refuse():
    """Block-level refusal evidence is checked even inside a reused record."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        forged_block = replace(
            bundle.artifact.blocks[0],
            refusals=(IRRefusal('forged', 'forged', bundle.artifact.blocks[0].addr),))
        forged = replace(
            bundle.artifact,
            blocks=(forged_block, *bundle.artifact.blocks[1:]))
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, forged) is None


def test_rebind_malformed_caller_graph_raises_typed_failure():
    """A malformed caller surface keeps the canonical typed refusal, never a guess."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        broken = replace(
            bundle.artifact,
            blocks=(replace(
                bundle.artifact.blocks[0],
                instrs=[IRInstr('NOP', None, ())],  # type: ignore[arg-type]
            ), *bundle.artifact.blocks[1:]))
        with pytest.raises(source_graph_binding.SourceGraphSerializationError8616):
            vex_import.raw_x86_16_import_bundle_for_artifact_8616(
                project, boundary, broken)


def test_rebind_changed_native_bytes_reimport_and_refuse(monkeypatch):
    """Changed source bytes invalidate the record; the caller cannot ride along."""
    project, boundary = _jump_world()
    counts = _counted(monkeypatch)
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        assert counts['lifts'] == 1 and counts['compares'] == 0
        project.loader.memory.store(boundary.addr, b'\x90')
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is None
        assert counts['lifts'] == 2 and counts['compares'] == 1


def test_rebind_configuration_mutation_forces_full_path(monkeypatch):
    """Engine configuration drift must not read retained facts as unchanged."""
    project, boundary = _jump_world()
    counts = _counted(monkeypatch)
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        assert counts['lifts'] == 1 and counts['compares'] == 0
        project.factory.default_engine._single_step = True
        rebound = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact)
        assert counts['lifts'] == 2 and counts['compares'] == 1
        assert rebound is None or rebound.artifact is bundle.artifact


def test_rebind_producer_callback_mutation_reimports(monkeypatch):
    """Replacing a registered lift producer invalidates retained facts honestly."""
    project, boundary = _jump_world()
    counts = _counted(monkeypatch)
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        assert counts['lifts'] == 1 and counts['compares'] == 0
        native = vex_import._block_to_ir

        def convert(block, **kwargs):
            return native(block, **kwargs)

        monkeypatch.setattr(vex_import, '_block_to_ir', convert)
        rebound = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact)
        assert rebound is not None and rebound.artifact is bundle.artifact
        assert counts['lifts'] == 2 and counts['compares'] == 1


def test_rebind_terminal_evidence_is_detached_per_call():
    """Each bundle owns a private evidence copy; mutation cannot reach records."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        first = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact)
        second = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact)
        assert first is not None and second is not None
        assert first.terminal_evidence and second.terminal_evidence
        key = next(iter(first.terminal_evidence))
        assert first.terminal_evidence[key] is not second.terminal_evidence[key]
        original = second.terminal_evidence[key].proven_target
        object.__setattr__(first.terminal_evidence[key], 'proven_target', 0xdead)
        third = vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact)
        assert third is not None
        assert third.terminal_evidence[key].proven_target == original


def test_rebind_deadline_expiry_refuses_instead_of_facts(monkeypatch):
    """Expiry during the bounded comparison returns no binding."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        expired = False
        capture = source_graph_binding.capture_immutable_source_graph_facts_8616

        def capture_then_expire(*args, **kwargs):
            nonlocal expired
            result = capture(*args, **kwargs)
            expired = True
            return result

        monkeypatch.setattr(
            source_graph_binding, 'capture_immutable_source_graph_facts_8616',
            capture_then_expire)
        monkeypatch.setattr(
            cache, 'direct_evidence_deadline_expired_8616', lambda current: expired)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is None


def test_rebind_deadline_expired_before_work_refuses(monkeypatch):
    """An expired request cannot even authenticate a caller against records."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        monkeypatch.setattr(
            vex_import, 'direct_evidence_deadline_expired_8616', lambda current: True)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is None


def test_rebind_foreign_artifact_same_address_refuses():
    """A foreign graph at the same root address must not read retained facts."""
    project, boundary = _jump_world()
    with cache.native_import_request_8616():
        bundle = vex_import.raw_x86_16_function_bundle_8616(project, boundary)
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
        foreign = IRFunctionArtifact(
            function_addr=bundle.artifact.function_addr,
            blocks=(),
        )
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, foreign) is None
        # The retained record still authenticates the real caller afterwards.
        assert vex_import.raw_x86_16_import_bundle_for_artifact_8616(
            project, boundary, bundle.artifact) is not None
