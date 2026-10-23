"""Fresh declared construction acquires the same owner guard before its body."""
import time
from dataclasses import replace

import pytest

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.ir import real16_invocation_domain as owner
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tests.ir.test_real16_prefix_capture_core import high_capture_advice as high_capture_advice


@pytest.fixture
def world() -> tuple:
    """Build the existing authentic declared-entry fixture."""
    apply_x86_16_bootstrap()
    return _world()


def test_canonical_factory_enrolls_source_bound_prefix_only_in_current_traversal(world):
    """Actual byte-backed capture is private and dies with its proof traversal."""
    project, boot, link = world
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        domain = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute,
        )
        assert domain is not None
        capture = traversal.invocation_prefixes[id(domain)]
        assert capture.context.prefix_sources.complete
        assert capture.artifact is link.artifact
        assert capture.boundary is link.boundary
        assert capture.context.prefix_terminal_call.instruction.addr == domain.callsite_addr
        assert traversal.retained_domains[id(domain)] is domain
        assert traversal.domain_verdicts[id(domain)] is True
    with segment_call_dependency_traversal_scope_8616() as other:
        assert not other.invocation_prefixes


def test_uncached_factory_preserves_success_without_enrolling_prefix(world):
    """Absent native session authority cannot turn data into a reusable record."""
    project, boot, link = world
    with segment_call_dependency_traversal_scope_8616() as traversal:
        domain = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute,
        )
        assert domain is not None and domain.failure is None
        assert traversal.domain_verdicts[id(domain)]
        assert not traversal.invocation_prefixes


def test_unadmitted_capture_cannot_enroll_domain(world):
    """A valid derivation alone cannot allocate an unguarded prefix record."""
    project, boot, link = world
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        domain, derived = owner._derive_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute, prefix_capture=True,
        )
        assert derived.prefix_census is not None
        assert derived.prefix_census.context.prefix_sources.complete
        owner._enroll_prefix_census_data_8616(domain, derived)
        assert not traversal.invocation_prefixes
        traversal.retained_domains[id(domain)] = domain
        traversal.domain_verdicts[id(domain)] = False
        owner._enroll_prefix_census_data_8616(domain, derived)
        assert not traversal.invocation_prefixes


@pytest.mark.parametrize("changed", ["source", "project", "root", "callsite"])
def test_incomplete_or_mismatched_capture_cannot_replace_retained_data(world, changed):
    """Malformed optional data cannot overwrite the guarded canonical capture."""
    project, boot, link = world
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        target = owner._DeclaredInvocationConstruction8616(project, link, 0x1023, boot, _recompute)
        domain, derived = owner._construct_declared_invocation_domain_8616(target)
        original = traversal.invocation_prefixes.pop(id(domain))
        if changed == "source":
            original.context.prefix_sources.complete = False
        elif changed == "project":
            derived = replace(derived, prefix_census=replace(original, context=replace(original.context, project=object())))
        elif changed == "root":
            derived = replace(derived, prefix_census=replace(original, artifact=replace(original.artifact)))
        else:
            derived = replace(derived, prefix_census=replace(original, context=replace(original.context, callsite_addr=0x1040)))
        owner._enroll_prefix_census_data_8616(domain, derived)
        assert not traversal.invocation_prefixes


@pytest.mark.parametrize("changed", ["artifact", "coordinate", "index", "instruction"])
def test_forged_terminal_metadata_cannot_enroll_same_address(world, changed):
    project, boot, link = world
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        target = owner._DeclaredInvocationConstruction8616(project, link, 0x1023, boot, _recompute)
        domain, derived = owner._construct_declared_invocation_domain_8616(target)
        data = traversal.invocation_prefixes.pop(id(domain))
        terminal = data.context.prefix_terminal_call
        if changed == "artifact":
            forged = replace(terminal, artifact=replace(terminal.artifact))
        elif changed == "coordinate":
            forged = replace(terminal, block=replace(terminal.block, addr=0x1040))
        elif changed == "index":
            forged = replace(terminal, index=-1)
        else:
            forged = replace(terminal, instruction=replace(terminal.instruction, op="RET"))
        ctx = replace(data.context, prefix_terminal_call=forged)
        owner._enroll_prefix_census_data_8616(domain, replace(derived, prefix_census=replace(data, context=ctx)))
        assert not traversal.invocation_prefixes


@pytest.mark.parametrize("exceptional", [False, True])
def test_failed_forced_verifier_discards_prefix_data(world, exceptional):
    """A refused or exceptional replay cannot leave earlier prefix data usable."""
    project, boot, link = world
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        domain = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute,
        )
        assert id(domain) in traversal.invocation_prefixes

        def refused():
            if exceptional:
                raise ValueError("forced verifier failed")
            return False

        if exceptional:
            with pytest.raises(ValueError):
                domain._consume_completion_8616(refused, force_current=True)
        else:
            assert not domain._consume_completion_8616(refused, force_current=True)
        assert not traversal.active_domains
        assert not traversal.invocation_prefixes


def test_failed_peer_projection_discards_provisional_offered_capture(world):
    """Inner success cannot retain data when the paired peer later refuses."""
    project, boot, link = world
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616() as traversal:
        offered = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute,
        )
        assert id(offered) in traversal.invocation_prefixes
        required = replace(offered, maximum_selector=offered.maximum_selector - 1)
        assert not owner._complete_shared_replay_8616(offered, required)
        assert not traversal.invocation_prefixes
        assert traversal.domain_verdicts[id(offered)] is False
        assert traversal.domain_verdicts[id(required)] is False



@pytest.mark.parametrize('exhausted', ['domains', 'work', 'depth'])
def test_fresh_public_factory_does_not_enter_body_without_admission(world: tuple, monkeypatch: pytest.MonkeyPatch, exhausted: str) -> None:
    """Fresh public factory does not enter body without admission."""
    project, boot, link = world
    calls = []
    original = owner._derive_declared_function_entry_domain_8616
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, '_derive_declared_function_entry_domain_8616', counted)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if exhausted == 'domains':
            traversal.remaining_domains = 0
        elif exhausted == 'work':
            traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616 + 1
        else:
            traversal.active_domains.update(range(owner._CHAIN_DEPTH_LIMIT_8616))
        result = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute)
    assert result is None
    assert calls == []



def test_same_construction_token_cannot_reenter_body(world: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Same construction token cannot reenter body."""
    project, boot, link = world
    target = owner._DeclaredInvocationConstruction8616(project, link, 0x1023, boot, _recompute)
    original = owner._derive_declared_function_entry_domain_8616
    calls = []
    nested = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        nested.append(owner._construct_declared_invocation_domain_8616(target))
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, '_derive_declared_function_entry_domain_8616', counted)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        before = traversal.remaining_domains
        result = owner._construct_declared_invocation_domain_8616(target)
        assert traversal.remaining_domains == before - 1
        assert not traversal.active_domains
        assert result is not None
        domain, derived = result
        assert owner._replayed_domain_equal_8616(derived, domain)
        assert domain.complete
    assert calls == [1]
    assert nested == [None]



@pytest.mark.parametrize('rebuild', [False, True])
def test_same_public_factory_coordinates_cannot_reenter(world: tuple, monkeypatch: pytest.MonkeyPatch, rebuild: bool) -> None:
    """Same public factory coordinates cannot reenter."""
    from dataclasses import replace
    project, boot, link = world
    original = owner._derive_declared_function_entry_domain_8616
    calls = []
    nested = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        if len(calls) == 1:
            other_link = replace(link, artifact=replace(link.artifact), boundary=replace(link.boundary)) if rebuild else link
            other_boot = replace(boot) if rebuild else boot
            nested.append(owner.prove_fresh_real16_declared_function_entry_domain_8616(
                project, other_link, 0x1023, boot=other_boot, boot_recompute=_recompute))
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, '_derive_declared_function_entry_domain_8616', counted)
    with segment_call_dependency_traversal_scope_8616():
        result = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute)
    assert result is not None
    assert calls == [1]
    assert nested == [None]



def test_exact_work_limit_still_admits_zero_charge_verifier(world: tuple) -> None:
    """Exact work limit still admits zero charge verifier."""
    project, boot, link = world
    target = owner._DeclaredInvocationConstruction8616(project, link, 0x1023, boot, _recompute)
    calls = []
    def verify() -> bool:
        calls.append(1)
        return True
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units = owner._CENSUS_WORK_LIMIT_8616
        assert owner._consume_invocation_admission_8616(target, verify)
        assert traversal.census_work_units == owner._CENSUS_WORK_LIMIT_8616
        assert not traversal.active_domains
        assert not traversal.domain_verdicts
    assert calls == [1]



def test_fresh_factory_outside_traversal_later_public_complete_replays(world: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh factory outside traversal later public complete replays."""
    project, boot, link = world
    original = owner._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, '_derive_invocation_domain_8616', counted)
    domain = owner.prove_fresh_real16_declared_function_entry_domain_8616(
        project, link, 0x1023, boot=boot, boot_recompute=_recompute)
    assert domain is not None
    assert calls == [1]
    assert domain.complete
    assert calls == [1, 1]



def test_fresh_factory_current_traversal_reuses_only_existing_public_verdict(world: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh factory current traversal reuses only existing public verdict."""
    project, boot, link = world
    original = owner._derive_invocation_domain_8616
    calls = []
    def counted(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, '_derive_invocation_domain_8616', counted)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        domain = owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute)
        assert domain is not None
        assert traversal.retained_domains[id(domain)] is domain
        assert traversal.domain_verdicts[id(domain)]
        assert domain.complete
        assert calls == [1]
    assert domain.complete
    assert calls == [1, 1]



def test_construction_subclass_cannot_enroll_positive_proof_memo(world: tuple) -> None:
    """Construction subclass cannot enroll positive proof memo."""
    class Construction(owner._DeclaredInvocationConstruction8616):
        """Exercise private typed subclasses without proof authority."""
    project, boot, link = world
    target = Construction(project, link, 0x1023, boot, _recompute)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert owner._consume_invocation_admission_8616(target, lambda: True)
        assert not traversal.active_domains
        assert not traversal.retained_domains
        assert not traversal.domain_verdicts



def _mint(world: tuple[object, object, owner.DeclaredFunctionEntryLink8616]) -> owner.Real16InvocationDomain8616:
    project, boot, link = world
    domain = owner.prove_fresh_real16_declared_function_entry_domain_8616(
        project, link, 0x1023, boot=boot, boot_recompute=_recompute)
    assert domain is not None and domain.failure is None
    return domain



def test_specific_exception_propagates_and_clears_pending_key(world: tuple[object, object, owner.DeclaredFunctionEntryLink8616],
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    """A body exception cannot leave active construction or cached evidence."""
    project, boot, link = world

    def failed(*args: object, **kwargs: object) -> tuple[owner.Real16InvocationDomain8616, owner._Derivation8616]:
        raise ValueError('construction body failure')

    monkeypatch.setattr(owner, '_derive_declared_function_entry_domain_8616', failed)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        before = traversal.remaining_domains
        with pytest.raises(ValueError) as caught:
            owner.prove_fresh_real16_declared_function_entry_domain_8616(
                project, link, 0x1023, boot=boot, boot_recompute=_recompute)
        assert caught.value.args == ('construction body failure',)
        assert not traversal.active_domains
        assert not traversal.domain_verdicts
        assert not traversal.retained_domains
        assert traversal.remaining_domains == before - 1



def test_expired_traversal_never_enters_construction_body(world: tuple[object, object, owner.DeclaredFunctionEntryLink8616],
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """An existing expired shared deadline refuses before any body execution."""
    project, boot, link = world
    calls = []

    def forbidden(*args: object, **kwargs: object) -> tuple[owner.Real16InvocationDomain8616, owner._Derivation8616]:
        calls.append(1)
        raise AssertionError('body entered after deadline')

    monkeypatch.setattr(owner, '_derive_declared_function_entry_domain_8616', forbidden)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = time.monotonic() - 1
        before = traversal.remaining_domains
        assert owner.prove_fresh_real16_declared_function_entry_domain_8616(
            project, link, 0x1023, boot=boot, boot_recompute=_recompute) is None
        assert not traversal.active_domains and not traversal.domain_verdicts
        assert traversal.remaining_domains == before
    assert not calls



@pytest.mark.parametrize('force_current', [False, True])
def test_cached_false_never_reenters_verifier(world: tuple[object, object, owner.DeclaredFunctionEntryLink8616],
                                            force_current: bool) -> None:
    """Ordinary and forced consumption preserve the current false memo."""
    domain = _mint(world)
    calls = []

    def verify() -> bool:
        calls.append(1)
        return True

    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.domain_verdicts[id(domain)] = False
        traversal.retained_domains[id(domain)] = domain
        before = traversal.remaining_domains
        assert not owner._consume_invocation_admission_8616(domain, verify, force_current=force_current)
        assert not calls and not traversal.active_domains
        assert traversal.domain_verdicts[id(domain)] is False
        assert traversal.remaining_domains == before



@pytest.mark.parametrize('depth_exhausted', [False, True])
def test_cached_true_forced_uses_current_active_and_depth_guard(world: tuple[object, object, owner.DeclaredFunctionEntryLink8616],
                                                              depth_exhausted: bool) -> None:
    """A true memo cannot bypass current replay's active/depth admission."""
    domain = _mint(world)
    calls = []
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.domain_verdicts[id(domain)] = True
        traversal.retained_domains[id(domain)] = domain
        before = traversal.remaining_domains
        if depth_exhausted:
            traversal.active_domains.update(range(owner._CHAIN_DEPTH_LIMIT_8616))
        original_active = set(traversal.active_domains)

        def verify() -> bool:
            calls.append(1)
            assert id(domain) in traversal.active_domains
            assert not owner._consume_invocation_admission_8616(domain, verify, force_current=True)
            return True

        assert owner._consume_invocation_admission_8616(domain, verify, force_current=True) is (not depth_exhausted)
        assert calls == ([] if depth_exhausted else [1])
        assert traversal.active_domains == original_active
        assert traversal.remaining_domains == before
