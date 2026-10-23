"""Raw startup route admission must not replace later call-backed proof."""
import pytest

from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir import real16_invocation_domain as domain
from tests.ir.test_x86_16_boot_entry_link import (
    _recompute,
    _world,
    build_boundary_direct_callsite_index_8616,
    resolve_direct_call_target_from_instruction_8616,
)

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize(('prefix', 'site', 'blocked'), [
    ('e82000', 0x10010, True),
    ('e80000', 0x10010, True),
    ('9a23000010', 0x10010, True),
    ('e82000', 0x10000, False),
    ('cd21e81e00', 0x10010, True),
    ('cd21', 0x10010, False),
    ('7403e81e00', 0x10010, False),
    ('eb0e', 0x10010, False),
])
def test_native_linear_prefix_admission(prefix, site, blocked):
    from inertia.ir.raw_boot_route_admission import RawBootRouteAdmission8616, raw_boot_route_admission_8616
    project, boundary, _, _ = _world(bytes.fromhex(prefix))
    admission = raw_boot_route_admission_8616(project, boundary, site)
    assert (admission is RawBootRouteAdmission8616.ORDINARY_CALL_BARRIER) is blocked


def test_changed_native_bytes_retain_the_attempt():
    from inertia.ir.raw_boot_route_admission import RawBootRouteAdmission8616, raw_boot_route_admission_8616
    project, boundary, _, _ = _world(bytes.fromhex('e82000'))
    project.loader.memory.store(boundary.addr, bytes.fromhex('909090'))
    assert raw_boot_route_admission_8616(project, boundary, 0x10010) is RawBootRouteAdmission8616.RETAIN_ATTEMPT


def test_raw_route_cannot_cross_an_ordinary_call_without_records(monkeypatch):
    project, boundary, _, boot = _world(bytes.fromhex('e82000'))
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction))
    source = owner.Real16InvocationSource8616(boot, _recompute, index)
    monkeypatch.setattr(owner, '_exact_boundary_for_8616', lambda current, head: boundary)

    def forbidden(*args, **kwargs):
        raise AssertionError('raw census cannot cross the preceding ordinary call')

    monkeypatch.setattr(domain, 'real16_native_census_import_8616', forbidden)
    premise = owner._raw_boot_invocation_premise_8616(project, boundary.addr, 0x10010, source)
    assert premise is None
    assert owner._raw_boot_premise_status_8616(
        project, premise, source, boundary.addr, None) is owner._RawBootPremiseStatus8616.RETRY
