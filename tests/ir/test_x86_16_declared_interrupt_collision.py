"""A real FAR CALL must not borrow the synthetic interrupt service identity."""

import tests.ir.test_x86_16_declared_interrupt_boundary as fixture


def test_far_call_to_interrupt_token_is_not_an_interrupt(monkeypatch):
    # mov ah,30h; call far f000:f021 (linear ff021); call next; ret
    caller = bytes.fromhex('b430 9a21f000f0 e80100 c3')
    monkeypatch.setattr(fixture, 'CALLER_CODE', caller)
    monkeypatch.setattr(fixture, 'INT_ADDR', fixture.MODULE_BASE + 2)
    monkeypatch.setattr(fixture, 'CALL_ADDR', fixture.MODULE_BASE + 7)
    monkeypatch.setattr(fixture, 'CALLEE_ADDR', fixture.MODULE_BASE + len(caller))
    env = fixture._environment()
    boot = fixture._boot(env)
    project, _, _, coverage = fixture._world(boot)
    relation = fixture.declared_int21_version_service_8616(
        env, caller_addr=fixture.MODULE_BASE, callsite_addr=fixture.INT_ADDR,
    )
    assert isinstance(relation, fixture.DeclaredInterruptService8616)
    premise = fixture._premise(project, coverage, boot, (relation,))
    assert not premise.complete, 'FAR CALL address collision accepted as INT21'
