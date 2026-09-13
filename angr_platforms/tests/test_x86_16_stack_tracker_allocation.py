"""Keep native stack tracking coherent with binary-proven call allocation."""

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.compiler_helpers import hook_x86_16_compiler_helper_at_8616
from test_x86_16_call_stack_allocation_proof import PROBE

_ENTRY = 0x1000
_HELPER = 0x1020
_AFTER_CALL = 0x1009


def _track(prefix, helper=PROBE):
    displacement = _HELPER - (_ENTRY + len(prefix) + 3)
    code = prefix + b"\xe8" + displacement.to_bytes(2, "little")
    after_call = _ENTRY + len(code)
    code += bytes.fromhex("57 5f 8b e5 5d c3")
    code = code.ljust(_HELPER - _ENTRY, b"\x90") + helper
    project = angr.load_shellcode(code, arch=Arch86_16(), load_address=_ENTRY)
    hook_x86_16_compiler_helper_at_8616(project, _HELPER)
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[_ENTRY])
    function = cfg.kb.functions[_ENTRY]
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    return tracker.offset_before(after_call, project.arch.sp_offset)


@pytest.mark.parametrize("allocation", [0, 2, 18])
def test_native_tracker_consumes_proven_allocation_before_following_pushes(allocation):
    # PUSH BP; MOV BP,SP; MOV AX,n; CALL helper; PUSH/POP DI; restore BP; RET.
    prefix = bytes.fromhex("55 8b ec b8") + allocation.to_bytes(2, "little")

    # angr's stack-offset domain uses the register width, including ESP's
    # preserved upper word. Compare its exact modular representation.
    expected = (-2 - allocation) & 0xffffffff
    assert _track(prefix) == expected


@pytest.mark.parametrize("clobber", ["b0 04", "b4 00", "8b c2", "66 b8 02 00 00 00"])
def test_native_tracker_refuses_an_unproven_allocation_operand(clobber):
    prefix = bytes.fromhex("55 8b ec b8 02 00 " + clobber)
    assert _track(prefix) is None


def test_ordinary_call_does_not_allocate_the_ax_value():
    expected = (-2) & 0xffffffff
    assert _track(bytes.fromhex("55 8b ec b8 12 00"), helper=b"\xc3") == expected
