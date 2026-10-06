"""Bounded Unicorn TCG arena: child-limit pressure regression and refusals.

Layer: tests.
Responsibility: prove engines built through tools.dosunit.unicorn_engine keep
identical guest observables in both modes under an explicit child-only
address-space limit where the raw default arena cannot initialize, and that
the factory's refusal paths keep typed causes.
"""
from __future__ import annotations

import os
import resource
import subprocess
import sys
from pathlib import Path

import pytest
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, UC_MODE_32
from unicorn.unicorn_py3.unicorn import UcError
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_CS,
    UC_X86_REG_EAX,
    UC_X86_REG_EIP,
    UC_X86_REG_IP,
)

from tools.dosunit import unicorn_engine
from tools.dosunit.unicorn_engine import EngineArenaRefusal, make_guest

# The child process gets its own address-space ceiling, then reserves
# anonymous PROT_NONE-equivalent spans until under _PRESSURE_HEADROOM_BYTES
# remains — less than libunicorn's ~1 GiB default TCG arena, measured on this
# binding as a +1,050,532 KiB VmSize reservation at the first engine op.
_CHILD_ADDRESS_SPACE_BYTES = 2 << 30
_PRESSURE_HEADROOM_BYTES = 900 << 20
_PRESSURE_TIMEOUT_SECONDS = 120
_BOUND_BYTES = 16 << 20

# Self-contained child: lowers ONLY its own soft RLIMIT_AS (never raises it),
# prefills address space, then builds the guest either raw (red control) or
# through the real factory, and prints guest observables.
_PRESSURE_CHILD_PROGRAM = """
import mmap
import resource
import sys

policy, mode_name = sys.argv[1], sys.argv[2]
cap, headroom, bound = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])


def vsz():
    with open("/proc/self/status") as status:
        for line in status:
            if line.startswith("VmSize:"):
                return int(line.split()[1]) * 1024
    return 0


soft, hard = resource.getrlimit(resource.RLIMIT_AS)
if soft == resource.RLIM_INFINITY or soft > cap:
    resource.setrlimit(resource.RLIMIT_AS, (cap, hard))
limit = resource.getrlimit(resource.RLIMIT_AS)[0]

pads = []
while limit - vsz() > headroom:
    try:
        pads.append(mmap.mmap(-1, 128 << 20, prot=mmap.PROT_READ))
    except OSError:
        break
print(f"child limit={limit} vsz={vsz()} headroom={limit - vsz()}", flush=True)

from unicorn import UC_ARCH_X86, UC_MODE_16, UC_MODE_32, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_CS,
    UC_X86_REG_EAX,
    UC_X86_REG_EIP,
    UC_X86_REG_IP,
)

uc_mode = UC_MODE_16 if mode_name == "16" else UC_MODE_32
if policy == "bounded":
    from tools.dosunit.unicorn_engine import make_guest

    guest = make_guest(UC_ARCH_X86, uc_mode, tcg_buffer_bytes=bound)
else:
    guest = Uc(UC_ARCH_X86, uc_mode)
guest.mem_map(0, 0x110000)
if mode_name == "16":
    guest.mem_write(0x1200, bytes.fromhex("b8341240"))
    guest.reg_write(UC_X86_REG_CS, 0x120)
    guest.reg_write(UC_X86_REG_IP, 0)
    guest.emu_start(0x1200, 0, count=2)
    out = int(guest.reg_read(UC_X86_REG_AX))
    assert out == 0x1235
    assert int(guest.reg_read(UC_X86_REG_IP)) == 4
else:
    guest.mem_write(0x40000, bytes.fromhex("b87856341240"))
    guest.reg_write(UC_X86_REG_EIP, 0x40000)
    guest.emu_start(0x40000, 0, count=2)
    out = int(guest.reg_read(UC_X86_REG_EAX))
    assert out == 0x12345679
    assert int(guest.reg_read(UC_X86_REG_EIP)) == 0x40006
print(f"observed mode={mode_name} out={out:#x}", flush=True)
print("PASS", flush=True)
"""


def _child_env() -> dict[str, str]:
    """Child environment: import root for tools plus inherited variables."""
    env = dict(os.environ)
    tools_parent = str(Path(unicorn_engine.__file__).resolve().parents[2])
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = tools_parent + (os.pathsep + inherited if inherited else "")
    return env


@pytest.mark.parametrize("mode", (16, 32))
def test_bounded_guest_preserves_guest_observables(mode: int) -> None:
    """A bounded engine executes the same single-step shape as the existing
    native-coordinate tests and returns identical architectural effects."""
    guest = make_guest(UC_ARCH_X86, UC_MODE_16 if mode == 16 else UC_MODE_32)
    guest.mem_map(0, 0x110000)
    if mode == 16:
        code = bytes.fromhex("b83412" "40")  # mov ax,0x1234 ; inc ax
        head, ip_reg, out_reg = 0x1200, UC_X86_REG_IP, UC_X86_REG_AX
        expect_out, expect_ip = 0x1235, 4
        guest.mem_write(head, code)
        guest.reg_write(UC_X86_REG_CS, head >> 4)
        guest.reg_write(UC_X86_REG_IP, 0)
    else:
        code = bytes.fromhex("b878563412" "40")  # mov eax,0x12345678 ; inc eax
        head, ip_reg, out_reg = 0x40000, UC_X86_REG_EIP, UC_X86_REG_EAX
        expect_out, expect_ip = 0x12345679, head + 6
        guest.mem_write(head, code)
        guest.reg_write(UC_X86_REG_EIP, head)
    visited: list[int] = []
    guest.hook_add(UC_HOOK_CODE, lambda _g, addr, _s, _d: visited.append(addr))
    guest.emu_start(head, 0, count=2)
    assert visited == [head, head + (3 if mode == 16 else 5)]
    assert int(guest.reg_read(out_reg)) == expect_out
    assert int(guest.reg_read(ip_reg)) == expect_ip


@pytest.mark.parametrize("mode", (16, 32))
def test_child_address_space_pressure_kills_default_arena_but_bounded_guest_completes(
    mode: int,
) -> None:
    """Under a child-only address-space cap the raw default arena dies natively
    while the factory-built bounded guest completes with correct observables."""
    assert hasattr(resource, "RLIMIT_AS"), "platform lacks RLIMIT_AS"

    def run(policy: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, "-c", _PRESSURE_CHILD_PROGRAM,
                policy, str(mode),
                str(_CHILD_ADDRESS_SPACE_BYTES),
                str(_PRESSURE_HEADROOM_BYTES),
                str(_BOUND_BYTES),
            ],
            capture_output=True,
            text=True,
            env=_child_env(),
            cwd=str(Path(unicorn_engine.__file__).resolve().parents[2]),
            timeout=_PRESSURE_TIMEOUT_SECONDS,
        )

    default = run("default")
    assert default.returncode != 0
    assert "Could not allocate dynamic translator buffer" in default.stdout + default.stderr
    bounded = run("bounded")
    assert bounded.returncode == 0, bounded.stdout + bounded.stderr
    expected = 0x1235 if mode == 16 else 0x12345679
    assert f"observed mode={mode} out={expected:#x}" in bounded.stdout
    assert "PASS" in bounded.stdout


class _CtlStub:
    """Minimal ctl-surface double for refusal-boundary checks (not a guest)."""

    def __init__(self, *, reported: int | None = None, error: UcError | None = None) -> None:
        self.reported = reported
        self.error = error
        self.requested = 0

    def ctl_set_tcg_buffer_size(self, size: int) -> None:
        if self.error is not None:
            raise self.error
        self.requested = size

    def ctl_get_tcg_buffer_size(self) -> int:
        return self.reported if self.reported is not None else self.requested


def test_missing_ctl_surface_is_a_typed_refusal() -> None:
    """A binding without the ctl surface refuses rather than guessing."""
    with pytest.raises(EngineArenaRefusal, match="lacks TCG buffer-size controls"):
        unicorn_engine._apply_arena_bound(object(), _BOUND_BYTES)


def test_rejected_arena_write_refuses_with_cause() -> None:
    """A rejected ctl write keeps the backend error as the refusal cause."""
    original = UcError(65)
    with pytest.raises(EngineArenaRefusal, match="rejected TCG buffer bound") as held:
        unicorn_engine._apply_arena_bound(_CtlStub(error=original), _BOUND_BYTES)
    assert held.value.__cause__ is original


def test_effective_size_above_bound_refuses() -> None:
    """A binding reporting an adjusted arena above the bound is refused."""
    with pytest.raises(EngineArenaRefusal, match="above bound"):
        unicorn_engine._apply_arena_bound(_CtlStub(reported=_BOUND_BYTES * 4), _BOUND_BYTES)


def test_nonpositive_bound_refuses_before_construction() -> None:
    """A zero bound is a typed refusal; no engine is constructed."""
    with pytest.raises(EngineArenaRefusal, match="must be positive"):
        make_guest(UC_ARCH_X86, UC_MODE_16, tcg_buffer_bytes=0)
