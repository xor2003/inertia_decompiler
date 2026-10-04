"""Parent controls for native memory ranges before ctypes conversion."""

import ctypes

import pytest

from tools.dosunit import kvikdos_vm_worker as vmw


@pytest.mark.parametrize("op", ["read_memory", "write_memory"])
@pytest.mark.parametrize("linear,size", [(-1, 1), (2**32, 1), (0xA0000, 1), (0x9FFFF, 2)])
def test_invalid_guest_range_rejected_before_native_call(op: str, linear: int, size: int) -> None:
    """Invalid ranges cannot reach the API whose addresses narrow to uint32."""
    calls = []

    def native_call(*args: object) -> int:
        calls.append(args)
        return 0

    api = vmw._VmApi(
        create=lambda *args: 0, destroy=lambda *args: None,
        run_program=lambda *args: 0, snap_create=lambda *args: 0,
        snap_restore=lambda *args: 0, snap_destroy=lambda *args: None,
        read_memory=native_call, write_memory=native_call,
    )
    state = vmw._ChildVmState(vm=ctypes.c_void_p(1), api=api)
    operation = {"op": op, "linear": linear, "size": size, "data": "01" * size}
    with pytest.raises(ValueError):
        vmw._child_dispatch(operation, state=state)
    assert not calls


@pytest.mark.parametrize("op", ["read_memory", "write_memory"])
@pytest.mark.parametrize("linear,size", [(0, 1), (0x9FFFF, 1), (0xA0000, 0)])
def test_valid_guest_boundary_keeps_native_operation(op: str, linear: int, size: int) -> None:
    """Keep the native half-open range and empty end-of-memory operation."""
    calls = []

    def native_call(*args: object) -> int:
        calls.append(args)
        return 0

    api = vmw._VmApi(
        create=lambda *args: 0, destroy=lambda *args: None,
        run_program=lambda *args: 0, snap_create=lambda *args: 0,
        snap_restore=lambda *args: 0, snap_destroy=lambda *args: None,
        read_memory=native_call, write_memory=native_call,
    )
    state = vmw._ChildVmState(vm=ctypes.c_void_p(1), api=api)
    operation = {"op": op, "linear": linear, "size": size, "data": "01" * size}
    assert vmw._child_dispatch(operation, state=state)["status"] == 0
    assert len(calls) == 1
