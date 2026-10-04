"""Exercise the actual child registry before native snapshot API calls."""

import ctypes
from typing import Any

from tools.dosunit import kvikdos_vm_worker as vmw


def test_snapshot_tokens_never_forward_unowned_native_pointers() -> None:
    """Only a live minted token can restore/free its corresponding pointer."""
    calls: list[tuple[str, int | None]] = []

    def create_snapshot(_vm: object, output: Any) -> int:
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(0x1234)
        return 0

    def restore_snapshot(_vm: object, pointer: ctypes.c_void_p) -> int:
        calls.append(('restore', pointer.value))
        return 0

    def destroy_snapshot(pointer: ctypes.c_void_p) -> None:
        calls.append(('destroy', pointer.value))

    api = vmw._VmApi(
        create=lambda *args: 0, destroy=lambda *args: None,
        run_program=lambda *args: 0, snap_create=create_snapshot,
        snap_restore=restore_snapshot, snap_destroy=destroy_snapshot,
        read_memory=lambda *args: 0, write_memory=lambda *args: 0,
    )
    state = vmw._ChildVmState(vm=ctypes.c_void_p(1), api=api)
    token = vmw._child_dispatch({'op': 'snapshot_create'}, state=state)['handle']
    assert token != 0x1234
    assert vmw._child_dispatch({'op': 'snapshot_restore', 'handle': token}, state=state)['status'] == 0
    assert vmw._child_dispatch({'op': 'snapshot_destroy', 'handle': token}, state=state)['status'] == 0
    assert calls == [('restore', 0x1234), ('destroy', 0x1234)]
    for handle in (token, 0x1234, 0xDEADBEEF):
        for op in ('snapshot_restore', 'snapshot_destroy'):
            assert vmw._child_dispatch({'op': op, 'handle': handle}, state=state)['status'] != 0
    assert calls == [('restore', 0x1234), ('destroy', 0x1234)]
