"""Parent controls for typed failures at process and memory protocol edges."""

from pathlib import Path

import pytest

import tools.dosunit.runtime.kvikdos_backend as backend
import tools.dosunit.runtime.kvikdos_vm_worker as vmw


def test_missing_worker_command_has_typed_cause(tmp_path: Path) -> None:
    """A spawn failure must retain its OS cause inside the backend boundary."""
    with pytest.raises(vmw.KvikdosWorkerError) as error:
        vmw.KvikdosVmClient.spawn(
            lib_path=tmp_path / 'unused.so', command_prefix=[str(tmp_path / 'absent')],
        )
    assert isinstance(error.value.__cause__, OSError)


@pytest.mark.parametrize('data', ['zz', '', '0001'])
def test_bad_memory_reply_is_typed_backend_error(data: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid hex or wrong byte count must not become a usable observation."""
    session = backend.KvikdosSession()
    monkeypatch.setattr(session, '_call_status', lambda *args, **kwargs: {'status': 0, 'data': data})
    with pytest.raises(backend.KvikdosBackendError):
        session.read_memory(0, 1)
