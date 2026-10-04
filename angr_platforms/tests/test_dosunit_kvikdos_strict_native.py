"""Native KVM controls for unsupported DOS service rejection."""
from pathlib import Path

import pytest

from tools.dosunit import kvikdos_backend as backend


@pytest.mark.requires_kvm
@pytest.mark.skipif(not Path("/home/xor/kvikdos/kvikdos").exists(), reason="kvikdos required")
@pytest.mark.parametrize("program,expected_error", [
    ("b8004ccd21", None),
    ("cdf0b8004ccd21", "unsupported int 0xf0"),
    ("b8074ccd21", "status 7"),
])
def test_native_cli_preserves_supported_exit_and_rejects_unknown_service(
    tmp_path: Path, program: str, expected_error: str | None,
) -> None:
    """An unknown interrupt cannot become success before a supported DOS exit."""
    guest, dump = tmp_path / "guest.com", tmp_path / "dump"
    guest.write_bytes(bytes.fromhex(program))
    if expected_error is not None:
        with pytest.raises(backend.KvikdosBackendError, match=expected_error):
            backend._run_with_kvikdos_cli(guest, dump, kvikdos_path=None)
    else:
        assert backend._run_with_kvikdos_cli(guest, dump, kvikdos_path=None) == 0
        assert dump.is_file()
