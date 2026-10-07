"""Flag-elision lookahead must stop where sequential execution is unproved."""

import pickle
from pathlib import Path

import pytest

from inertia.semantics.status_flag_liveness import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    DecodedStatusFlagInstruction8616,
    decide_status_flag_liveness_8616,
)


@pytest.mark.parametrize("mnemonic", ["jcxz", "jecxz", "jmp", "loop", "ret", "retf", "call", "int"])
def test_later_overwrite_beyond_transfer_cannot_kill_flags(mnemonic: str) -> None:
    """The skipped successor may observe flags before the later DEC executes."""
    decision = decide_status_flag_liveness_8616(
        INCDEC_STATUS_FLAG_WRITES_8616,
        (DecodedStatusFlagInstruction8616(mnemonic), DecodedStatusFlagInstruction8616("dec")),
    )
    assert not decision.suppresses_write
    assert decision.stats.closed


def test_unrolled_loop_first_step_preserves_flags_at_odd_exit() -> None:
    """Real instruction bytes retain the DEC FLAGS before JCXZ can return."""
    import pyvex
    from inertia.frontend.x86_16.arch_86_16 import Arch86_16
    from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

    arch = Arch86_16()
    code = bytes.fromhex("8d5f0149e3068d5f0149ebf2c3")
    block = pyvex.lift(code, 0x1202, arch, opt_level=0)
    flags_offset = arch.get_register_offset("flags")
    assert any(stmt.tag == "Ist_Put" and stmt.offset == flags_offset for stmt in block.statements)


def test_cached_lifts_from_before_flag_boundary_fix_are_rejected(tmp_path: Path) -> None:
    """A cached IRSB with elided live flags must be lifted again."""
    from tools.dosunit.compare import straightline_ssa as ssa

    digest = "flag-boundary-cache-regression"
    path = ssa._vex_cache_file(cache_dir=tmp_path, exe_digest=digest)
    path.parent.mkdir(parents=True)
    path.write_bytes(pickle.dumps({
        "schema": "dosunit.lifter_cache.v5",
        "flavor": "vex",
        "exe_sha256": digest,
        "entries": {"old-block": {"omitted_live_flags": True}},
    }))
    loaded = ssa._load_vex_cache(cache_dir=tmp_path, exe_digest=digest)
    assert loaded["schema"] != "dosunit.lifter_cache.v5"
    assert loaded["entries"] == {}
