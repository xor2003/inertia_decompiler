"""Prove MS C batch orchestration budgets workers from the selected jobs.

Layer: Tooling/gates.
Responsibility: test worker-budget transport and binary job-file policy in the
production command builder. This checks tooling contracts, not recovered
semantics. ``INERTIA_MSC6_BATCH_OWNER`` may select a saved source for an isolated
red regression; routine runs exercise the current production owner.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _repo_root() -> Path:
    """Find the repository root above this regression file."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "scripts" / "msc6_function_targets.py").is_file() and (
            parent / "pyproject.toml"
        ).is_file():
            return parent
    raise RuntimeError(f"cannot locate repository root above {__file__}")


_REPO_ROOT = _repo_root()
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import batch_decompile_procs
from scripts.msc6_function_targets import BinaryFunctionTarget
from scripts.msc6_memory_model import MSCMemoryModel

_OWNER_ENV = "INERTIA_MSC6_BATCH_OWNER"
_DEFAULT_OWNER = _REPO_ROOT / "scripts" / "build_msc6_examples.py"
_OWNER_MODULE_NAME = "inertia_msc6_owner_under_test"
_SIBLING_MODULE_NAME = "inertia_msc6_batch_sibling_under_test"


def _load_module_at(module_name: str, path: Path) -> ModuleType:
    """Load one Python file by absolute path under a private module name."""
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec so dataclass field resolution sees the module.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def _selected_owner_path() -> Path:
    """Resolve which command-builder source this pytest process exercises."""
    override = os.environ.get(_OWNER_ENV)
    path = Path(override) if override else _DEFAULT_OWNER
    path = path.resolve()
    if not path.is_file():
        raise RuntimeError(f"owner under test is not a file: {path}")
    return path


@pytest.fixture(scope="module")
def owner_path() -> Path:
    """Expose the selected owner path for sibling-script checks."""
    return _selected_owner_path()


@pytest.fixture(scope="module")
def owner(owner_path: Path) -> ModuleType:
    """Load the selected owner once per pytest worker process."""
    return _load_module_at(_OWNER_MODULE_NAME, owner_path)


def _options(owner: ModuleType, tmp_path: Path) -> Any:
    """Instantiate the owner's typed decompile options against a scratch dir."""
    exe_path = tmp_path / "TEST.EXE"
    exe_path.write_bytes(b"MZ")
    return owner._FunctionDecompileOptions(
        exe_path=exe_path,
        out_dir=tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        memory_model=MSCMemoryModel.SMALL,
        decompile_c_name="TEST1.C",
    )


def _workers_arg(cmd: list[str]) -> int:
    """Return the integer transported after a single ``--workers`` flag."""
    assert "--workers" in cmd, f"batch command lacks --workers: {cmd}"
    assert cmd.count("--workers") == 1
    return int(cmd[cmd.index("--workers") + 1])


@pytest.mark.parametrize(
    ("selected", "expected_workers"),
    [(1, 1), (3, 3), (4, 4), (8, 4)],
    ids=["one", "three", "four", "over-four"],
)
def test_named_fallback_worker_budget_tracks_selected_jobs(
    owner: ModuleType, tmp_path: Path, selected: int, expected_workers: int
) -> None:
    """Named mode must emit ``--workers`` capped at the typed maximum."""
    cmd = owner._batch_decompile_command(
        _options(owner, tmp_path),
        batch_dir=tmp_path / "named.batch",
        fallback_functions=tuple(f"func_{index}" for index in range(selected)),
        binary_targets=None,
    )
    assert _workers_arg(cmd) == expected_workers
    assert _workers_arg(cmd) == min(owner.MSC6_BATCH_MAX_WORKERS, max(1, selected))


@pytest.mark.parametrize(
    ("target_count", "fallback_count", "expected_workers"),
    [(1, 4, 1), (3, 6, 3), (4, 2, 4), (8, 1, 4), (0, 3, 1)],
    ids=["one", "three", "four", "over-four", "empty-floor"],
)
def test_binary_targets_own_the_worker_budget(
    owner: ModuleType,
    tmp_path: Path,
    target_count: int,
    fallback_count: int,
    expected_workers: int,
) -> None:
    """Binary mode must count selected targets, not the fallback inventory."""
    targets = tuple(
        BinaryFunctionTarget(f"target_{index}", 0x10000 + 0x10 * (index + 1))
        for index in range(target_count)
    )
    fallback_functions = tuple(f"unselected_{index}" for index in range(fallback_count))
    batch_dir = tmp_path / "binary.batch"
    cmd = owner._batch_decompile_command(
        _options(owner, tmp_path),
        batch_dir=batch_dir,
        fallback_functions=fallback_functions,
        binary_targets=targets,
    )
    assert _workers_arg(cmd) == expected_workers
    assert _workers_arg(cmd) == min(owner.MSC6_BATCH_MAX_WORKERS, max(1, target_count))
    assert "--proc" not in cmd
    assert "--proc-kind" not in cmd
    assert cmd.count("--job-file") == 1
    payload = json.loads((batch_dir / "jobs.json").read_text(encoding="utf-8"))
    assert len(payload["jobs"]) == target_count


def test_binary_job_file_keeps_numeric_addresses_and_no_source_hints(
    owner: ModuleType, tmp_path: Path
) -> None:
    """Selected binary jobs keep numeric addresses and refuse source hints."""
    targets = (
        BinaryFunctionTarget("alpha", 0x10010),
        BinaryFunctionTarget("beta", 0x20020),
    )
    batch_dir = tmp_path / "binary.batch"
    cmd = owner._batch_decompile_command(
        _options(owner, tmp_path),
        batch_dir=batch_dir,
        fallback_functions=("alpha", "beta"),
        binary_targets=targets,
    )
    job_file = Path(cmd[cmd.index("--job-file") + 1])
    payload = json.loads(job_file.read_text(encoding="utf-8"))
    raw_jobs = payload["jobs"]
    assert [raw["addr"] for raw in raw_jobs] == [0x10010, 0x20020]
    for raw in raw_jobs:
        assert type(raw["addr"]) is int
        assert raw["binary"] == str(tmp_path / "TEST.EXE")
        assert raw["alternate_source_c"] is False
        assert raw["ignore_local_sidecar_hints"] is True
        assert "proc" not in raw
    decoded = batch_decompile_procs._load_jobs(job_file)
    assert [job.name for job in decoded] == ["alpha", "beta"]
    for job, address in zip(decoded, (0x10010, 0x20020), strict=True):
        assert job.argv[job.argv.index("--addr") + 1] == f"0x{address:x}"
        assert "--no-alternate-source-c" in job.argv
        assert "--ignore-local-sidecar-hints" in job.argv
        assert "--proc" not in job.argv


def test_named_mode_transports_proc_names_and_memory_model(
    owner: ModuleType, tmp_path: Path
) -> None:
    """Named mode selects procs explicitly and writes no job file."""
    batch_dir = tmp_path / "named.batch"
    cmd = owner._batch_decompile_command(
        _options(owner, tmp_path),
        batch_dir=batch_dir,
        fallback_functions=("first", "second"),
        binary_targets=None,
    )
    assert "--job-file" not in cmd
    assert not (batch_dir / "jobs.json").exists()
    proc_positions = [index for index, token in enumerate(cmd) if token == "--proc"]
    assert [cmd[index + 1] for index in proc_positions] == ["first", "second"]
    assert cmd[cmd.index("--proc-kind") + 1] == MSCMemoryModel.SMALL.default_procedure_kind


def test_generic_batch_script_keeps_single_worker_default(
    owner_path: Path, tmp_path: Path
) -> None:
    """The sibling generic batch entrypoint still defaults to one worker."""
    sibling_path = owner_path.parent / "batch_decompile_procs.py"
    assert sibling_path.is_file(), f"missing sibling batch script: {sibling_path}"
    sibling = _load_module_at(_SIBLING_MODULE_NAME, sibling_path)
    args = sibling._parse_args(["--out-dir", str(tmp_path / "out")])
    assert args.workers == 1
