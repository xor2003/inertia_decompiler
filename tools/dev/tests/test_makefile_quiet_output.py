from __future__ import annotations

import os
import shlex
import subprocess
import sys
from collections import Counter
from itertools import pairwise
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(("owner", "test"), (
    ("tools/dosunit/ssa/vex_cache_identity.py", "tools/dosunit/tests/test_dosunit_vex_cache_identity.py"),
    ("tools/dosunit/ssa/ssa_selection.py", "tools/dosunit/tests/test_real16_selected_lowering.py"),
    ("tools/dosunit/catalog/binary_callee_control_target.py", "tools/dosunit/tests/test_binary_callee_control_target.py"),
    ("tools/dosunit/compare/flat32_loop_calls.py", "tools/dosunit/tests/test_flat32_loop_calls.py"),
))
def test_scoped_cache_linters_select_the_promoted_owner(owner: str, test: str) -> None:
    """Late inventory additions must not silently disappear from scoped checks."""
    result = subprocess.run(
        ["make", "-n", "ruff-files", "mypy-files", "pyright-files",
         f"PYTHON={sys.executable}", f"FILES={owner} {test}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    lines = result.stdout.replace("\\\n", " ").splitlines()

    def arguments(line: str) -> list[str]:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)

    for tool in ("ruff", "mypy", "pyright"):
        recipes = [line for line in lines if f"-m {tool} " in line]
        assert recipes and any(owner in arguments(line) for line in recipes), result.stdout
    ruff = next(line for line in lines if "-m ruff " in line)
    assert test in arguments(ruff)


def test_comparator_admission_includes_freshness_and_public_accounting() -> None:
    """Run source-integrity and status controls before spending time on the broad suite."""
    result = subprocess.run(
        ["make", "-n", "comparator-check-fast", f"PYTHON={sys.executable}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    arguments = shlex.split(result.stdout)
    uncatalogued_leaf = "tools/dosunit/tests/test_real16_uncatalogued_calls.py::test_public_uncatalogued_direct_leaf"
    required = {
        uncatalogued_leaf,
        "tools/dosunit/tests/test_flat32_loop_calls.py",
        "tools/dosunit/tests/test_flat32_loop_calls_public.py",
        "tools/dosunit/tests/test_replay_capture_vectors.py",
        "tools/dosunit/tests/test_binary_callee_control_target.py",
        "tools/dosunit/tests/test_dosunit_ssa_source_identity_paths.py",
        "tools/dosunit/tests/test_real16_self_lowering_reuse.py",
        "tools/dosunit/tests/test_real16_public_accounting.py",
        "tools/dosunit/tests/test_real16_selected_lowering.py",
        "tools/dosunit/tests/test_flat32_proof_seal.py",
        "tools/dosunit/tests/test_dosunit_vex_cache_identity.py",
        "tools/dosunit/tests/test_dosunit_transitive_callees.py",
        "tools/dosunit/tests/test_dosunit_alarm_boundary.py",
    }
    assert required <= set(arguments), required - set(arguments)
    assert arguments.count(uncatalogued_leaf) == 1
    assert uncatalogued_leaf.split("::", 1)[0] not in arguments
    assert "tests/frontend/test_replay_capture_cohorts.py" not in arguments
    for test in ("test_flat32_loop_calls.py", "test_flat32_loop_calls_public.py", "test_replay_capture_vectors.py"):
        assert arguments.count(f"tools/dosunit/tests/{test}") == 1


@pytest.mark.parametrize("jobs", (1, 6))
@pytest.mark.parametrize("admitted", (False, True))
def test_fast_pipeline_requires_comparator_admission(
    tmp_path: Path, jobs: int, admitted: bool,
) -> None:
    """A failed cheap gate must prevent broad tests, including under parallel Make."""
    events = tmp_path / "events"
    overrides = tmp_path / "gates.mk"
    overrides.write_text(
        "decompiler-contracts:\n\t@echo contracts >> \"$(EVENTS)\"\n"
        "comparator-check-fast:\n\t@echo admission >> \"$(EVENTS)\"\n"
        f"\t@exit {0 if admitted else 1}\n",
        encoding="utf-8",
    )
    # Replace only the external broad runner; exercise the real Make dependency
    # and recipe ordering without executing the multi-minute test suites.
    runner = tmp_path / "flock"
    runner.write_text('#!/bin/sh\necho pipeline >> "$EVENTS"\n', encoding="utf-8")
    runner.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    for variable in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES"):
        environment.pop(variable, None)
    environment["EVENTS"] = str(events)
    result = subprocess.run(
        [
            "make", f"-j{jobs}", "-f", "Makefile", "-f", str(overrides),
            "test-pipeline-fast", "PYTHON=true", f"TEST_PIPELINE_LOCK={tmp_path / 'lock'}",
        ],
        cwd=REPO_ROOT, env=environment, capture_output=True, text=True, check=False,
    )
    assert (result.returncode == 0) is admitted, result.stderr
    expected = ["contracts", "admission"] + (["pipeline"] if admitted else [])
    assert events.read_text(encoding="utf-8").splitlines() == expected


@pytest.mark.parametrize(
    ("target", "worker_flag"),
    (
        ("pytest", "-n"),
        ("pytest-files", "-n"),
        ("pytest-profile", "-n"),
        ("decompiler-contracts", "-n"),
        ("compiler-coverage-contracts", "-n"),
        ("comparator-check-fast", "-n"),
        ("pytest-all", "--workers"),
    ),
)
@pytest.mark.parametrize("workers", (None, "1", "6"))
def test_pytest_worker_default_and_override_are_independent_of_cpu_count(
    target: str, worker_flag: str, workers: str | None,
) -> None:
    """Check the default and explicit override without inheriting the outer gate."""
    environment = dict(os.environ)
    # Recursive Make exports command-line overrides through MAKEFLAGS. A gate
    # running with six workers must not turn this default probe into an override.
    for variable in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "PYTEST_WORKERS", "COMPARATOR_PYTEST_WORKERS"):
        environment.pop(variable, None)
    result = subprocess.run(
        [
            "make", "-n", target, f"PYTHON={sys.executable}",
            "CPU_COUNT=128", "PARALLEL_JOBS=41",
            "FILES=tools/dev/tests/test_makefile_quiet_output.py",
            "QA_PYTEST_TARGETS=tools/dev/tests/test_makefile_quiet_output.py",
            "PYTEST_PROFILE_TARGETS=tools/dev/tests/test_makefile_quiet_output.py",
            *([] if workers is None else [f"PYTEST_WORKERS={workers}"]),
        ],
        cwd=REPO_ROOT, env=environment, capture_output=True, text=True, check=True,
    )
    arguments = shlex.split(result.stdout)
    worker_values = [
        value for flag, value in pairwise(arguments)
        if flag == worker_flag and value.isdecimal()
    ]
    requested_workers = "3" if workers is None else workers
    contract_workers = "1" if requested_workers == "1" else "2"
    # The tiny contracts amortize startup better with at most two workers;
    # Wall-budgeted comparator proofs also cap their default pool at two.
    expected = [requested_workers]
    if target == "decompiler-contracts":
        expected = [contract_workers]
    elif target == "comparator-check-fast":
        expected = [contract_workers, contract_workers]
    assert worker_values == expected
    if target == "comparator-check-fast":
        assert "--maxfail=1" in arguments


@pytest.mark.parametrize("comparator_workers", (None, "1", "2", "6"))
def test_comparator_pool_override_does_not_reduce_following_test_pool(
    comparator_workers: str | None,
) -> None:
    """Keep wall-budgeted proofs bounded while allowing six later test workers."""
    environment = dict(os.environ)
    for variable in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "PYTEST_WORKERS", "COMPARATOR_PYTEST_WORKERS"):
        environment.pop(variable, None)
    result = subprocess.run(
        ["make", "-n", "comparator-check-fast", "pytest", f"PYTHON={sys.executable}",
         "PYTEST_WORKERS=6",
         *([] if comparator_workers is None else [f"COMPARATOR_PYTEST_WORKERS={comparator_workers}"]),
         "QA_PYTEST_TARGETS=tools/dev/tests/test_makefile_quiet_output.py"],
        cwd=REPO_ROOT, env=environment, capture_output=True, text=True, check=True,
    )
    workers = [value for flag, value in pairwise(shlex.split(result.stdout)) if flag == "-n" and value.isdecimal()]
    selected = comparator_workers or "2"
    assert workers == ["2", selected, "6"]


@pytest.mark.parametrize("override", (False, True))
def test_mypy_dev_checks_each_inventory_file_once_without_dropping_scope(override):
    """Repeated promotions or explicit overrides must not make MyPy reject its inputs."""
    first = "inertia/cli/discovery_candidate_ranges.py"
    second = "inertia/lowering/c_runtime_header.py"
    command = ["make", "-n", "mypy-dev", f"PYTHON={sys.executable}"]
    if override:
        command.append(f"LINTERS_DEV_MYPY_FILES={first} {second} {first}")
    result = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    recipes = [line for line in result.stdout.splitlines() if " -m mypy " in line]
    assert len(recipes) == 1
    files = [argument for argument in shlex.split(recipes[0]) if argument.endswith(".py")]
    assert first in files
    assert {path: count for path, count in Counter(files).items() if count != 1} == {}
    if override:
        assert set(files) == {first, second}


@pytest.mark.parametrize("use_path", (False, True))
def test_pyright_recipes_resolve_selected_python_environment(use_path: bool) -> None:
    """Every Pyright batch must inspect dependencies from Make's interpreter."""
    interpreter = Path(sys.executable)
    python = interpreter.name if use_path else sys.executable
    env = dict(os.environ, PATH=f"{interpreter.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    result = subprocess.run(
        [
            "make", "-n", "pyright", "pyright-all", "pyright-files",
            f"PYTHON={python}", "PYRIGHT_WATCH=0",
            "FILES=inertia/frontend/x86_16/access.py",
        ],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=True,
    )
    commands = [line for line in result.stdout.splitlines() if " -m pyright " in line]
    assert commands
    assert all(f"--pythonpath {sys.executable}" in line for line in commands)


def test_makefile_quiets_inventory_expanded_tool_recipes() -> None:
    """Large file inventories stay hidden unless a developer requests them."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "Q ?= @" in makefile
    assert "MAKEFLAGS += --no-print-directory" in makefile
    assert "RUFF_OUTPUT_FLAGS ?= --quiet --output-format concise" in makefile
    assert "MYPY_OUTPUT_FLAGS ?= --no-pretty --no-color-output --no-error-summary" in makefile
    assert "PYRIGHT_OUTPUT_FLAGS ?= --level warning" in makefile
    assert "PYTEST_OUTPUT_FLAGS ?= --tb=short --no-header" in makefile
    assert "LIZARD_OUTPUT_FLAGS ?= --warnings_only" in makefile
    assert "\nruff:\n\t$(Q)$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS)" in makefile
    assert "\nmypy:\n\t$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS)" in makefile
    assert "\nmypy-dev:\n\t$(Q)$(PYTHON) -m mypy $(MYPY_OUTPUT_FLAGS)" in makefile
    assert "PYRIGHT_CMD_BASE := $(PYTHON) -m pyright $(PYRIGHT_OUTPUT_FLAGS)" in makefile
    assert "\npyright:\n\t$(Q)$(PYRIGHT_CMD_BASE)" in makefile
    assert "\npyright-all:\n\t$(Q)$(PYRIGHT_CMD_BASE)" in makefile
    assert "\npytest:\n\t$(Q)INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=" in makefile
    assert "\nagent-context-check:\n\t$(Q)$(PYTHON) tools/dev/agent_context_check.py --compact" in makefile


def test_agents_document_bounded_gate_output() -> None:
    """Agents retain full diagnostics without loading successful broad logs."""
    instructions = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "Mandatory guidance: read and follow" in instructions
    assert "[reference/agent-execution.md](reference/agent-execution.md)" in instructions
    execution = (REPO_ROOT / "reference/agent-execution.md").read_text(encoding="utf-8")
    assert "### Token-Efficient Command Output" in execution
    assert "report only the exit status, pass/fail/skip counts" in execution
    assert "Output reduction must never suppress diagnostics" in execution
