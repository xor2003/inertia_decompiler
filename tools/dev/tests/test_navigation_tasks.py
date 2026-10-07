"""Frozen navigation tasks for the structure pilot's routing controls.

These validate context construction and test routing. They do not substitute
for repair trials with an actual smaller model.
"""

import json

import pytest

from tools.dev import agent_test_focus
from tools.dev.task_context import build_task_context

pytestmark = pytest.mark.tooling

TASKS = (
    ("compiler_id", "tools/compiler_id/report.py", "compiler_detector", "tools/compiler_id/tests/test_flags.py"),
    ("ada_signatures", "tools/ada_script/signatures.py", "ada_script", "tests/integration/test_ada_signature_integration.py"),
    ("ssa_compare", "tools/dosunit/compare/straightline_ssa.py", "ssa_z3", "tools/dosunit/tests/test_dosunit_io_read_state.py"),
    ("lifting", "inertia/frontend/x86_16/lift_86_16.py", "lifter", "tests/integration/test_x86_16_frontend_condition_evidence.py"),
    ("stack_lowering", "inertia/lowering/stack_variable_coordinates.py", "decompiler", "tests/lowering/test_x86_16_stack_variable_coordinates.py"),
    ("structuring", "inertia/structuring/decompiler_structuring_stage.py", "decompiler", "tests/structuring/test_x86_16_structuring_stage_environment.py"),
    ("cli_cache", "inertia/cli/cache_lock.py", "decompiler", "tests/cli/test_cache_lock.py"),
    ("compiler_runner", "tools/compiler_toolchain/compiler_coverage_runner.py", "compiler_toolchain", "tools/compiler_toolchain/tests/test_compiler_coverage_runner.py::test_invalid_deadline_rejected_before_creating_artifacts"),
)


@pytest.mark.parametrize("task,path,owner,expected_test", TASKS, ids=[task[0] for task in TASKS])
def test_frozen_navigation_routes_to_owner_and_regression(task, path, owner, expected_test):
    plans = agent_test_focus._plan(None, (path,), include_shared=False)
    tests = tuple(entry.test for entry in agent_test_focus._materialize_selected_tests(plans))
    context = build_task_context((path,), tests)
    assert owner in {entry["name"] for entry in context["owners"]}, task
    assert expected_test in tests, task
    assert context["selected_tests"] == tests
    assert len(json.dumps(context)) < 24000, task
