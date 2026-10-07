"""Generic helper annotations must bind the parameters they declare."""

import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import ParamSpec, TypeVar, assert_type, get_args, get_overloads, get_type_hints

from inertia.frontend.x86_16.regs import _coerce_enum, reg16_t
from inertia.lowering.type_array_matching import _limit_sorted_mapping_8616

from inertia.cli.fork_timeout import run_with_timeout_in_fork
from inertia.cli.telemetry import trace_function


def _parameters(annotation: object) -> Iterator[object]:
    if isinstance(annotation, TypeVar | ParamSpec):
        yield annotation
    arguments = annotation if isinstance(annotation, list | tuple) else get_args(annotation)
    for argument in arguments:
        yield from _parameters(argument)


def test_annotations_use_declared_type_parameters() -> None:
    for function in (
        run_with_timeout_in_fork, _coerce_enum, _limit_sorted_mapping_8616,
        trace_function, *get_overloads(trace_function),
    ):
        referenced = {
            parameter
            for annotation in get_type_hints(function).values()
            for parameter in _parameters(annotation)
        }
        assert referenced == set(function.__type_params__), function.__name__


@trace_function
def _direct(value: int) -> str:
    return str(value)


@trace_function(name="generic-contract")
def _configured(value: int) -> str:
    return str(value)


def _attributes(value: int) -> dict[str, object]:
    return {"value": value}


@trace_function(attr_factory=_attributes)
def _attributed(value: int) -> str:
    return str(value)


def test_generic_result_types() -> None:
    assert_type(_direct(1), str)
    assert_type(_configured(1), str)
    assert_type(_attributed(1), str)
    assert_type(_coerce_enum(reg16_t, 0), reg16_t)
    assert _direct(1) == _configured(1) == _attributed(1) == "1"


def test_generic_type_inference(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable, "-m", "mypy", "--no-error-summary", "--no-pretty",
            "--cache-dir", str(tmp_path / "mypy"),
            "inertia.cli/fork_timeout.py", "inertia.cli/telemetry.py",
            "inertia/frontend/x86_16/regs.py",
            "inertia/lowering/type_array_matching.py", __file__,
        ],
        cwd=root, capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
