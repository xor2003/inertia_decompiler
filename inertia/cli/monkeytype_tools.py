# cython: language_level=3, infer_types=True
"""Shared MonkeyType paths and filters for the decompiler type ratchet.

Layer: CLI/fallback/reporting.
Responsibility: owns shared MonkeyType paths and repository code filters.
"""

from __future__ import annotations
import typing
import cython

from pathlib import Path
from types import CodeType

from monkeytype.config import default_code_filter  # pyright: ignore[reportMissingImports]
import operator
import builtins

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
MONKEYTYPE_CACHE_DIR: Path = REPO_ROOT / ".cache" / "monkeytype"
MONKEYTYPE_DB_PATH: Path = MONKEYTYPE_CACHE_DIR / "monkeytype.sqlite3"
MONKEYTYPE_STUBS_DIR: Path = MONKEYTYPE_CACHE_DIR / "stubs"

TRACEABLE_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "inertia" / "cli",
    REPO_ROOT / "angr_platforms" / "angr_platforms" / "X86_16",
    REPO_ROOT / "scripts",
)

TRACEABLE_FILES: tuple[Path, ...] = (
    REPO_ROOT / "decompile.py",
    REPO_ROOT / "monkeytype_config.py",
)

DEFAULT_MONKEYTYPE_TEST_TARGETS: tuple[str, ...] = (
    "tests/integration/test_x86_16_access_trait_arrays.py",
    "tests/integration/test_x86_16_access_trait_policy.py",
    "tests/integration/test_x86_16_access_trait_strides.py",
    "tests/postprocess/test_x86_16_decompiler_postprocess_utils.py",
    "tests/alias/test_x86_16_segmented_memory.py",
    "tests/validation/test_x86_16_tail_validation.py",
    "angr_platforms/tests/test_x86_16_type_equivalence_classes.py",
)

DEFAULT_STUB_MODULE_PREFIXES: tuple[str, ...] = (
    "inertia.cli",
    "inertia.frontend.x86_16.public_api",
    "decompile",
)


@cython.ccall
def ensure_monkeytype_dirs() -> None:
    """Create the MonkeyType cache and stub output directories."""
    MONKEYTYPE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    MONKEYTYPE_STUBS_DIR.mkdir(parents=True, exist_ok=True)


def is_traceable_repo_path(path: Path) -> cython.bint:
    """Return whether a file path belongs to traceable decompiler code."""
    try:
        resolved = path.resolve()
    except FileNotFoundError:
        resolved = path
    if resolved in TRACEABLE_FILES:
        return True
    return any(root in resolved.parents for root in iter(TRACEABLE_ROOTS))


@cython.ccall
def monkeytype_code_filter(code: CodeType) -> cython.bint:
    """Return whether MonkeyType should trace a code object from this repo."""
    if not default_code_filter(code):
        return False
    filename = code.co_filename
    if not isinstance(filename, str) or not filename:
        return False
    return is_traceable_repo_path(Path(filename))


def parse_list_modules_output(text: object, prefixes: object = DEFAULT_STUB_MODULE_PREFIXES) -> tuple[str, ...]:
    """Return sorted MonkeyType module names matching the allowed prefixes."""
    modules = {
        line.strip()
        for line in builtins.iter(text.splitlines())
        if line.strip() and any(operator.eq(line.strip(), prefix) or line.strip().startswith(prefix + ".") for prefix in iter(prefixes))
    }
    return tuple(sorted(modules))


@cython.ccall
def stub_path_for_module(module_name: object) -> Path:
    """Return the local stub-cache path for a Python module name."""
    parts = module_name.split(".")
    return MONKEYTYPE_STUBS_DIR.joinpath(*parts).with_suffix(".pyi")


@cython.ccall
def source_path_for_module(module_name: object) -> Path | None:
    """Return the repository source path for a traceable module name."""
    if module_name == "decompile":
        return REPO_ROOT / "decompile.py"
    if module_name.startswith("inertia.cli."):
        rel = module_name.removeprefix("inertia.cli.").replace(".", "/")
        return REPO_ROOT / "inertia" / "cli" / f"{rel}.py"
    if module_name.startswith("inertia.frontend.x86_16.public_api."):
        rel = module_name.removeprefix("inertia.frontend.x86_16.public_api.").replace(".", "/")
        return REPO_ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / f"{rel}.py"
    return None


def source_line_count(path: Path) -> cython.longlong:
    """Return the number of text lines in a source file."""
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in iter(handle))
