from __future__ import annotations

from pathlib import Path
from types import CodeType

from monkeytype.config import default_code_filter


REPO_ROOT = Path(__file__).resolve().parents[1]
MONKEYTYPE_CACHE_DIR = REPO_ROOT / ".cache" / "monkeytype"
MONKEYTYPE_DB_PATH = MONKEYTYPE_CACHE_DIR / "monkeytype.sqlite3"
MONKEYTYPE_STUBS_DIR = MONKEYTYPE_CACHE_DIR / "stubs"

TRACEABLE_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "inertia_decompiler",
    REPO_ROOT / "angr_platforms" / "angr_platforms" / "X86_16",
    REPO_ROOT / "scripts",
)

TRACEABLE_FILES: tuple[Path, ...] = (
    REPO_ROOT / "decompile.py",
    REPO_ROOT / "monkeytype_config.py",
)

DEFAULT_MONKEYTYPE_TEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_x86_16_access_trait_arrays.py",
    "angr_platforms/tests/test_x86_16_access_trait_policy.py",
    "angr_platforms/tests/test_x86_16_access_trait_strides.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py",
    "angr_platforms/tests/test_x86_16_segmented_memory.py",
    "angr_platforms/tests/test_x86_16_type_equivalence_classes.py",
    "angr_platforms/tests/test_x86_16_stack_prototype_promotion.py",
    "angr_platforms/tests/test_x86_16_tail_validation.py",
    "angr_platforms/tests/test_x86_16_widening_model.py",
)

DEFAULT_STUB_MODULE_PREFIXES: tuple[str, ...] = (
    "inertia_decompiler",
    "angr_platforms.X86_16",
    "decompile",
)


def ensure_monkeytype_dirs() -> None:
    MONKEYTYPE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    MONKEYTYPE_STUBS_DIR.mkdir(parents=True, exist_ok=True)


def is_traceable_repo_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except FileNotFoundError:
        resolved = path
    if resolved in TRACEABLE_FILES:
        return True
    return any(root in resolved.parents for root in TRACEABLE_ROOTS)


def monkeytype_code_filter(code: CodeType) -> bool:
    if not default_code_filter(code):
        return False
    filename = getattr(code, "co_filename", None)
    if not isinstance(filename, str) or not filename:
        return False
    return is_traceable_repo_path(Path(filename))


def parse_list_modules_output(text: str, prefixes: tuple[str, ...] = DEFAULT_STUB_MODULE_PREFIXES) -> tuple[str, ...]:
    modules = {
        line.strip()
        for line in text.splitlines()
        if line.strip() and any(line.strip() == prefix or line.strip().startswith(prefix + ".") for prefix in prefixes)
    }
    return tuple(sorted(modules))


def stub_path_for_module(module_name: str) -> Path:
    parts = module_name.split(".")
    return MONKEYTYPE_STUBS_DIR.joinpath(*parts).with_suffix(".pyi")


def source_path_for_module(module_name: str) -> Path | None:
    if module_name == "decompile":
        return REPO_ROOT / "decompile.py"
    if module_name.startswith("inertia_decompiler."):
        rel = module_name.removeprefix("inertia_decompiler.").replace(".", "/")
        return REPO_ROOT / "inertia_decompiler" / f"{rel}.py"
    if module_name.startswith("angr_platforms.X86_16."):
        rel = module_name.removeprefix("angr_platforms.X86_16.").replace(".", "/")
        return REPO_ROOT / "angr_platforms" / "angr_platforms" / "X86_16" / f"{rel}.py"
    return None


def source_line_count(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)
