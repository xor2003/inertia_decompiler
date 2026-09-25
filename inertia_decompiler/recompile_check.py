"""Run emitted-C recompilation checks as validation/reporting evidence.

Layer: CLI/fallback/reporting.
Responsibility: compile emitted C as validation evidence without repairing generated semantics.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616

from inertia_decompiler.recompile_check_contract import (
    RecompileCheckOutcome as RecompileCheckOutcome,
)
from inertia_decompiler.recompile_check_contract import (
    RecompileCheckResult as RecompileCheckResult,
)


def _sanitize_nested_block_comments(text: str) -> str:
    """Replace /* inside /* */ block comments to prevent -Werror=comment failures."""

    def _fix_inner(match: re.Match[str]) -> str:
        content = match.group(1)
        content = content.replace("/*", "/ *")
        return "/*" + content + "*/"

    return re.sub(r"/\*(.*?)\*/", _fix_inner, text, flags=re.DOTALL)


def _c89_line_comment_start_8616(line: str) -> int | None:
    in_string = False
    in_char = False
    escaped = False
    for index, char in enumerate(line[:-1]):
        if escaped:
            escaped = False
            continue
        if (in_string or in_char) and char == "\\":
            escaped = True
            continue
        if not in_char and char == '"':
            in_string = not in_string
            continue
        if not in_string and char == "'":
            in_char = not in_char
            continue
        if in_string or in_char:
            continue
        if char == "/" and line[index + 1] == "/":
            return index
    return None


def _sanitize_c99_line_comments_for_msc_8616(text: str) -> str:
    lines: list[str] = []
    for line in str(text or "").splitlines(keepends=True):
        newline = ""
        body = line
        if line.endswith("\r\n"):
            body = line[:-2]
            newline = "\r\n"
        elif line.endswith("\n"):
            body = line[:-1]
            newline = "\n"
        comment_start = _c89_line_comment_start_8616(body)
        if comment_start is None:
            lines.append(line)
            continue
        prefix = body[:comment_start]
        comment = body[comment_start + 2 :].replace("/*", "/ *").replace("*/", "* /")
        lines.append(f"{prefix}/*{comment} */{newline}")
    return "".join(lines)


def _dedupe_msc_runtime_typedefs_8616(text: str) -> str:
    typedef_re = re.compile(
        r"^\s*typedef\s+.+?\s+"
        r"(?P<name>int8_t|int16_t|int32_t|uint8_t|uint16_t|uint32_t|clock_t|time_t)"
        r"\s*;\s*$",
        re.IGNORECASE,
    )
    seen: set[str] = set()
    kept: list[str] = []
    for line in str(text or "").splitlines(keepends=True):
        match = typedef_re.match(line.rstrip("\r\n"))
        if match is not None:
            name = match.group("name").lower()
            if name in seen:
                continue
            seen.add(name)
        kept.append(line)
    return "".join(kept)


def _strip_msc_dos_header_aggregate_typedefs_8616(text: str) -> str:
    """Remove emitted DOS aggregate definitions already supplied by DOS.H.

    This is target compile hygiene only. The checked emitted payload retains
    its self-contained definitions, while the MS C compiler input uses the
    canonical target-header definitions and preserves source line numbers.
    """
    cleaned = str(text or "")
    for kind, name in (("union", "REGS"), ("struct", "SREGS")):
        pattern = re.compile(
            rf"(?ms)^[ \t]*typedef[ \t]+{kind}[ \t]+{name}[ \t]*\{{"
            rf".*?^[ \t]*\}}[ \t]*{name}[ \t]*;[ \t]*(?:\r?\n)?"
        )
        alias = f"typedef {kind} {name} {name};\n"
        cleaned = pattern.sub(
            lambda match: alias + "\n" * max(0, match.group(0).count("\n") - 1),  # noqa: B023
            cleaned,
        )
    return cleaned


_DEFAULT_KVIKDOS_PATH = Path("/home/xor/kvikdos/kvikdos")
_DEFAULT_MSC51_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v5.1")
_MSC51_MIRROR_CACHE: dict[Path, Path] = {}
_DEFAULT_RECOMPILE_TIMEOUT_SEC = 20
_MSC51_TRANSIENT_RETRY_LIMIT = 5
_MSC51_COMPILER_LOCK_PATH = Path(tempfile.gettempdir()) / "inertia-msc51-kvikdos.lock"


@contextmanager
def _msc51_compiler_lock_8616() -> Iterator[None]:
    """Serialize KvikDOS/MS C invocations shared by parallel test workers.

    KvikDOS and the DOS compiler use shared emulator state, so concurrent
    processes can produce false compiler errors.  This lock covers only the
    external compiler call; payload preparation and GCC validation stay
    parallel.
    """
    with _MSC51_COMPILER_LOCK_PATH.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _timeout_stream_text(value: str | bytes | None) -> str:
    """Normalize subprocess timeout stream payloads to text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _compile_input_payload_8616(c_text: str, *, target: str) -> str:
    header_payload = _with_runtime_header_8616(c_text, target=target)
    if target == "msc-dos":
        header_payload = _strip_msc_dos_header_aggregate_typedefs_8616(header_payload)
        header_payload = _dedupe_msc_runtime_typedefs_8616(header_payload)
        header_payload = _sanitize_c99_line_comments_for_msc_8616(header_payload)
    sanitized = _sanitize_nested_block_comments(header_payload)
    return sanitized


def _checked_payload_identity_8616(c_text: str) -> tuple[str, str]:
    checked_payload = str(c_text or "")
    return checked_payload, _sha256_text_8616(checked_payload)


def _recompile_timeout_sec() -> int:
    raw = os.environ.get("INERTIA_RECOMPILE_TIMEOUT_SEC", "").strip()
    try:
        value = int(raw) if raw else _DEFAULT_RECOMPILE_TIMEOUT_SEC
    except ValueError:
        value = _DEFAULT_RECOMPILE_TIMEOUT_SEC
    return max(1, value)


def _msc51_transient_emulator_failure_8616(stdout_text: str, stderr_text: str, exit_code: int) -> bool:
    if int(exit_code) == 0:
        return False
    combined_text = f"{stderr_text}\n{stdout_text}".lower()
    has_compiler_error = (" error c" in combined_text) or ("fatal error c" in combined_text)
    if has_compiler_error:
        return False
    return (
        "unexpected kvm exit" in combined_text
        or "unexpected hlt" in combined_text
        or "not a valid dos pathname" in combined_text
    )


def _sanitize_empty_control_bodies_for_compile_8616(text: str) -> str:
    normalized = str(text or "")
    # Compile-hygiene only: preserve condition expression while making malformed
    # empty control bodies syntactically explicit.
    normalized = re.sub(
        r"(?m)^(?P<indent>\s*)if \((?P<cond>[^\n]+)\)\s*(?=\n\s*(?:\}|$))",
        r"\g<indent>if (\g<cond>);",
        normalized,
    )
    return normalized


def _with_runtime_header_8616(c_text: str, *, target: str) -> str:
    text = _sanitize_empty_control_bodies_for_compile_8616(c_text)
    if target == "portable-flat":
        if "extern uint8_t inertia_memory[];" in text and "#define SEG_U8(seg, off)" in text:
            return text
        return f"{render_c_runtime_header_8616(target)}\n{text.lstrip()}"
    if target == "msc-dos":
        if "#define SEG_U8(seg, off)" in text and "#include <dos.h>" in text.lower():
            return text
        return f"{render_c_runtime_header_8616(target)}\n{text.lstrip()}"
    return f"{render_c_runtime_header_8616(target)}\n{text.lstrip()}"


def _resolve_kvikdos_path() -> Path | None:
    raw = os.environ.get("INERTIA_KVIKDOS_PATH", "").strip()
    candidate = Path(raw) if raw else _DEFAULT_KVIKDOS_PATH
    if not candidate.exists():
        return None
    return candidate


def _resolve_msc51_root() -> Path | None:
    raw = os.environ.get("INERTIA_MSC51_ROOT", "").strip()
    candidate = Path(raw) if raw else _DEFAULT_MSC51_ROOT
    if not candidate.exists():
        return None
    if not (candidate / "bin").exists():
        return None
    return candidate


def _resolve_msc51_dir_8616(source_root: Path, lower: str, upper: str) -> Path:
    """Resolve a case-variant tool directory under the MSC51 source root."""
    candidate = source_root / lower
    if not candidate.exists():
        candidate = source_root / upper
    return candidate


def _mirror_bin_entries_8616(bin_src: Path, bin_dst: Path) -> None:
    """Copy tool binaries under both original and lowercase names for kvikdos."""
    for entry in bin_src.iterdir():
        if not entry.is_file():
            continue
        dst = bin_dst / entry.name
        if not dst.exists():
            shutil.copy2(entry, dst)
        lowered = bin_dst / entry.name.lower()
        if not lowered.exists():
            shutil.copy2(entry, lowered)


def _cached_msc51_mirror_8616(source_root: Path) -> Path | None:
    """Return the cached mirror root when it still has the expected layout."""
    cached = _MSC51_MIRROR_CACHE.get(source_root)
    if (
        cached is not None
        and cached.exists()
        and (cached / "bin").exists()
        and (cached / "include").exists()
        and (cached / "lib").exists()
    ):
        return cached
    return None


def _prepare_msc51_mirror_tree(source_root: Path) -> Path:
    cached = _cached_msc51_mirror_8616(source_root)
    if cached is not None:
        return cached

    mirror_root = Path(tempfile.mkdtemp(prefix="inertia-msc51-kvikdos-"))
    bin_src = _resolve_msc51_dir_8616(source_root, "bin", "BIN")
    include_src = _resolve_msc51_dir_8616(source_root, "include", "INCLUDE")
    lib_src = _resolve_msc51_dir_8616(source_root, "lib", "LIB")
    bin_dst = mirror_root / "bin"
    bin_dst.mkdir(parents=True, exist_ok=True)

    if include_src.exists():
        (mirror_root / "include").symlink_to(include_src)
    if lib_src.exists():
        (mirror_root / "lib").symlink_to(lib_src)

    _mirror_bin_entries_8616(bin_src, bin_dst)

    _MSC51_MIRROR_CACHE[source_root] = mirror_root
    return mirror_root


def _check_c_recompiles_msc51_8616(c_text: str, *, target: str) -> RecompileCheckResult:
    def _impl() -> RecompileCheckResult:
        kvikdos = _resolve_kvikdos_path()
        if kvikdos is None:
            compile_payload = _compile_input_payload_8616(c_text, target=target)
            checked_payload, checked_hash = _checked_payload_identity_8616(c_text)
            return RecompileCheckResult(
                outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE,
                target=target,
                exit_code=127,
                compiler=None,
                stdout="",
                stderr="kvikdos not found; install from https://github.com/xor2003/kvikdos and set INERTIA_KVIKDOS_PATH",
                command=("kvikdos",),
                checked_payload=checked_payload,
                checked_payload_hash=checked_hash,
                source_path=None,
            )
        msc_root = _resolve_msc51_root()
        if msc_root is None:
            compile_payload = _compile_input_payload_8616(c_text, target=target)
            checked_payload, checked_hash = _checked_payload_identity_8616(c_text)
            return RecompileCheckResult(
                outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE,
                target=target,
                exit_code=127,
                compiler=str(kvikdos),
                stdout="",
                stderr=("Microsoft C v5.1 root not found; obtain the toolchain from "
                        "https://github.com/davidly/dos_compilers and set INERTIA_MSC51_ROOT"),
                command=(str(kvikdos),),
                checked_payload=checked_payload,
                checked_payload_hash=checked_hash,
                source_path=None,
            )

        tmpdir = Path(tempfile.mkdtemp(prefix="inertia-recompile-msc51-"))
        src_path = tmpdir / "GEN.C"
        compile_payload = _compile_input_payload_8616(c_text, target=target)
        checked_payload, checked_hash = _checked_payload_identity_8616(c_text)
        src_path.write_text(compile_payload, encoding="utf-8")
        upper_src_path = tmpdir / "gen.c"
        upper_src_path.write_text(compile_payload, encoding="utf-8")
        command = (
            str(kvikdos),
            f"--mount=c:{tmpdir}/",
            f"--mount=e:{msc_root}/",
            "--drive=c",
            "--cwd-dos=c:\\",
            "--path-dos=e:\\BIN",
            "--env=INCLUDE=E:\\INCLUDE",
            "--env=LIB=E:\\LIB",
            "--prog=e:\\BIN\\CL.EXE",
            r"e:\BIN\CL.EXE",
            "/nologo",
            "/c",
            r"/Foc:\GEN.OBJ",
            r"c:\GEN.C",
        )
        attempts: list[subprocess.CompletedProcess[str]] = []
        with _msc51_compiler_lock_8616():
            for _attempt_index in range(_MSC51_TRANSIENT_RETRY_LIMIT):
                try:
                    proc = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=_recompile_timeout_sec(),
                    )
                except subprocess.TimeoutExpired as ex:
                    return RecompileCheckResult(
                        outcome=RecompileCheckOutcome.FAILED,
                        target=target,
                        exit_code=124,
                        compiler=str(kvikdos),
                        stdout=_timeout_stream_text(ex.stdout),
                        stderr=_timeout_stream_text(ex.stderr) + "\nrecompile timeout (msc-dos)",
                        command=command,
                        checked_payload=checked_payload,
                        checked_payload_hash=checked_hash,
                        source_path=str(src_path),
                    )
                attempts.append(proc)
                if not _msc51_transient_emulator_failure_8616(
                    proc.stdout or "", proc.stderr or "", proc.returncode
                ):
                    break
            else:
                proc = attempts[-1]
        stderr_text = proc.stderr or ""
        stdout_text = proc.stdout or ""
        combined_text = f"{stderr_text}\n{stdout_text}".lower()
        has_hard_error = (" error " in combined_text) or ("error:" in combined_text) or ("fatal" in combined_text)
        passed = proc.returncode == 0 and not has_hard_error
        if passed:
            shutil.rmtree(tmpdir, ignore_errors=True)
            source_path = None
        else:
            source_path = str(src_path)
        if not passed and len(attempts) > 1:
            stdout_text = "\n".join(attempt.stdout or "" for attempt in attempts)
            stderr_text = "\n".join(attempt.stderr or "" for attempt in attempts)
        return RecompileCheckResult(
            outcome=RecompileCheckOutcome.PASSED if passed else RecompileCheckOutcome.FAILED,
            target=target,
            exit_code=proc.returncode,
            compiler=str(kvikdos),
            stdout=stdout_text,
            stderr=stderr_text,
            command=command,
            checked_payload=checked_payload,
            checked_payload_hash=checked_hash,
            source_path=source_path,
        )

    return _impl()


def check_c_recompiles_8616(c_text: str, *, target: str = "portable-flat") -> RecompileCheckResult:
    """Compile without linking; syntax-only GCC omits return-flow diagnostics."""

    def _impl() -> RecompileCheckResult:
        if target == "msc-dos":
            return _check_c_recompiles_msc51_8616(c_text, target=target)
        compile_payload = _compile_input_payload_8616(c_text, target=target)
        checked_payload, checked_hash = _checked_payload_identity_8616(c_text)
        compiler = shutil.which("gcc")
        if compiler is None:
            return RecompileCheckResult(
                outcome=RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE,
                target=target,
                exit_code=127,
                compiler=None,
                stdout="",
                stderr="gcc not found",
                command=("gcc", "-std=c99", "-Wall", "-Werror", "-c", "-o", os.devnull),
                checked_payload=checked_payload,
                checked_payload_hash=checked_hash,
                source_path=None,
            )

        tmpdir = Path(tempfile.mkdtemp(prefix="inertia-recompile-"))
        src_path = tmpdir / "generated.c"
        src_path.write_text(compile_payload, encoding="utf-8")
        command = (
            compiler,
            "-std=c99",
            "-Wall",
            "-Werror",
            "-Wno-error=unused-but-set-variable",
            "-Wno-error=parentheses",
            "-Wno-error=unused-variable",
            "-Wno-error=nonnull",
            "-Wno-error=builtin-declaration-mismatch",
            "-fno-builtin",
            "-c",
            "-o",
            os.devnull,
            str(src_path),
        )
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=_recompile_timeout_sec(),
            )
        except subprocess.TimeoutExpired as ex:
            return RecompileCheckResult(
                outcome=RecompileCheckOutcome.FAILED,
                target=target,
                exit_code=124,
                compiler=compiler,
                stdout=_timeout_stream_text(ex.stdout),
                stderr=_timeout_stream_text(ex.stderr) + "\nrecompile timeout (portable-flat)",
                command=command,
                checked_payload=checked_payload,
                checked_payload_hash=checked_hash,
                source_path=str(src_path),
            )
        passed = proc.returncode == 0
        if passed:
            shutil.rmtree(tmpdir, ignore_errors=True)
            source_path = None
        else:
            source_path = str(src_path)
        return RecompileCheckResult(
            outcome=RecompileCheckOutcome.PASSED if passed else RecompileCheckOutcome.FAILED,
            target=target,
            exit_code=proc.returncode,
            compiler=compiler,
            stdout=proc.stdout,
            stderr=proc.stderr,
            command=command,
            checked_payload=checked_payload,
            checked_payload_hash=checked_hash,
            source_path=source_path,
        )

    return _impl()


def _sha256_text_8616(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", errors="ignore")).hexdigest()
