"""Layer: Tooling/gates.

Responsibility: persist bounded production-CLI attempts for every COD procedure.
COD inputs are normalized object fixtures; CLI success is not linked-program
equivalence. Structured tail evidence is retained independently of CLI exit status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.fork_timeout import run_captured_subprocess_tree  # noqa: E402
from inertia_decompiler.tail_validation import TAIL_VALIDATION_METADATA_PREFIX  # noqa: E402


class Outcome(StrEnum):
    """Execution outcomes, deliberately separate from semantic acceptance."""

    CLI_OK_UNVERIFIED = "cli_ok_unverified"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    NO_OUTPUT = "no_output"


class TailStatus(StrEnum):
    """Reported whole-tail evidence, not overall decompilation acceptance."""

    PASSED = "passed"
    FAILED = "failed"
    CHANGED = "changed"
    UNKNOWN = "unknown"
    UNCOLLECTED = "uncollected"
    MISSING = "missing"
    INVALID = "invalid"


@dataclass(frozen=True)
class TailEvidence:
    """Keep the original structured report alongside its qualified status."""

    status: TailStatus
    detail: str
    payload: dict[str, object] | None = None


def tail_evidence(stderr: str, procedure: str) -> TailEvidence:
    """Read exactly one matching function report; refuse malformed ambiguity."""
    reports = [line.removeprefix(TAIL_VALIDATION_METADATA_PREFIX)
               for line in stderr.splitlines() if line.startswith(TAIL_VALIDATION_METADATA_PREFIX)]
    if not reports:
        return TailEvidence(TailStatus.MISSING, "No structured tail report")
    if len(reports) != 1:
        return TailEvidence(TailStatus.INVALID, "Expected exactly one structured tail report")
    try:
        payload = json.loads(reports[0])
    except json.JSONDecodeError:
        return TailEvidence(TailStatus.INVALID, "Malformed tail report JSON")
    if not isinstance(payload, dict):
        return TailEvidence(TailStatus.INVALID, "Tail report must be an object")
    summary = payload.get("summary")
    rows = summary.get("function_statuses") if isinstance(summary, dict) else None
    if not isinstance(rows, list) or len(rows) != 1:
        return TailEvidence(TailStatus.INVALID, "Expected one function status", payload)
    row = rows[0]
    if not isinstance(row, dict) or row.get("proc_name") != procedure:
        return TailEvidence(TailStatus.INVALID, "Function status identity mismatch", payload)
    try:
        raw_status = row.get("status")
        status = TailStatus(raw_status) if isinstance(raw_status, str) else TailStatus.INVALID
    except (ValueError, TypeError):
        return TailEvidence(TailStatus.INVALID, "Unrecognized function status", payload)
    return TailEvidence(status, "Structured function status; not linked-program equivalence", payload)


@dataclass(frozen=True)
class Procedure:
    """Stable object-listing identity and source provenance."""

    path: str
    name: str
    kind: str
    source_sha256: str

    @property
    def key(self) -> str:
        """Return an artifact-safe identity without assuming unique basenames."""
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


def digest(path: Path) -> str:
    """Hash exact artifact bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> list[Procedure]:
    """Enumerate existing extraction-owner procedures without using their bytes."""
    from angr_platforms.X86_16.corpus_scan import extract_cod_functions

    procedures: list[Procedure] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() != ".cod":
            continue
        entries = extract_cod_functions(path)
        if not entries:
            raise ValueError(f"No procedures extracted from {path}; inventory is incomplete")
        source_hash = digest(path)
        procedures.extend(Procedure(str(path.resolve()), name, kind, source_hash) for name, kind, _code in entries)
    keys = [item.key for item in procedures]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate procedure identity; refuse an ambiguous sweep")
    if not procedures:
        raise ValueError(f"No COD procedures found under {root}")
    return procedures


def write_json(path: Path, payload: object) -> None:
    """Atomically publish a manifest or completed attempt."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def prepare(output: Path, procedures: list[Procedure], timeout: int, memory_mb: int) -> None:
    """Pin code, inputs and execution settings; refuse stale resume evidence."""
    from inertia_decompiler.cache import DECOMPILATION_CACHE_SOURCE_FILES, _cache_source_digest

    manifest = {
        "schema": 2,
        "input_contract": "normalized_object_fixture_not_linked_binary",
        "source_digest": _cache_source_digest(DECOMPILATION_CACHE_SOURCE_FILES),
        "runner_digest": digest(Path(__file__)),
        "python": sys.version,
        "timeout": timeout,
        "memory_mb": memory_mb,
        "procedures": [asdict(item) for item in procedures],
    }
    output.mkdir(parents=True, exist_ok=True)
    path = output / "inventory.json"
    if path.exists():
        if json.loads(path.read_text()) != manifest:
            raise ValueError("Sweep inputs/code/settings changed; use a new output directory")
    else:
        write_json(path, manifest)


def completed(output: Path, item: Procedure) -> bool:
    """Require both preserved artifacts before trusting a completed attempt."""
    path = output / f"{item.key}.json"
    if not path.exists():
        return False
    payload = json.loads(path.read_text())
    Outcome(payload["outcome"])
    for suffix, field in (("c", "stdout_sha256"), ("log", "stderr_sha256")):
        artifact = output / f"{item.key}.{suffix}"
        if not artifact.exists() or digest(artifact) != payload[field]:
            raise ValueError(f"Missing or changed sweep artifact: {artifact}")
    return True


def attempt(output: Path, item: Procedure, timeout: int, memory_mb: int) -> Outcome:
    """Run one CLI in a disposable process tree and durably retain its result."""
    command = [sys.executable, str(REPO_ROOT / "decompile.py"), item.path,
               "--proc", item.name, "--proc-kind", item.kind,
               "--timeout", str(timeout), "--max-memory-mb", str(memory_mb)]
    env = dict(os.environ, PYTHON_JIT="1", PYTHONHASHSEED="0", INERTIA_TAIL_VALIDATION_STDERR_JSON="1")
    started = time.monotonic()
    returncode: int | None = None
    try:
        result = run_captured_subprocess_tree(command, env=env, timeout=max(60, timeout * 3))
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        outcome = Outcome.FAILED if returncode else Outcome.CLI_OK_UNVERIFIED
        if returncode == 0 and not stdout.strip():
            outcome = Outcome.NO_OUTPUT
    except subprocess.TimeoutExpired as exc:
        stdout = _text(exc.stdout)
        stderr = _text(exc.stderr)
        outcome = Outcome.TIMED_OUT
    stdout_path, stderr_path = output / f"{item.key}.c", output / f"{item.key}.log"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    write_json(output / f"{item.key}.json", {
        "procedure": asdict(item), "outcome": outcome, "returncode": returncode,
        "wall_seconds": time.monotonic() - started, "command": command,
        "stdout_sha256": digest(stdout_path), "stderr_sha256": digest(stderr_path),
        "validation": asdict(tail_evidence(stderr, item.name)), "compilation": "not_checked",
    })
    return outcome


def _text(value: str | bytes | None) -> str:
    """Normalize subprocess timeout captures without losing diagnostics."""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""


def main() -> int:
    """Attempt the next bounded batch; report pending separately from failures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--limit", type=int, default=8, help="New attempts; zero attempts all pending")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--memory-mb", type=int, default=768)
    args = parser.parse_args()
    if args.limit < 0 or min(args.workers, args.timeout, args.memory_mb) < 1:
        parser.error("limit must be nonnegative; workers, timeout and memory must be positive")
    procedures = inventory(args.root)
    prepare(args.output, procedures, args.timeout, args.memory_mb)
    pending = [item for item in procedures if not completed(args.output, item)]
    selected = pending[:args.limit] if args.limit else pending
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(attempt, args.output, item, args.timeout, args.memory_mb) for item in selected]
        for future in futures:
            future.result()
    counts: Counter[str] = Counter()
    for item in procedures:
        if completed(args.output, item):
            counts[json.loads((args.output / f"{item.key}.json").read_text())["outcome"]] += 1
        else:
            counts["pending"] += 1
    write_json(args.output / "summary.json", dict(counts))
    print(json.dumps(dict(counts), sort_keys=True))
    if any(counts[outcome] for outcome in (Outcome.FAILED, Outcome.TIMED_OUT, Outcome.NO_OUTPUT)):
        return 1
    return 2 if counts["pending"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
