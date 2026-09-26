#!/usr/bin/env python3
"""Generate MS C 5.1 flag-profile fixtures for decompiler regression data.

Layer: Tooling/gates.
Responsibility: build optional compiler flag-profile diagnostics without proving semantics.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

TOKEN_RE = re.compile(r"\b[_$A-Za-z][_$A-Za-z0-9]*\b")
ASM_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\b(.*)$")
SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "goto",
    "break",
    "continue",
    "mov",
    "push",
    "pop",
    "call",
    "cmp",
    "add",
    "sub",
    "mul",
    "div",
    "lea",
    "byte",
    "word",
    "ptr",
    "short",
    "near",
    "far",
}
ASM_PROMPT_RE = re.compile(r"Recover the function from this assembly:\s*(.*)", re.S | re.I)


def combo_from_name(path: Path) -> str:
    """Return a canonical flag-combination label from an output filename."""
    stem = path.stem
    if stem.startswith("output_"):
        stem = stem[len("output_") :]
    parts = [p for p in stem.split("_") if p]
    return " ".join(sorted(parts))


def extract_tokens(text: str) -> Counter[str]:
    """Extract runtime/helper-like symbol tokens from text."""
    c: Counter[str] = Counter()
    for m in TOKEN_RE.finditer(text):
        t = m.group(0)
        tl = t.lower()
        if tl in SKIP:
            continue
        if tl.startswith(("__", "$", "_")):
            c[tl] += 1
    return c


def _instruction_shape_tokens(rest: str) -> tuple[str, ...]:
    """Return cheap operand-shape markers that are often flag-sensitive."""
    shapes: list[str] = []
    if " ptr " in rest:
        shapes.append("shape:ptr")
    if "[" in rest and "]" in rest:
        shapes.append("shape:mem")
    if "bp" in rest:
        shapes.append("shape:bp")
    if "sp" in rest:
        shapes.append("shape:sp")
    if "si" in rest or "di" in rest:
        shapes.append("shape:index")
    if "short" in rest:
        shapes.append("shape:short")
    return tuple(shapes)


def extract_instruction_tokens(text: str) -> Counter[str]:
    """Extract opcode and operand-shape tokens from assembly text."""
    out: Counter[str] = Counter()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        m = ASM_LINE_RE.match(s)
        if not m:
            continue
        op = m.group(1).lower()
        rest = m.group(2).lower()
        out[f"op:{op}"] += 1
        for shape in _instruction_shape_tokens(rest):
            out[shape] += 1
    return out


def extract_byte_ngram_tokens(blob: bytes, n: int = 4, step: int = 3, limit: int = 20000) -> Counter[str]:
    """Extract bounded byte n-gram tokens from compiler artifacts."""
    out: Counter[str] = Counter()
    if len(blob) < n:
        return out
    end = min(len(blob) - n + 1, limit)
    for i in range(0, end, step):
        gram = blob[i : i + n]
        out[f"b{n}:{gram.hex()}"] += 1
    return out


def canonical_combo_from_flags(flags: str) -> str:
    """Normalize a compiler flag string into a canonical combo label."""
    parts: list[str] = []
    for tok in flags.split():
        t = tok.strip()
        if not t:
            continue
        if t.startswith("/"):
            t = t[1:]
        parts.append(t)
    norm = set(parts)
    if "Ox" in norm:
        norm.discard("Ox")
        norm.update({"Oa", "Oi", "Ol", "Ot", "Gs"})
    return " ".join(sorted(norm, key=lambda x: x.lower()))


def maybe_extract_asm_from_dataset_user_msg(text: str) -> str:
    """Extract the assembly prompt payload from one dataset user message."""
    m = ASM_PROMPT_RE.search(text)
    if not m:
        return ""
    return m.group(1).strip()


def _parse_args_8616(argv: list[str] | None) -> argparse.Namespace:
    """Parse the MS C 5.1 flag-profile command line."""
    ap = argparse.ArgumentParser(description="Build MS C 5.1 flag-combo token profiles from deep/*.COD")
    ap.add_argument(
        "--cod-dir",
        dest="cod_dirs",
        action="append",
        type=Path,
        help="Directory containing output_*.COD (repeatable). Default: /home/xor/vextest/deep",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=Path("/home/xor/vextest/signature_catalogs/msc51_flag_profiles.json"),
    )
    ap.add_argument(
        "--dataset-jsonl",
        dest="dataset_jsonls",
        action="append",
        type=Path,
        help="Optional nndecomp dataset jsonl (repeatable), e.g. cod_combo_strict_10x.jsonl",
    )
    return ap.parse_args(argv)


def _collect_cod_profiles_8616(
    roots: list[Path],
    profiles: dict[str, Counter[str]],
    counts: Counter[str],
    allowed_combos: set[str],
) -> int:
    """Accumulate token profiles from each output_*.COD under the roots."""
    used_files = 0
    for root in roots:
        for cod in sorted(root.glob("output_*.COD")):
            combo = combo_from_name(cod)
            allowed_combos.add(combo)
            txt = cod.read_text(errors="ignore")
            profiles[combo].update(extract_tokens(txt))
            profiles[combo].update(extract_instruction_tokens(txt))
            base = cod.with_suffix("")
            for ext in (".EXE", ".OBJ"):
                p = base.with_suffix(ext)
                if p.exists():
                    with contextlib.suppress(Exception):
                        profiles[combo].update(extract_byte_ngram_tokens(p.read_bytes()))
            counts[combo] += 1
            used_files += 1
    return used_files


def _dataset_paths_8616(dataset_jsonls: list[Path] | None) -> list[Path]:
    """Return the requested dataset jsonl paths or the default artifact."""
    dataset_paths = dataset_jsonls or []
    if not dataset_paths:
        default_ds = Path("/home/xor/nndecomp/artifacts/dataset/cod_combo_strict_10x.jsonl")
        if default_ds.exists():
            dataset_paths = [default_ds]
    return dataset_paths


def _dataset_row_combo_8616(obj: dict[Any, Any], allowed_combos: set[str]) -> str | None:
    """Return the canonical flag combo of one dataset row, or None."""
    meta = obj.get("meta", {})
    if not isinstance(meta, dict):
        return None
    flags = str(meta.get("flags", "")).strip()
    if not flags:
        return None
    combo = canonical_combo_from_flags(flags)
    if not combo or (allowed_combos and combo not in allowed_combos):
        return None
    return combo


def _dataset_user_text_8616(obj: dict[Any, Any]) -> str:
    """Return the first user message content of one dataset row."""
    msgs = obj.get("messages", [])
    if not isinstance(msgs, list):
        return ""
    for msg in msgs:
        if isinstance(msg, dict) and msg.get("role") == "user":
            return str(msg.get("content", ""))
    return ""


def _collect_dataset_profiles_8616(
    dataset_paths: list[Path],
    allowed_combos: set[str],
    profiles: dict[str, Counter[str]],
    counts: Counter[str],
) -> tuple[int, int]:
    """Accumulate dataset-row token profiles; return (rows, sources)."""
    dataset_rows = 0
    dataset_sources = 0
    for ds in dataset_paths:
        if not ds.exists():
            continue
        dataset_sources += 1
        with ds.open("r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                combo = _dataset_row_combo_8616(obj, allowed_combos)
                if combo is None:
                    continue
                user_text = _dataset_user_text_8616(obj)
                if not user_text:
                    continue
                asm_text = maybe_extract_asm_from_dataset_user_msg(user_text)
                if not asm_text:
                    continue
                profiles[combo].update(extract_instruction_tokens(asm_text))
                profiles[combo].update(extract_tokens(asm_text))
                counts[combo] += 1
                dataset_rows += 1
    return dataset_rows, dataset_sources


def _combo_payload_entry_8616(
    combo: str,
    profiles: dict[str, Counter[str]],
    counts: Counter[str],
    token_df: Counter[str],
    combo_count: int,
) -> dict[str, Any]:
    """Return one IDF-weighted top-token entry for a flag combo."""
    return {
        "samples": int(counts[combo]),
        "tokens": dict(
            sorted(
                (
                    (
                        tok,
                        float(val) * (math.log((combo_count + 1.0) / (token_df.get(tok, 0) + 1.0)) + 1.0),
                    )
                    for tok, val in profiles[combo].items()
                    if val > 0
                ),
                key=lambda kv: kv[1],
                reverse=True,
            )[:800]
        ),
    }


def _flag_profile_payload_8616(
    roots: list[Path],
    profiles: dict[str, Counter[str]],
    counts: Counter[str],
    used_files: int,
    dataset_sources: int,
    dataset_rows: int,
) -> dict[str, Any]:
    """Build the IDF-weighted flag-profile payload document."""
    # Keep the most informative tokens per combo to improve separation.
    combo_count = max(1, len(profiles))
    token_df: Counter[str] = Counter()
    for prof in profiles.values():
        for token, value in prof.items():
            if value > 0:
                token_df[token] += 1
    return {
        "schema": 2,
        "source_dirs": [str(r) for r in roots],
        "source_file_count": used_files,
        "dataset_sources": dataset_sources,
        "dataset_rows": dataset_rows,
        "combos": {
            combo: _combo_payload_entry_8616(combo, profiles, counts, token_df, combo_count)
            for combo in sorted(profiles)
        },
    }


def main(argv: list[str] | None = None) -> int:
    """Build MS C 5.1 flag-combo profiles from COD and optional dataset inputs."""
    args = _parse_args_8616(argv)
    profiles: dict[str, Counter[str]] = defaultdict(Counter)
    counts: Counter[str] = Counter()
    roots = args.cod_dirs or [Path("/home/xor/vextest/deep")]
    allowed_combos: set[str] = set()
    used_files = _collect_cod_profiles_8616(roots, profiles, counts, allowed_combos)
    dataset_rows, dataset_sources = _collect_dataset_profiles_8616(
        _dataset_paths_8616(args.dataset_jsonls),
        allowed_combos,
        profiles,
        counts,
    )
    payload = _flag_profile_payload_8616(
        roots,
        profiles,
        counts,
        used_files,
        dataset_sources,
        dataset_rows,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True))
    combos = payload.get("combos")
    combo_count = len(combos) if isinstance(combos, dict) else 0
    print(f"wrote {args.output} combos={combo_count} files={used_files}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
