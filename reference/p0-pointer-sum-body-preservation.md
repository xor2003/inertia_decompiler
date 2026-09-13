# Word Sum Body Preservation

## Scope And Root Cause

The MS C `pointer_memory` roundtrip stopped at `sum_words`: GP stack-restore
facts were classified but none materialized. The legacy
`_materialize_word_pointer_sum_loop_8616` replaced the complete function body
with a synthesized sum loop, discarding SI/DI saves and restores. Its generic
path already recovered the indexed word load, signed count and return.

An isolated diagnostic disabled only that callback in a fresh cache namespace.
It retained the memory indexing and GP effects, with stable validation and
portable compilation. Production then removed the callback, its structuring
wiring and its dispatch contract. Other pointer idioms were not disabled.
Compatibility normalization remains, but cannot justify reintroducing semantic
whole-body replacement. See the guard in `lowering/pointer_memory_idioms.py`.

The next failure was a tooling ABI omission: extracting function bodies for
the MS C rebuild discarded the header's `PTR_U16` macro. The linker reported
an unresolved `_PTR_U16`. Lowering now owns one shared pointer-storage macro
renderer, consumed by both its complete target headers and the rebuild harness.
Neither fix rewrites emitted bodies or uses the original source as recovery
evidence. The source is only a behavior oracle.

## Acceptance Evidence

| Work | Reason | Definition Of Done | Definition Of Failure | Observed |
| --- | --- | --- | --- | --- |
| Retire word-sum substitution | Preserve all machine effects | Generic indexed body retains signed count, return and SI/DI; normal CLI validates and compiles | Lost state/index/return, semantic replacement, or validation refusal | Normal CLI exit 0, validation=passed, clean whole-tail; strict compiled behavior passes |
| Independent behavior oracle | Avoid accepting a prettier but incorrect loop | Positive/reference checks and deliberately corrupt controls cover sums, nonpositive counts, word wrap, input memory and GP preservation | Oracle accepts corruption or fails only on unrelated compiler warnings | Six oracle tests pass in 3.52s; generated output passes the same GCC/UBSan harness |
| Rebuild runtime ABI | Link actual generated operations | Harness and target header consume identical pointer casts; original and rebuilt DOS programs agree | Duplicate semantic owners, missing helper, changed function body or different exit code | Header regression failed before repair; full pointer_memory build/decompile/recompile/run passes, both exits 255 |

The oracle checks counts -32768, -1, 0, 1, 4, 31, 256 and 511 and four input
patterns. Nonpositive counts use a null pointer; no read is permitted. It
compares 16-bit return bits, checks the full source buffer, and preserves seeded
32-bit SI/DI runtime lanes. Corrupt controls fix the index, extend the bound,
replace accumulation, clobber DI or write the source. The source-write control
uses braces so failure comes from behavior rather than GCC indentation lint.

The new oracle is enrolled in Make, the routine pipeline and test ownership.
Combined builder/oracle tests: 62 passed in 25.51s. Runtime-header tests:
18 passed in 25.51s, including both target casts and unknown-target refusal.
Pointer-idiom dispatch tests previously passed 9 cases after callback removal.
Scoped header and pointer-idiom MyPy pass. Architecture, agent context and test
ownership gates pass. New oracle and header tests pass Ruff `check --fix`.
Legacy lint findings remain visible; `quality-fast` exits 2 at global linters,
with compiled-import smoke passing for 39 modules. No global quality claim.

## Timing And Artifacts

The sum-work interval began before this checkpoint's exact clock was retained;
do not invent an active-work start or extrapolate a goal ETA. Normal CLI output
was observed at 16:30 +02:00 on 2026-09-12. The successful targeted roundtrip
was observed before 16:43 +02:00, taking 79.23s as reported by the harness.
This is not a controlled performance comparison. The broader pipeline started
at 16:43:50 +02:00 and its terminal result must be recorded separately.

Logs under `/home/xor/.cache/`: `sum-words-final.c/.log`,
`pointer-sum-behavior-tests.log`, `msc-pointer-header-{before,after,mypy,ruff}.log`,
`msc-runtime-header-tests.log`, `pointer-memory-runtime-header-roundtrip.log`,
`pointer-sum-final-gates.log`, `pointer-sum-quality.log` and
`pointer-sum-pipeline.log`. The authoritative targeted report is
`examples/build_msc6_tiny/pointer_memory/report.json`.

Step 9 remains open. The latest pre-refresh failures are three SORTD curated
tests and `loops_jumps`/`nested_loops`; complete collection and expanded
acceptance are not refreshed. Investigate the nested-loop body replacement at
its owning layer before considering any relaxation of the GP invariant.

## Final Default-Pipeline Checkpoint

Observed terminal at 16:54:26 +02:00: preliminary 268 tests pass; curated pytest
has 4,679 passes and the same three SORTD failures in 364.72s. QuickC passes.
MS C improves to 6/7: pointer_memory remains green in the combined run, and
only loops_jumps fails. Lane wall times are 366.14s, 84.25s and 145.10s.
Make exits 2, correctly refusing overall acceptance. This is not the complete
pytest collection and does not close Step 9. No execution session remains live.

Current source inspection confirms the nested-loop callback replaces the
entire C function root, making it the next candidate for an isolated generic-
path probe. It is not yet proven to be the sole cause of nested_loops failure.
