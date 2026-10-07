# DOS Unit Tool Gap-Closure Plan

## Current Working Baseline

`./dosunit.py` is the root CLI.

Implemented now:

- function discovery from MZRE-style `.map` and IDA `.lst`
- segment catalog import from `.map`
- entry-vector generation with deterministic Z3-backed register seeds
- libdosbox aggregate trace import for priorities/access ranges
- real `record-oracle --backend libkvikdos` for MZ `.EXE` vectors with concrete `CS:IP`
- in-process KVM execution through a generated wrapper around `/home/xor/kvikdos/kvikdos.c`
- near/far return capture, register/segment/flag observation, and declared memory observation
- explicit `dosunit.mapping.v1` candidate mapping for `compare`
- segmented `CS`/`DS`/`ES`/`SS` pre-memory and observe-memory ranges
- loaded-MZ `compare-data` for data-segment byte baselines, including
  relocation application, zero-filled tail/BSS synthesis, segment-name mapping,
  and exact-symbol near code-pointer normalization
- original-side direct `cmp`/`test` edge-vector generation with lazy condition
  lowering, coverage metadata, Z3-backed register/register predicates, and
  typed refusals for unsupported memory/control-flow
- fixture backend for deterministic comparison tests

The working backend is not the final architecture yet. It generates a small MZ
harness per vector and executes that through a reusable in-process KVM wrapper.
That proves the oracle path is real, but it does not yet expose the full
standalone `libkvikdos` snapshot/restore API described in
`reference/dosunit-execution-spec.md`.

## Gap 1: Extract Stable `libkvikdos`

Problem: `dosunit` currently compiles a wrapper that includes `kvikdos.c`
directly. It exposes a small `dosvm_create` / `dosvm_destroy` /
`dosvm_run_program` surface for batched in-process runs, but the API is not
packaged as a stable library yet.

Plan:

1. Split `/home/xor/kvikdos/kvikdos.c` into CLI and library-owned units.
2. Expose `dosvm_create`, `dosvm_load_program`, `dosvm_snapshot_create`,
   `dosvm_snapshot_restore`, `dosvm_set_regs`, `dosvm_get_regs`,
   `dosvm_read_memory`, `dosvm_write_memory`, and `dosvm_run_until_trap`.
3. Keep the existing `kvikdos` executable as a thin wrapper.
4. Replace the generated include-wrapper in `tools/dosunit/runtime/kvikdos_backend.py`
   with `ctypes` or `cffi` bindings to the stable library.

Definition of done:

- one KVM VM is initialized per `dosunit` session
- one program load creates a reusable baseline snapshot
- recording 100 vectors does not spawn 100 OS processes
- focused C tests cover create/load/snapshot/restore/trap
- Python tests run the same vector set through the library backend twice and
  produce byte-identical results

## Gap 2: Batch Vectors Against One Loaded Program

Problem: current real backend reuses one in-process KVM handle for a batch, but
it still executes generated harnesses and reloads a harness image per vector.

Plan:

1. Use the stable snapshot API from Gap 1.
2. Load the original program once.
3. Restore baseline before each vector.
4. Apply vector pre-state directly to registers and guest memory.
5. Install near/far return traps without code-cave requirements when possible.

Definition of done:

- `record-oracle` accepts a vector file with mixed near/far functions and runs
  it in one backend session
- per-vector result includes trap kind, timeout/fault status, and observed fields
- near functions no longer require a same-CS code cave when the backend can trap
  return addresses directly

## Gap 3: Real VEX/AIL/Z3 Path Vectors

Problem: `gen-vectors --strategy entry` produces valid entry seeds, and
`edge` now handles local direct original-side `cmp`/`test` branch predicates.
General VEX/AIL path constraints, `hot`, loop unrolling, symbolic memory, and
`manual_seed` are still not materialized.

Plan:

1. Lift function blocks through the existing x86-16 VEX/IR path.
2. Convert register, flag, stack, and segmented-memory reads into typed SSA.
3. Emit bounded path predicates and memory requirements.
4. Solve concrete vector inputs with Z3.
5. Use Sympy only for algebraic simplification where it preserves typed
   segmented-memory facts.

Definition of done:

- local direct-branch fixtures produce taken/fallthrough edge-covering vectors
- generated vector assumptions list every bounded memory and call constraint
- unsupported dirty helpers, indirect jumps, unbounded memory, and DOS/device
  effects produce typed refusals
- counters report attempted paths, solved paths, emitted vectors, refusals, and
  solver time

## Gap 4: libdosbox Per-Call Snapshot Import

Problem: current libdosbox import handles aggregate runtime JSON. It can
prioritize hot functions and access ranges, but cannot yet produce replayable
entry/exit vectors.

Plan:

1. Add optional function-entry hooks in `/home/xor/inertia_player/libdosbox`.
2. Record `CS:IP`, `SS:SP`, regs, sregs, flags, stack window, selected memory,
   and call depth.
3. Record exit state and written memory ranges at return traps.
4. Import snapshots as `source.kind=runtime` vectors.

Definition of done:

- one gameplay trace imports at least one replayable vector
- imported vectors replay through `record-oracle --backend libkvikdos`
- aggregate-only traces still import as priorities with `oracle_unavailable`
  refusals
- `m2c::m` remains backed by live DOSBox guest memory

## Gap 5: Candidate Mapping Coverage For C And ASM Outputs

Problem: `make-mapping` now emits `dosunit.mapping.v1` from original and
candidate function catalogs by function name, and `compare --mapping` consumes
it. The remaining work is broader coverage for reassembled ASM and compiled C
outputs whose public names, calling boundaries, or return kinds do not match
one-to-one.

Plan:

1. Extend `dosunit.mapping.v1` with ABI notes when a candidate has intentional
   calling-convention or return-kind changes.
2. Add optional map/listing-driven aliases for rebuilt C/ASM names that do not
   exactly match original names.
3. Support same-layout ASM, reassembled ASM, and compiled C candidates.
4. Keep ambiguous or missing mappings as typed verdicts instead of falling back
   to guessed addresses.

Definition of done:

- original-vs-original comparison passes for a selected corpus subset
- original-vs-reassembled-ASM comparison uses mapping instead of original entry
  addresses
- missing and ambiguous mappings are visible in result summaries

## Gap 6: Memory Diff And Stack-Window Coverage

Problem: current backend supports concrete `SEG`, `LINEAR`, `CS`, `DS`, `ES`,
and `SS` pre-memory and observation ranges, including automatic `DGROUP`
selection for rebuilt linker maps. `compare-data` now handles loaded-image data
baselines and normalizes code-pointer fields such as `off_389E8` without
forcing original bytes. The remaining runtime gap is deterministic bounded
write diffs and a higher-level way to declare stack windows such as
`SS:BP+offset`.

Plan:

1. Normalize any remaining symbolic vector memory spaces through catalog segment
   metadata.
2. Add `SS:BP+offset` stack-window syntax in vector manifests without flattening
   it before backend execution.
3. Track stack return slots separately from user-requested stack bytes.
4. Add deterministic, bounded memory-diff collection for declared write ranges.

Definition of done:

- vectors can declare `SS:BP+offset` stack windows without flattening them in
  the manifest
- output reports segmented addresses and only linearizes at backend boundaries
- memory diff output is deterministic and bounded

## Gap 7: Corpus And CI Closure

Problem: the unit tool has focused tests and a real smoke, but not a stable
corpus gate.

Plan:

1. Add tiny MZ near/far fixture binaries generated by tests.
2. Add a small F-15 subset manifest with known-safe pure functions.
3. Run discovery, vector generation, oracle recording, compare, and summarize
   in CI when `/dev/kvm` is available.
4. Keep KVM tests skipped with explicit reason when unavailable.

Definition of done:

- `pytest -q tools/dosunit/tests/test_dosunit_tool.py` passes with and without
  `/dev/kvm`
- a KVM-enabled run exercises real `libkvikdos` oracle recording
- summary output distinguishes passed, failed, refused, faulted, and timeout
  statuses
