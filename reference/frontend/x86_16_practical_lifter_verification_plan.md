# Practical x86-16 Real-Mode Lifter Verification Plan

## Goal

Prove that the Inertia frontend correctly decodes and lifts documented 16-bit
real-mode instructions that may occur in C-compiler output or intentional MASM
assembly for the 8086, 8088, 80186, and 80286.

The result must provide strong semantic evidence without repeatedly executing
hundreds of thousands of redundant random hardware cases.

## Supported Contract

In scope:

- documented 8086, 8088, 80186, and 80286 instructions usable in real mode;
- register, flag, memory, stack, control-flow, segment, exception, and I/O
  effects observable by ordinary real-mode programs;
- all valid instruction encodings and 16-bit ModR/M addressing forms that may
  be emitted by supported C compilers or MASM;
- CPU-generation differences when they change documented, program-visible
  semantics;
- x87 as a separate optional capability when compiler or MASM corpus evidence
  shows it is required.

Out of scope:

- protected-mode-only and system-setup instructions;
- undocumented instructions such as `SALC`, `LOADALL`, and `STOREALL`;
- behavior of invalid encodings beyond deterministic decode refusal or the
  architecturally required invalid-opcode result;
- undefined flag bits and other architecturally undefined results;
- timing, prefetch queues, external bus width, electrical signals, and cycle
  accuracy;
- FS/GS, MMX, SSE, and 32-bit operand/address forms unless a later contract
  explicitly adds them.

MASM's ability to emit arbitrary bytes does not expand this contract. Only
documented instructions valid for the selected real-mode CPU profile are
required.

## CPU Profiles

Use explicit typed profiles rather than a single ambiguous `x86-16` mode:

| Profile | Required semantics |
| --- | --- |
| `I8086` | documented 8086 real-mode behavior |
| `I8088` | same programmer-visible instruction semantics as 8086; bus and timing differences excluded |
| `I80186` | 8086 behavior plus documented 80186 instruction additions and changes |
| `I80286` | 80186 behavior plus documented 80286 real-mode additions and changes |

Share one proof between profiles only when the observable semantics are known
to be identical. Keep separate expectations for defined differences such as
`PUSH SP` and generation-specific shift-count behavior.

## Oracle Priority

Choose the strongest applicable oracle per instruction family:

1. **Symbolic upstream VEX equivalence** for ordinary operations whose 16-bit
   semantics equal the corresponding upstream x86 operation after explicit
   width truncation.
2. **CPU-profile hardware/reference cases** for segmented, stack, control-flow,
   exception, I/O, repetition, and generation-specific behavior.
3. **Deterministic corner cases** where symbolic comparison is unavailable or
   would obscure architectural boundaries.
4. **Compiler and MASM corpus execution** to verify decoding and composition in
   real programs.

The 80286 `.MOO` corpus is the final oracle only for behavior that is defined
for the 80286 profile. It must not silently define 8086/8088 behavior where the
CPUs differ.

## Workstream 1: Inventory and Classification

- Generate one machine-readable manifest for every in-scope opcode/form.
- Record minimum CPU, operand form, addressing form, affected state, oracle
  class, compared fields, and undefined fields.
- Classify every form as one of:
  - `SYMBOLIC_VEX_EQUIVALENT`;
  - `CORNER_CASE_VERIFIED`;
  - `HARDWARE_PROFILE_VERIFIED`;
  - `CORPUS_COMPOSITION_VERIFIED`;
  - `OUT_OF_SCOPE_WITH_REASON`;
  - `MISSING`.
- Fail the hard gate for any in-scope form left unclassified.
- Keep decoder coverage separate from semantic coverage: one semantic proof may
  cover several encodings, but every valid encoding must still decode.

Deliverable: a generated coverage report replacing vague labels such as
`smoke`, `compare`, or `corpus` with exact proof status and CPU profile.

## Workstream 2: Symbolic VEX Equivalence

Extend the existing direct `Arch86_16` versus upstream `ArchX86` comparison
tests into symbolic proofs.

For each eligible instruction:

1. Create symbolic input registers and relevant input flags.
2. Lift the 16-bit instruction with `Arch86_16`.
3. Lift the equivalent upstream x86 instruction with explicit 16-bit operand
   semantics.
4. Normalize register aliases and explicitly truncate results to the compared
   width.
5. Compare all architecturally defined output registers and flags.
6. Ask the solver for a counterexample where the outputs differ.
7. Pass only when the formula is unsatisfiable; store a reproducible
   counterexample on failure.

Initial candidates:

- `MOV`, `XCHG`;
- `ADD`, `SUB`, `ADC`, `SBB`, `CMP`;
- `AND`, `OR`, `XOR`, `TEST`;
- `INC`, `DEC`, `NEG`, `NOT`;
- shifts and rotates after CPU-specific count normalization is modeled;
- conditional branches whose required flags already have symbolic proof.

Do not claim universal proof from a few concrete values. Existing concrete
upstream comparisons remain regressions until each family is promoted to a
symbolic proof.

## Workstream 3: Deterministic Corner Cases

Use a compact, named boundary set instead of thousands of random values.

Arithmetic values:

- `0`, `1`, `2`;
- `0x7f`, `0x80`, `0xff` for byte operations;
- `0x7fff`, `0x8000`, `0xffff` for word operations;
- equal operands and operands differing by one;
- cases producing zero, carry, borrow, signed overflow, sign, auxiliary carry,
  and parity transitions;
- carry input clear and set for carry-consuming operations.

Shift and rotate counts:

- `0`, `1`, `15`, `16`, `17`, `31`, `32`, and `33`;
- carry input clear and set for `RCL` and `RCR`;
- separate CPU-profile expectations where count handling differs.

Multiply and divide:

- zero, one, signed minimum, signed maximum, and unsigned maximum;
- fitting and overflowing results;
- divide by zero;
- signed overflow such as `-32768 / -1`.

Memory and addressing:

- every 16-bit ModR/M addressing form;
- zero, positive, and negative displacement forms;
- offsets near `0`, `0x7fff`, `0x8000`, `0xfffe`, and `0xffff`;
- default DS and SS selection plus valid CS, DS, ES, and SS overrides;
- segment wrap and exception boundaries where the selected CPU defines them.

Each corner case must state which architectural boundary it proves. Do not add
random cases without a missing-boundary justification.

## Workstream 4: Hardware Corpus Reduction

Refactor the borrowed 80286 loader so filtering is explicit and reported:

- include documented real-mode forms relevant to the `I80286` profile;
- exclude undocumented, protected-mode-only, and undefined-only forms with a
  structured reason;
- retain valid `LOCK` forms when their program-visible semantics matter;
- mask undefined flags according to corpus metadata;
- consume the upstream revocation list;
- deduplicate by semantic input, not instruction bytes alone;
- select named corner cases per instruction family and addressing class;
- retain a separately runnable exhaustive audit for diagnosing a failed family.

The regular hard gate should run symbolic proofs plus the reduced boundary set.
The exhaustive hardware corpus is a diagnostic/expanded gate, not the ordinary
development loop.

## Workstream 5: Compiler and MASM Corpus

- Compile focused source fixtures with every supported C compiler and memory
  model.
- Assemble a documented-instruction matrix with supported MASM versions.
- Extract every reachable instruction encoding from the resulting binaries.
- Require every reachable instruction to decode completely and produce valid
  VEX/typed IR without unexplained unsupported operations.
- Execute representative functions through the existing validation harness to
  catch multi-instruction flag, stack, segment, and control-flow interactions.
- Report newly observed instruction forms as manifest gaps instead of silently
  accepting them.

Compiler fixtures supplement instruction proofs; they do not replace them.

## Workstream 5A: Real-EXE Discovery and Lifter Census

### Investigation snapshot

The initial real-EXE audit used conservative Rizin `aa`, merged `aflj`
functions with direct `CALL` targets from `axlj`, and then traversed each seed
independently. This proved useful lifter coverage but is not a complete code
census.

Measured on 2026-08-08:

| EXE | `aa` merged roots | `aaa` merged roots | Current unique lifted instructions | Current audit time |
| --- | ---: | ---: | ---: | ---: |
| `VGAME.EXE` | 13 | 485 | 350 | 7 s |
| `BAILEY.EXE` | 8 | 917 | 645 | 17 s |
| `RIPTIDE.EXE` | 8 | 601 | 312 | 8 s |
| `LHX.EXE` | 291 | 1,119 | 18,775 | 213 s |
| `unp.exe` | 2 | 123 | 60 | 5 s |
| `TDIII.EXE` | 49 | 465 | 7,214 | 132 s |
| `DNPRGDRV.EXE` | 1 fallback | 14 | 68 | 5 s |

Aggressive Rizin discovery itself was not the slow component: separate `aflj`
and `axlj` runs completed in approximately 0.3–11 seconds per executable. The
largest costs came from repeated traversal and repeated lifting after starting
a fresh walk from every root.

Observed discovery failure classes:

- Rizin reports DOS MZ addresses relative to the load module while Inertia maps
  the image at `0x10000`; unnormalized offsets point at the wrong bytes.
- `aflj` may merge much of a segmented executable into one pathological
  function even when `axlj` still exposes hundreds of useful direct-call roots.
- A linear `minbound..maxbound` sweep crosses embedded data and gaps. It produced
  false `SYSENTER`, `INT1`, and 32-bit instruction reports in LHX.
- Relocated far calls may name overlay destinations whose resident file bytes
  are overlay data rather than currently loaded code. BAILEY demonstrated this
  with a `2b92:0048` target.
- Indirect jumps and jump tables terminate static traversal unless their target
  sets are recovered from typed binary evidence.
- Independent per-root walks revisit the same blocks many times. LHX visited
  4,988 blocks with duplication and TDIII visited 1,635.
- A successful block lift is not proof that the discovered bytes are code.

### Discovery contract

Build a typed multi-source root manifest. Every candidate must retain its
provenance and classification:

- MZ entry `CS:IP`;
- Rizin `aflj` function entry;
- Rizin direct-call `axlj` destination;
- decoded immediate near-call destination;
- decoded immediate far-call `segment:offset` destination;
- relocation-backed code pointer;
- MAP/LST/COD/debug function entry when available;
- recovered jump-table destination;
- overlay destination with overlay identity;
- rejected or unresolved candidate with an explicit reason.

Do not flatten `segment:offset` evidence prematurely. Canonicalize it through
the MZ load segment and preserve the source segment so aliases and overlays can
be distinguished.

Candidate verdicts must be typed:

- `RESIDENT_CODE_ROOT`;
- `OVERLAY_CODE_ROOT`;
- `INDIRECT_TARGET_SET`;
- `DUPLICATE_ALIAS`;
- `REJECTED_DATA`;
- `UNRESOLVED_KEEP`.

Rizin, CFG-based analysis, prologue scanning, and sidecars are evidence sources,
not unconditional truth. Select or merge them according to measured valid-root
yield. Keep `CFGFast` available until an evidence-backed comparison proves that
another method dominates it for each binary class.

### Aggressive discovery with validation

- Run Rizin `aaa` for the expanded/hard census because it finds substantially
  more roots than `aa` on all seven executables.
- Cache raw `aflj`, `axlj`, segment, relocation, and basic-block JSON by binary
  hash, Rizin version, command policy, and schema version.
- Invoke Rizin analysis once per binary and collect all reports from that same
  analysis session. Do not rerun `aa`/`aaa` separately for each function.
- Reject pathological `aflj` containers as function-bound evidence while still
  consuming their direct call and basic-block evidence.
- Validate each proposed resident root with mapped-image bounds, segment
  evidence, exact first-instruction decoding, and a bounded terminator path.
- Never reject a candidate merely because it lacks a conventional BP prologue;
  frameless assembly and compiler helpers are valid.
- Keep overlay targets separate from resident bytes. Do not lift the current
  file payload as though it were the overlay's runtime code.
- Report disagreements between Rizin and Inertia instead of silently choosing
  whichever backend produces more functions.

### One shared multi-root traversal

Replace independent per-function walks with one deterministic work queue:

1. Insert all validated resident roots in sorted order.
2. Lift each block address at most once per binary/source fingerprint.
3. Record every decoded instruction address once.
4. Add direct branch successors and fallthroughs.
5. Add direct call destinations to the root manifest and continue through the
   caller fallthrough.
6. Resolve jump tables only from typed memory/address evidence.
7. Record indirect exits without inventing targets.
8. Preserve segment context on every edge.

The traversal must publish:

- raw roots, normalized roots, classified roots, and materialized resident roots;
- rejected-data, overlay, duplicate, and unresolved-root counts;
- unique blocks and unique instructions;
- direct, far, indirect, and jump-table edge counts;
- decode failures, lift failures, and unresolved exits;
- per-source valid-root yield and false-positive rate.

If classified roots are nonzero and no resident roots materialize, fail the
pipeline.

### Incremental EXE cache

Use two independent caches:

1. **Discovery cache:** binary hash, MZ loader schema, relocation/overlay schema,
   Rizin version and commands, sidecar hashes, and discovery-classifier version.
2. **Lifter cache:** exact bytes, mapped address/segment context, CPU profile,
   lifter source fingerprint, pyvex/angr versions, and verifier schema.

Cache raw evidence and structured verdicts, not rendered disassembly text.
Invalidating discovery must not discard unchanged symbolic instruction-family
proofs. Invalidating one lifter family should relift only instructions decoded
to that family plus blocks whose boundaries changed.

### Fast test layout

#### Per-edit frontend gate

- Run symbolic/unit tests for changed opcode families.
- Load cached discovery manifests for the seven EXEs.
- Relift only changed instruction families and previously failing addresses.
- Always verify manifest integrity, stale-cache rejection, and zero silent
  instruction disappearance.
- Run independent binaries with at most four workers and deterministic output.

Initial warm target: at most 15 seconds for the seven-EXE frontend gate.

#### Hard frontend gate

- Use cached aggressive discovery.
- Traverse all validated resident roots once with the shared queue.
- Lift every unique resident instruction address.
- Require zero unexplained decode/lift failures and stable unresolved/overlay
  accounting.

Initial warm target: at most 60 seconds for all seven EXEs. Record per-binary
timings and fail a performance ratchet only after a stable baseline is checked
in.

#### Expanded discovery audit

- Bypass discovery caches.
- Compare `aa`, `aaa`, optional CFG-based evidence, sidecars, relocations, and
  runtime/overlay evidence.
- Minimize every backend disagreement to root address, source edge, bytes,
  segment context, and rejection reason.
- Rebuild the checked-in discovery manifest only after review.

This tier may be slow and scheduled; it must not run in the ordinary quality
loop.

### Real-EXE acceptance criteria

1. Every reported instruction belongs to at least one validated resident code
   path or an explicitly identified overlay image.
2. Every discovered direct near/far call has a classified destination.
3. Every indirect transfer is either resolved from typed evidence or reported
   unresolved.
4. No linear function-range scan crosses unclassified data.
5. Every resident instruction lifts, or the audit fails with exact bytes,
   address, segment context, source root, and exception.
6. Repeated roots do not cause repeated block lifting.
7. Warm incremental tests meet the checked-in timing budget without reducing
   instruction or root coverage.
8. Discovery coverage can only decrease with an explicit reviewed reason and a
   retained before/after manifest.

## Workstream 6: Correct Incremental Cache

The existing full-corpus success cache hashes instruction bytes and records only
successful block creation. It is not a semantic correctness cache and must not
survive relevant implementation changes.

Define a semantic cache key from:

- instruction bytes and decoded form;
- complete initial state used by the case;
- expected observable state and compared-field masks;
- CPU profile;
- lifter and semantic-owner source fingerprint;
- angr, pyvex, archinfo, and solver versions;
- verifier schema/version;
- oracle fixture hash or symbolic proof specification hash.

Cache only structured successful verdicts. A source, dependency, profile,
oracle, expected-state, or verifier change must invalidate the affected result.
Failures must always remain reproducible and must never be hidden by cache
markers.

Use family-level dependency fingerprints where practical so an unrelated
decompiler cleanup does not invalidate all instruction proofs.

## Gate Layout

### Fast gate

- manifest integrity and no unclassified newly observed forms;
- symbolic proofs for changed instruction families;
- one named boundary case per relevant semantic class;
- compiler/MASM decode smoke for cached unchanged artifacts.

Target: suitable for repeated local development.

### Hard gate

- all symbolic instruction proofs;
- complete deterministic corner-case matrix;
- every valid encoding in the compiler/MASM corpus;
- all CPU-profile difference regressions;
- semantic cache validation and stale-cache rejection.

Target: mandatory before merging lifter or instruction-semantics changes.

### Expanded diagnostic gate

- exhaustive applicable 80286 `.MOO` cases;
- broader 8086/8088/80186 reference corpora when available;
- cache bypass mode;
- per-family failure summaries and minimized counterexamples.

Target: scheduled audits and diagnosis, not every edit.

## Acceptance Criteria

The plan is complete when:

1. Every documented in-scope instruction form has an explicit CPU-profile and
   proof classification.
2. Ordinary width-equivalent operations have solver-backed equivalence proofs,
   not merely representative concrete executions.
3. Every defined CPU-generation difference has a focused regression.
4. Undefined results are masked explicitly rather than accidentally accepted.
5. Every supported compiler/MASM encoding decodes and lifts to valid IR.
6. Hardware execution is reduced to meaningful boundaries in normal gates while
   an exhaustive diagnostic mode remains available.
7. Cached success is invalidated by every relevant semantic, oracle, profile,
   dependency, or verifier change.
8. Reports distinguish decode coverage, liftability, semantic equivalence, and
   corpus composition instead of presenting any one as complete correctness.

## Implementation Order

1. Add typed CPU profiles and the machine-readable instruction manifest.
2. Correct the cache key and make stale-cache rejection testable.
3. Promote simple register ALU/move families to symbolic VEX equivalence.
4. Add the deterministic corner-case generator and CPU-difference table.
5. Refactor 80286 corpus filtering and revocation handling around the manifest.
6. Implement the cached aggressive real-EXE root manifest and shared multi-root
   traversal from Workstream 5A.
7. Build compiler/MASM encoding inventory fixtures.
8. Wire fast, hard, and expanded gates into the existing pipeline.
9. Regenerate the coverage and reference-priority documentation from the new
   proof statuses.

At each step, preserve existing regressions until the stronger replacement is
running in the mandatory gate and reports at least the same instruction forms.
