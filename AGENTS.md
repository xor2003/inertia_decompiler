# Inertia Decompiler

## Mission

Inertia is an angr-based decompiler for 16/32-bit x86 real-mode binaries.

The goal is:

- human-readable, evidence-driven C
- correctness first
- readability second
- recompilable output where practical

The goal is not:

- a transpiler
- source-shaped guessing
- a pile of sample-specific rewrites

Project overview, usage, platform map, and status live in [`README.md`](/home/xor/vextest/README.md). This file is for agent operating rules only.

## Core model

All decompiler changes must respect:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

Interpretation:

- `IR`: normalized lifted input
- `Alias model`: storage identity
- `Widening`: proven-safe joins of narrow pieces
- `Traits`: evidence only
- `Types`: downstream object/type decisions from stable evidence
- `Rewrite`: final cleanup only

Current x86-16 shape also includes:

- `control-flow structuring` as an explicit stage
- `confidence/assumption` reporting as first-class output

## Hard rules

### Solve problems at the earliest correct layer

- Do not solve aliasing in late rewrite.
- Do not solve widening by final expression shape alone.
- Do not guess structs, arrays, or helpers before evidence is stable.
- Do not use naming as a substitute for recovery.

### Correctness over prettiness

If evidence is weak, prefer:

- ugly but honest output
- explicit segmented arithmetic
- explicit temporaries
- conservative types

Do not prefer:

- guessed structs
- guessed arrays
- guessed pointer lowering
- guessed helper signatures
- guessed high-level intent

### Alias-first

Before adding any join or simplification rule, ask whether the issue is actually storage identity.

Required behavior:

- storage identity comes from the alias model
- register slices, stack slots, and segmented memory are modeled as storage
- widening happens only after alias compatibility is proven

Forbidden shortcuts:

- no AL/AH/AX joins from shape alone
- no adjacent stack-byte folding without alias proof
- no segmented-pointer lowering before stable association is proven

### Traits are evidence only

Traits may:

- annotate
- classify
- score
- build profiles

Traits may not:

- invent structs directly
- invent arrays directly
- rename things as if recovery were complete

### Segmented-memory discipline

Real mode is not one flat pointer space.

Required behavior:

- treat `ss`, `ds`, and `es` as distinct spaces
- keep stable association separate from over-associated cases
- lower to pointer/object form only when evidence is strong

Forbidden behavior:

- do not flatten segmented memory for convenience
- do not merge segment spaces by default
- do not treat a familiar segmented expression as object-like without proof

### Rewrite boundary

Late rewrite is for final cleanup only.

Allowed:

- algebraic cleanup
- boolean normalization
- declaration cleanup
- naming polish
- final structured C cleanup

Not allowed:

- alias reasoning
- widening reasoning
- storage identity
- object inference
- prototype inference

### Validation boundary

When adding semantic validation for decompiler quality, start above `VEX` and below final generated `C`.

Preferred first boundary:

- compare whole-tail x86-16 structured-codegen effects before and after late `structuring`/`postprocess`
- validate end-to-end late-pipeline behavior before splitting into per-pass proofs
- use lower-layer `VEX` equivalence only for lift/IR correctness, not as the default validator for late cleanup passes

What to compare first:

- helper calls
- live-out register effects
- observable stack/global/segmented memory writes
- return values
- control-flow exits and guards

What to ignore first:

- temporary names
- dead internal rewrites
- non-live flag churn
- formatting or declaration-only cleanup

Default policy:

- prefer `live_out`-aware whole-tail validation over raw shape comparison
- only escalate to per-pass validation or SMT when whole-tail checks find a real semantic delta or when a pass is known to be risky

## Direction of travel

A change is good if it:

- explains several wins with one general mechanism
- reduces special cases
- improves real corpus outputs
- stays conservative when evidence is weak

A change is bad if it:

- fixes one sample with one more rewrite
- adds allowlists before trying alias/widening/evidence
- makes output prettier by guessing unsupported semantics
- hides debt inside postprocess cleanup

Before merging a fix, ask:

- Is this solving the problem at the correct layer, or only hiding it later?

## Corpus-first policy

Use the real target corpus.

Required workflow:

- use bounded scan-safe corpus runs
- use focused regression cases
- use golden readability anchors where available
- use existing x86-16 tests and sample matrix

Before merging a nontrivial change, check:

- did it help a real corpus case?
- did it regress any existing case?
- did it increase crashes or timeouts?
- did it reduce or increase special-case logic?

### Scan-safe lane

`scan-safe` favors robustness over prettiness.

Rules:

- risky beautification must not be on by default there
- experimental quality passes must stay out of the default scan-safe lane
- every crash or timeout must remain classifiable

## Failure reporting rules

- If lifting breaks, report the first known failing address when possible and dump assembly around it.
- If structured decompilation times out or returns empty, try a non-optimized decompilation fallback before dropping to raw assembly.
- If helper files are absent, say so explicitly and keep going with raw recovery plus fast seed heuristics.
- Prefer local `.pat` evidence when available; if only OMF `.obj`/`.lib` inputs exist, generate deterministic `.pat` files locally before giving up on FLAIR-style matching.
- Record fallback mode honestly in output; do not silently replace failures with guessed high-level C.

## One-off rescues

Special rewrites, allowlists, or source-backed rescues are allowed only if:

- they protect an important real corpus case
- they are clearly temporary
- they do not block replacement by a general architectural layer

Required follow-up:

- replace with alias/widening/types architecture
- keep only as oracle/regression support if still useful
- remove when general recovery exists

## Testing and profiling

Every change should add the smallest useful test at the right level.

Prefer:

- unit test for the new rule/layer
- focused corpus-backed test
- scan-safe sanity check

Architecture-specific expectations:

- alias changes: test domains, views, state
- widening changes: test allowed and forbidden joins
- segmented association: test stable vs over-associated behavior
- object/type recovery: test evidence-driven corpus outcomes

When memory or runtime grows:

1. reproduce on the smallest real corpus subset or PROC
2. confirm RSS growth with `/proc`, `ps`, or `/usr/bin/time -v`
3. use `memray run --native` on the exact repro once growth is real
4. compare before/after on the same target

Keep the repro, peak RSS, and top allocators tied to the fix.

## Harness rules

The meta harness respects the root-level `STOP` file. If `STOP` exists, `./run.sh` stops before advancing the cycle.

Repo-root Python one-liners launched with `python -c` or `python -` are memory-capped by [`sitecustomize.py`](/home/xor/vextest/sitecustomize.py).

`PLAN.md` rules:

- keep it as a flat numbered checklist
- each item must include target files, source line numbers when known, concrete functions/tests/scripts, and a deterministic definition of done
- preserve unfinished strategic items unless they are done or clearly superseded by a more precise replacement

Resume rules:

- `--resume` continues from the first unfinished step in the latest incomplete cycle
- `done-with-failures` counts as completed for sweep-step resume
- `--fresh` starts a new cycle

Token-efficiency defaults:

- prefer compact prompts
- prefer short continuation prompts on `codex resume`
- use `gpt-5.4-mini` by default for planner/checker/worker/reviewer unless a stronger model is justified

## Coding discipline

- Keep modules focused and small.
- Split mixed-responsibility files before adding more logic.
- Prefer SRP over convenience.
- Avoid hidden coupling and global state.
- Keep data flow explicit.
- Add comments only when they genuinely clarify non-obvious logic.

## Useful references

- Project overview and usage: [`README.md`](/home/xor/vextest/README.md)
- Main long-term roadmap: [`angr_platforms/docs/dream_decompiler_execution_plan.md`](/home/xor/vextest/angr_platforms/docs/dream_decompiler_execution_plan.md)
- Current working plan: [`PLAN.md`](/home/xor/vextest/PLAN.md)
- Meta harness usage: [`meta_harness/README.md`](/home/xor/vextest/meta_harness/README.md)
