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

Always prefer correctness, stable evidence, and honest output over prettier C or faster apparent progress.

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
- Do not recover semantics from textual matches over rendered assembly or rendered C.
- Do not use substring, regex, or line-text checks over disassembly text as semantic proof.

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

### No oracle cheating

Recovery must be derived from internal program evidence, not from external hints that merely look correlated.

Forbidden as semantic proof:

- sample-specific address ranges
- symbol-name families
- compiler/runtime/library name matches
- corpus-specific allowlists or deny-lists
- string or regex matches over rendered assembly, rendered C, logs, or diagnostics
- matching on emitted text instead of typed program state
- "known sample" substitutions that skip recovery
- replacing timeout/failure with guessed helper C because the pattern "looks familiar"
- using validation diffs themselves as proof of the missing semantics

Allowed only as temporary debugging aids, never as recovery logic:

- log messages
- pretty-printed assembly
- pretty-printed C
- corpus notes
- manual sample annotations

If a rule cannot be explained in terms of decoded instructions, CFG shape, lifted IR, alias state, typed pattern objects, or another structured intermediate representation, it is not an acceptable recovery rule.

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

### Tail validation is a semantic guardrail

Required behavior:

- preserve `changed`, `unknown`, and `uncollected` identities in reports
- keep timeout/fallback PROC identities attributable in aggregate outputs
- treat whole-tail observable deltas as a reason to localize, not a reason to soften validation

Forbidden behavior:

- do not drop timeout/fallback items from corpus summaries
- do not present validation as passed when it was skipped or uncollected
- do not use raw text-shape similarity as the primary semantic validator

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
- did it preserve honest attribution for failures and uncollected results?

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
- If validation is `changed`, `unknown`, or `uncollected`, report that state honestly rather than collapsing it into success.
- Any fallback that emits C must be driven by structured evidence from recovered instructions, CFG, lifted IR, alias/type state, or another typed intermediate representation.
- Pretty-printed assembly is diagnostic output only. It must not be the matching substrate for semantic recovery.

## Honesty over heroics

Prefer:

- explicit fallback mode
- explicit uncertainty
- ugly but truthful output
- attributable corpus accounting

Do not:

- silently replace failure with guessed high-level C
- treat uncollected work as if it disappeared
- collapse uncertainty into fake confidence

## One-off rescues

Special rewrites, allowlists, or source-backed rescues are allowed only if:

- they protect an important real corpus case
- they are clearly temporary
- they do not block replacement by a general architectural layer
- they are reported explicitly as temporary rescue logic rather than normal recovery

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
3. use `cProfile`/`pstats` for Python call hot spots and `line_profiler` for focused line-level hot paths
4. use `memray run --native` on the exact repro once growth is real
5. use `py-spy record`/`py-spy dump` for live hangs or runaway processes when ptrace/toolchain support allows it
6. compare before/after on the same target

Keep the repro, peak RSS, and top allocators tied to the fix.

If these profiling tools are missing from the active environment, install them into the active virtualenv and continue:
`python -m pip install line_profiler memray py-spy`.
Prefer invoking profilers through the active interpreter or virtualenv, e.g. `python -m cProfile`,
`python -m memray`, or `.venv/bin/py-spy`, so the profiling run uses the same dependencies as the repro.

## Determinism and reporting

Prefer:

- deterministic ranking, grouping, and report ordering where possible
- reproducible artifact generation
- enough metadata to trace summaries back to exact inputs

Avoid:

- non-deterministic ordering in summaries
- reports that depend on prior skipped runs
- output that cannot be explained later from stored metadata

## Harness rules

The meta harness respects the root-level `STOP` file. If `STOP` exists, `./run.sh` stops before advancing the cycle.

Repo-root Python one-liners launched with `python -c` or `python -` are memory-capped by [`sitecustomize.py`](/home/xor/vextest/sitecustomize.py).

`PLAN.md` rules:

- keep it as a flat numbered checklist
- each item must include target files, source line numbers when known, concrete functions/tests/scripts, and a deterministic definition of done
- preserve unfinished strategic items unless they are done or clearly superseded by a more precise replacement

Plan layering rules:

- keep `PLAN.md` and `PLAN2.md` for active execution checklists
- keep `DEMO.md` for the repeatable external-facing demo story and artifacts
- keep `GLOBAL_PLAN.md` for long-horizon architectural phases and milestone criteria
- do not replace an execution checklist with vague strategic prose

Resume rules:

- `--resume` continues from the first unfinished step in the latest incomplete cycle
- `done-with-failures` counts as completed for sweep-step resume
- `--fresh` starts a new cycle

Token-efficiency defaults:

- prefer compact prompts
- prefer short continuation prompts on `codex resume`
- use `gpt-5.4-mini` by default for planner/checker/worker/reviewer unless a stronger model is justified

## Review checklist

Before merging a nontrivial change, answer:

1. What architectural layer does this belong to?
2. Why is that the earliest correct layer?
3. What exact family or invariant does it fix?
4. What test proves the fix?
5. What corpus result improved?
6. What existing case might regress?
7. Is this architectural or a temporary rescue?
8. If temporary, what will replace it?

If those answers are weak, do not merge.

## Anti-patterns to avoid

Never do these unless explicitly marked as a temporary rescue:

- sample-specific address hacks
- symbol-name hacks used as semantic proof
- shape-only widening
- flatten-segment-for-convenience logic
- guessed structs, arrays, or helpers
- rewrite-stage semantic repairs for alias/widening/type problems
- silent fallback presented as success
- corpus summaries that drop missing work items
- semantic recovery via `if "...substring..." in asm_text`
- semantic recovery via regexes over rendered assembly lines
- semantic recovery from decompiler text output instead of structured program state
- corpus-specific semantic allowlists
- address-specific helper substitution presented as general recovery
- name-based helper substitution presented as recovered semantics
- using debug output as the decision substrate for recovery

## Coding discipline

- Keep modules focused and small.
- Split mixed-responsibility files before adding more logic.
- Prefer SRP over convenience.
- It is forbidden to add any code to file bigger when 400 lines.
For example to inertia_decompiler/cli.py and ./angr_platforms/tests/test_x86_16_cli.py.
- Avoid hidden coupling and global state.
- Keep data flow explicit.

### Comments
- Prefer self-documenting code (clear names)
- Write why, not what
- Use docstrings for public functions/classes
- Document edge cases, hacks, constraints
- Avoid obvious / redundant comments

### Typing
- Always type public APIs
- Use dataclass / TypedDict instead of raw dicts
- Prefer concrete types over Any
- Use Optional (X | None) explicitly
- Create type aliases for complex types
- Use Protocol for interfaces

## Useful references

- Project overview and usage: [`README.md`](/home/xor/vextest/README.md)
- Main long-term roadmap: [`angr_platforms/docs/dream_decompiler_execution_plan.md`](/home/xor/vextest/angr_platforms/docs/dream_decompiler_execution_plan.md)
- Current working plan: [`PLAN.md`](/home/xor/vextest/PLAN.md)
- Secondary active execution plan: [`PLAN2.md`](/home/xor/vextest/PLAN2.md)
- Demo plan: [`DEMO.md`](/home/xor/vextest/DEMO.md)
- Long-horizon architectural plan: [`GLOBAL_PLAN.md`](/home/xor/vextest/GLOBAL_PLAN.md)
- Meta harness usage: [`meta_harness/README.md`](/home/xor/vextest/meta_harness/README.md)

Act autonomously. Do not ask for permission or clarification if the next step is logically clear. Proceed with the implementation until the task is complete.
Provide full, production-ready code. Do not use placeholders, comments like 'insert logic here', or truncated snippets. Complete the entire file.
Identify, analyze, and fix the issue in one go. If you encounter a minor ambiguity, make an educated guess based on the existing codebase and proceed.
Be hyper-concise. No preamble/outro. Direct answers only. Use shorthand. Don't ask to continue—just finish.
