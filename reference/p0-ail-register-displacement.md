# Native Register Displacement Normalization

## Reason And Layer

The current x86-16 Clinic wrapper in `inertia_decompiler/runtime_support.py`
runs native statement/multistatement peepholes but bypasses expression
peepholes. Native SSA propagation consequently leaves long constant Add/Sub
chains in surviving register values. Re-enabling the entire expression
optimizer would also re-enable its broader cost and semantic surface.

`ir/ail_register_displacement.py` now owns a bounded bit-vector normalization:
one register base, same-width integer Add/Sub operations, and constant right
operands. Supported widths are 8, 16 and 32 bits. Constants combine modulo the
operation width; a zero displacement returns the original base atom. Calls,
memory/address bases, conversions, mixed widths and floating arithmetic refuse.
No operation is inferred from source, names or rendered C.

`ail_displacement_compat.py` runs this IR pass before native post-SSA level-one
simplification and again afterward for newly exposed chains. Changed graphs
invalidate cached reaching definitions. Other architectures delegate unchanged;
installation is idempotent. The adapter is installed by `compat.py`, not CLI
or Rewrite. It introduces no stack ownership or statement-deletion rule.

The native simplifier can now eliminate redundant assignments using the
normalized values. Nonzero stack effects remain visible for later ownership
and liveness work.

## Rejected Probe And Atom Identity

The first temporary normalizer reused a binary-expression atom ID for its new
constant. Three numeric SP writes then acquired incorrect address-valued
bindings and failed strict C compilation (`&ic_* & 0xffff`). Restricting the
probe to register bases alone did not fix that failure. A 323-call propagation
observation did not establish the suspected direct address-of replacement
bypass; do not install such a guard from this experiment.

Allocating fresh expression and constant atoms through the native AIL manager
resolved the failure. Production always allocates distinct fresh atoms for a
nonzero result and retains the original source tags. Zero-displacement results
retain the base atom. Explicit regression assertions guard this obligation.
The failed probes were not installed or accepted as successful decompilation.

## Acceptance

DoD: prove equality for all bit-vector inputs in the tested 8/16/32-bit
Add/Sub combinations; retain unsupported chains; preserve base/destination
atoms and CFG edges; allocate collision-free new atoms; invalidate changed
native reaching definitions; retain a closed fold census; pass routine tests,
scoped typing/linters, strict generated-C compilation and whole-tail validation
with no call or argument-class loss.

Definition of failure: arithmetic across a width/conversion boundary, floating
reassociation, call duplication/loss, stale atom bindings, altered CFG,
semantic recovery in CLI/Rewrite, or declaring nonzero stack effects dead
without independent ownership and complete live-use evidence.

The no-op baseline failed 36 mathematical regressions and passed seven refusal
cases (8.08 seconds). The initial implemented run passed the symbolic equality
checks but exposed a fixture mistake: rebuilding a Rust-backed native AIL node
may return new Python wrappers. Tests now check atom IDs and structural
identity rather than Python wrapper identity. The corrected 43 cases pass in
8.16 seconds. Two additional native-stage tests cover both normalization phases,
cache invalidation, architecture delegation and idempotent installation.
All 45 tests are admitted to routine selection.

The unchanged InitMenu acceptance test still fails its bookkeeping assertion:
45 tests passed and one failed, seven warnings, 49.67 seconds total
(40.81 seconds InitMenu). Its behavior harness after that assertion remains
unexecuted. Scoped Ruff `check --fix`, MyPy and Pyright pass; no type/doc bypass
was added. Native walker composition avoids inheriting from an untyped base.

## Live Result

InitMenu's two phase reports are respectively:

- raw=119, normalized=44, classified=44, materialized=44, failure=75;
- raw=77, normalized=2, classified=2, materialized=2, failure=75.

The failures here are retained unsupported arithmetic candidates, not deleted
code. They overlap across phases and must not be summed as distinct defects.
Each accepted fact records input atom indices, output atom, width and modular
displacement. Materialization counts mean arithmetic folds, not removed
statements or consumed argument effects.

Six of nine SP assignments disappear through native simplification. The three
remaining updates reduce to `BP - 4`, `SP - 8`, and `SP - 4`, each retaining the
proper low-word mask and upper ESP preservation. The separate BP frame setup
remains. All 18 observed callsite inventories are identical to the before run,
including logical widths and physical PUSH sources. Calls remain consistent
with the existing source comparison; no source-specific rule was introduced.

The live CLI exits zero, reports `validation=passed`, clean whole-tail
validation and passes its strict portable-C compilation gate. Generated C
SHA-256 is `3ddd2bf375cc778c4a1cfa8798a367901545aed6548b81f9203575ccfada7b8d`.
It is byte-identical to the successful fresh-atom probe. This is a measurable
output-quality improvement, not complete InitMenu acceptance or proof of
end-to-end DOS execution equivalence.

Both `make quality-fast` and `make test-pipeline` exited zero. Fast passed
3,387 tests in 141.31 seconds with eight warnings; default passed 3,387 tests
in 125.46 seconds with seven warnings. All three executable quality guards
passed. QuickC passed in 45.917 seconds; all seven MS C tiny full roundtrips
passed with return code zero in a 62.659-second lane. The default unit lane
remains over its configured budget (125.889 seconds including overhead).
This is routine-pipeline evidence, not a full-repository test pass.

The slowest fast tests were RunMenu Escape (58.59 seconds), InitBars stack-array
recovery (56.11 seconds), and indexed-address parity inventory (36.23 seconds).
The known threaded-fork warning remains visible alongside dependency warnings.
No speedup claim is made; this was not a controlled performance experiment.
Final `git diff --check` passed.

## Next Work And Timing

The reduced expressions make the remaining obligations smaller to inspect:
frame setup/restoration, callee-cleaned argument effects, and the final caller
cleanup. Classify each from exact binary/IR evidence before assigning ownership;
the arithmetic constants alone do not prove those roles. Preserve explicit
32-bit register observations and unknown cases.

The failed first probe ended at 05:28:36 CEST on 2026-09-10. The successful
fresh-atom output was written at 05:36:04. Production typing and focused tests
were observed by 05:43:58; original investigation start was not captured.
These anchors are not a remaining-plan ETA or a complete active-time account.
Final gate exit and structured roundtrip results were verified at 05:54:13 CEST.
The normalization checkpoint is verified; complete InitMenu acceptance and
the full plan remain open.

Logs: `/tmp/inertia-ail-displacement-{before,after-final,acceptance,live,ruff-final,mypy-final,pyright-final,gates}.log`.
Rejected probe: `/tmp/inertia-ail-displacement-probe.{c,log}`. Successful probe:
`/tmp/inertia-ail-fresh-atoms.{c,log}`. No temporary observer is production code.
