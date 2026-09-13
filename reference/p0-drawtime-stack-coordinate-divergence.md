# DrawTime Stack Coordinate Divergence

## Verified Status

On 2026-09-13, both the default direct-address command and the former explicit
`--window 0xc2` regression fail for sidecar-free DrawTime, address `0x10498`.
The existing explicit-window regression failed in 27.51 seconds. The routine
pipeline previously selected only three SORTD live regressions, excluding this
test. Its earlier green result did not cover DrawTime; no stale-cache explanation
has been established.

The executable images of SORTD.EXE and SORTDEMO.EXE are byte-identical after
stripping the overlay (26,432 bytes).

## Evidence

GP restore lowering receives two proven Alias obligations:

- SI restore at `0x1054e`: entry-SP bytes `(-86, -85)`.
- DI restore at `0x1054f`: entry-SP bytes `(-84, -83)`.

Live C-AST inspection finds corresponding runtime register assignments with
the correct instruction tags, but their stack-variable coordinates resolve to
`(-94, -93)` and `(-92, -91)`. This is an eight-byte divergence, not an absent
restore expression. Snapshot insertion succeeds; replacement matching refuses
both incorrect coordinate pairs. The hard materialization gate must remain.

Logs: `/home/xor/.cache/step9-drawtime-{current,gp,allpairs,window}.log`.
Focused GP diagnostic tests: 3 passed in 14.87 seconds; scoped MyPy passes.
Legacy complexity/magic-value Ruff findings remain in the touched GP module.

## Next Action And Acceptance

Trace the first divergence between machine entry-SP facts, angr stack tracking,
AIL storage variables and Lowering coordinate publication. Callee cleanup is a
hypothesis to inspect, not an established cause. Do not add an eight-byte offset
correction or weaken matching in GP restore lowering.

The existing DrawTime regression now exercises the default path and is enrolled
in the routine pipeline. It remains a known failing acceptance requirement.
Completion requires passed semantic/whole-tail validation, the original clock,
delay and Beep argument contracts, and coherent saved-register storage.
Failure includes any guessed coordinate adjustment, hidden materialization
failure, removed live restore, or passing only the explicit-window variant.
