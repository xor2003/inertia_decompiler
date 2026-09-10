# Strict C Operator Grouping

## Reason And Owner

InitMenu generated C failed `gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only`
with 20 parenthesis diagnostics. The C expression tree was already grouped,
but native rendering omitted parentheses that are optional for precedence and
required for warning-clean mixed arithmetic/bitwise expressions.

`X86_16/codegen_parentheses.py` installs an architecture-scoped rendering policy
through the existing compatibility bootstrap. It only emits grouping tokens
with native closing-object/source-node associations. It does not change AST
nodes, operand order, types, register widths, calls or memory effects. This is
formatting ownership, not semantic repair in postprocess or CLI.

The policy covers mixed bitwise operands, additive shift operands and logical
AND under logical OR in the native common binary renderer. Native precedence
grouping is retained; other architectures delegate unchanged. This is not a
claim that every separate native custom renderer is covered.

## Acceptance

DoD: strict compiler regressions on both operand sides pass; repeated
installation is idempotent; unrelated architecture rendering is unchanged;
InitMenu passes strict compilation and tail validation; scoped types/linters
and routine gates pass. Definition of failure: suppress compiler warnings,
rewrite rendered text, change expression meaning or remove stack effects to
make the compiler accept the output.

The first 14 mixed-operator cases failed before the patch. Two also exposed
GCC's unrelated `xor-used-as-pow` diagnostic for literal `2 ^ 1`; their test
operand was changed to 7 without disabling either compiler warning. All 14
then passed. Two installation/delegation cases bring routine admission to 16.
The unchanged InitMenu acceptance case still fails its bookkeeping assertion
at line 1663 after its preceding validation and call checks pass: final focused
run 16 passed, one failed, seven warnings, 47.39 seconds (39.46 seconds in the
function). Its behavior harness after that assertion was not reached.

The final after-probe has validation=passed, clean whole-tail validation and
zero strict-GCC errors. SHA-256:
`4a41e50d2e9dd5a85c438df8fee336b5c679ccfe28483c2677cacb87ca01ae3f`.
Scoped Ruff, production MyPy and Pyright on production/new tests pass.

The first fast gate passed 3,272 tests and failed the InitBars test's exact
old unparenthesized pause-store spelling. Only that expected spelling changed;
the array, pause-store value/high-word clearing, call and validation checks
remain intact. The renderer tests also check constant expression values with
C static assertions. Final focused rerun: 17 passed, seven warnings, 9.09s.
The combined routine gates were restarted on the final tests and exited zero:
fast passes 3,273 tests in 113.77 seconds; default passes 3,273 in 122.20 seconds
pytest / 122.624 seconds lane (seven warnings in each run). All three executable
quality guards pass. QuickC passes in 46.199 seconds and all seven MS C tiny
full roundtrips pass in 60.672 seconds, each with return code zero. The default
unit lane remains over budget. No full-repository audit is claimed.

An additional Pyright audit of the legacy SORTDEMO regression module reports
11 diagnostics outside the changed assertion: three unresolved test-helper
imports and eight operations on telemetry objects lacking type narrowing.
These were not suppressed or included in the clean production/new-test claim.
The [test-telemetry follow-up](p0-test-telemetry-typing.md) resolves all 11;
the original audit log remains `/tmp/inertia-parentheses-final-pyright.log`.
The generated-output cache fingerprints all production X86_16 modules, so the
new renderer participates in invalidation without a special cache-key rule.

Artifacts: `/tmp/inertia-parentheses-{before,after,acceptance,pyright}.log`,
`/tmp/inertia-parentheses-final-initmenu.{c,log}`,
`/tmp/inertia-parentheses-initbars.log` and
`/tmp/inertia-parentheses-final-gates.log`.
The separate return-segment tracker experiment was not installed; see
[the tracker investigation](p0-native-stack-tracker-width.md).

Timing anchors (2026-09-10 CEST): the initial compiler regression run ended at
03:03:05; the first fast-gate failure was recorded by 03:12:45. Final combined
gates started at 03:15:02, last wrote their log at 03:21:51, and terminal exit
zero was verified by 03:22:18 (7m16s observation window). These include waiting
and do not measure total active coding time or predict the remaining goal.
