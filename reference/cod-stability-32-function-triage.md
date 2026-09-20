# COD Stability: First 32 Functions

September 20 checkpoint after literal-identity and exact-function-extent repairs.
Artifacts: `.cache/cod-stability-exact-extent/` (inventory, per-function JSON,
generated C, stderr and hashes). Two workers, 768 MiB child limit, 30-second
function deadline. Inventory publication to summary publication:
08:23:25.498 to 08:28:23.538 +0200, approximately 298 seconds.

## Coverage And Verdicts

32 of 432 procedures attempted; 400 remain pending. The selected prefix covers
BIOSFUNC.COD, DOSFUNC.COD, EGAME0.COD and part of EGAME1.COD. It is not a random
sample or an estimate of the remaining corpus failure rate.

- CLI outcomes: 13 successful but unverified, 19 failed.
- Structured tail evidence: 16 passed, seven changed, nine uncollected.
- The 16 passed tails include three compilation failures. No original linked
  execution equivalence is established; these are normalized object fixtures.
- No extra compilation or execution oracle was run by the sweep itself.

The initial runner did not recognize the producer's `changed` status and
recorded those seven reports as invalid, preserving their full raw payloads.
The enum now includes `changed`; its new regression failed before the fix.
The counts above were recomputed from every preserved stderr report. Original
attempt records remain unchanged. A runner-digest change requires a new output
directory under the existing resume contract; do not overwrite frozen evidence.

## Ranked Failure Families

| Priority | Family | Cases | Next evidence needed |
| --- | --- | --- | --- |
| P0 | Return contract/output mismatch | `_dos_getProcessId`, `_dos_setProcessId` | Inspect binary interrupt/register effects, declared return contract and generated terminal paths; compilation rejects non-void fallthrough despite clean tail validation |
| P0 | Classified stack restores not materialized | `_dos_lastFreeBlock`, `_dos_mcbInfo`, `_dos_envSize` | Trace typed GP restore facts through the consumer; retain the fail-closed gate |
| P0 | Uninitialized or unresolved stack locals | `_drawCockpit`, `_moveStuff`, `_load3DG`, `_moveNearFar` | Distinguish input relocation/ABI limitations from lost stores and bad stack identity |
| P0 | Tail changes | `_sub_10211` (structuring), `_gfxInit` (postprocess) | Inspect typed deltas and first divergent stage; do not whitelist differences |
| P1 | Compilation declarations/types | `_dos_resize` | FILE dependency ownership and format-pointer evidence; prior stream identity and return repairs remain accepted partial work |
| P1 | Timeouts | `_dos_alloc`, EGAME0 `_main`, `_sub_11E0E`, `_load3D3`, `_load3DT`, `_strcpyFromDot`, `_otherKeyDispatch` | Group current stage/profile evidence before changing deadlines or optimizing |

The failure-family counts are 2 + 3 + 4 + 2 + 1 + 7 = 19. Priority here orders
investigation, not permission to accept any known correctness error. The next
bounded correctness cohort is the two small process-ID wrappers: they provide
a smaller reproducer for a remaining gap between clean tail status and emitted
C acceptance. Continue inventory coverage in resumable batches; do not replace
the full-corpus objective with these 32 cases.

DoD for triage: all selected attempts accounted for, original artifacts retained,
failure families linked to exact procedures, and malformed reporting distinct
from genuine validation changes. Failure: treating CLI zero as equivalence,
counting pending as passed, suppressing failed guards, or blaming unresolved
object relocations on binary decompilation without qualification.
