# X86-16 Layer Module Status

This project is an evidence-based decompiler in every layer.  A module being
present under `inertia.frontend.x86_16.public_api` does not mean it is admitted into the
production pipeline.

The source of truth is `inertia.cli.layer_module_status`:

- `PRODUCTION_WIRED`: imported by production code and allowed to affect output.
- `COMPATIBILITY_WRAPPER`: re-exports an existing owner module and must not hide
  new logic.
- `TEST_ONLY_PROTOTYPE`: tested design/prototype code. It must not affect output
  until admitted through the correct layer with evidence counters and regressions.

Current audit of the modules that previously looked unused:

| Module | Status | Owner | Note |
| --- | --- | --- | --- |
| `validation.canonicalize` | `PRODUCTION_WIRED` | validation | Validation-only canonicalizer consumed by production control-flow checks. |
| `alias.state` | `PRODUCTION_WIRED` | alias | Imported by CLI AST rewrite handoff for alias evidence. |
| `alias.domains` | `PRODUCTION_WIRED` | alias | Register-domain helpers consumed by production bridges. |
| `structuring.loop_recovery` | `TEST_ONLY_PROTOTYPE` | structuring | Natural-loop metadata prototype only. |
| `structuring.simple_loop_recovery` | `PRODUCTION_WIRED` | structuring | Focused counted-loop evidence helper. |
| `structuring.control_flow` | `COMPATIBILITY_WRAPPER` | structuring | Re-export wrapper for existing structuring stage. |
| `semantics.evidence_cache` | `PRODUCTION_WIRED` | semantics | Raw semantic access cache. |
| `postprocess.simplify` | `COMPATIBILITY_WRAPPER` | postprocess | Re-export wrapper for cleanup-only simplification. |
| `quality` | `COMPATIBILITY_WRAPPER` | diagnostics | Historical quality exports; the implementation lives in `inertia.cli.acceptance_scorecard`. |
| `postprocess.cleanup` | `COMPATIBILITY_WRAPPER` | postprocess | Reserved compatibility module with no implementation logic. |
| `lowering.segmented_lowering` | `PRODUCTION_WIRED` | lowering | Typed segmented-address classifier. |
| `ir.ir_canonicalize_8616` | `TEST_ONLY_PROTOTYPE` | IR | Local expression canonicalizer prototype only. |
| `exact_region_diagnostics` | `PRODUCTION_WIRED` | diagnostics | Function-discovery diagnostics. |

Admission rule: do not wire a prototype into production just to improve emitted
C. First identify the owning layer, add evidence counters, prove materialization,
and add regressions that preserve validation, call semantics, and recompilation.
