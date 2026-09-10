#!/usr/bin/env python3
"""Static architecture guard for decompiler ownership and agent contracts.

Layer: Tooling/gates.
Responsibility: enforce decompiler architecture, documentation, and ownership ratchets.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from .makefile_inventory import makefile_variable_words as _makefile_variable_words
    from .pytest_source_index import load_pytest_source_index
else:
    from makefile_inventory import makefile_variable_words as _makefile_variable_words
    from pytest_source_index import load_pytest_source_index

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
X86_16_ROOT: Path = REPO_ROOT / "angr_platforms" / "angr_platforms" / "X86_16"
CLI_DECOMPILATION: Path = REPO_ROOT / "inertia_decompiler" / "cli_decompilation.py"
AGENTS_MD: Path = REPO_ROOT / "AGENTS.md"
PROJECT_MAP: Path = REPO_ROOT / "reference" / "project-map.md"
AGENT_RULES: Path = REPO_ROOT / "reference" / "agent-rules.md"
UNDERSTAND_CONFIG: Path = REPO_ROOT / ".understand-anything" / "config.json"

_PROTECTED_IMPORT_PREFIXES = (
    ".lift_86_16",
    ".semantics",
    ".alias",
    ".widening",
    ".widening_alias",
    ".widening_model",
    ".structuring",
    ".lowering",
    ".cod_extract",
)

_POSTPROCESS_LEGACY_IMPORT_ALLOWLIST: dict[str, frozenset[str]] = {
    "decompiler_postprocess_calls.py": frozenset(
        {
            ".cod_extract",
            # Compatibility-only edges: logical call-shape reconciliation and
            # indirect-call parameter recovery remain owned by Types/Lowering.
            ".lowering.call_argument_shape",
            # Publication-only edge: Lowering synchronizes accepted logical
            # shapes across identical physical call facts; the bridge adds no proof.
            ".lowering.call_argument_shape_publication",
            # Compatibility-only edge: typed call-argument expression
            # materialization is owned by Types/Lowering.
            ".lowering.call_argument_expression",
            # Compatibility-only edge: exact live callsite presence is owned
            # by Types/Lowering; the legacy bridge only consumes its result.
            ".lowering.callsite_inventory_presence",
            # Compatibility-only edge: Lowering proves whether an existing GP
            # call result can be read; the bridge must not clone a live call.
            ".lowering.runtime_call_results",
            # Cache-only edge: the legacy call bridge compares materialized
            # argument tokens owned by Lowering; it must not produce proof.
            ".lowering.call_argument_semantic_token",
            # Veto-only edge: Lowering preserves exact embedded machine calls;
            # the legacy mutation bridge cannot invent replacement semantics.
            ".lowering.call_argument_call_preservation",
            # Compatibility-only edge: the legacy call bridge consumes typed
            # stack objects selected by Lowering; it must not discover them.
            ".lowering.call_argument_stack_sources",
            ".lowering.function_pointer_parameters",
            ".lowering.real_mode_linear",
            ".lowering.segmented_global_loads",
            ".lowering.stack_lowering_from_facts",
            ".lowering.stack_probe_return_facts",
            ".structuring.simple_loop_recovery",
        }
    ),
    "decompiler_postprocess_jcc.py": frozenset(
        {
            ".lowering.real_mode_linear",
            ".lowering.segmented_memory_lowering",
            # Compatibility-only edge: the JCC bridge may consume the proven
            # four-byte stack object; Widening/Types-Lowering own its semantics.
            ".lowering.wide_stack_pair_evidence",
        }
    ),
    "decompiler_postprocess_simplify.py": frozenset(
        {
            ".lowering.stack_lowering_from_facts",
            ".semantics.alias_query",
            ".widening_alias",
            ".widening_model",
        }
    ),
    "decompiler_postprocess_stage.py": frozenset(
        {
            # Orchestration-only edge: Lowering owns ConditionIR-derived
            # argument types; the final AST stage only replays its typed result.
            ".lowering.condition_argument_types",
            ".lowering.condition_transfer",
            ".lowering.fact_transfer",
            ".lowering.global_declarations",
            # Type-only edge: legacy cleanup may construct a pointer surface,
            # but the fixed near-pointer ABI contract remains owned by Lowering.
            ".lowering.near_pointer_type",
            ".lowering.real_mode_linear",
            # Orchestration-only edge: Lowering owns typed IR load/register
            # provenance; the final AST stage only replays its proven carrier.
            ".lowering.ir_segmented_load_carriers",
            # Orchestration-only edge: Lowering owns typed register-indirect
            # call targets; the final AST stage only replays that typed result.
            ".lowering.register_indirect_call_targets",
            # Orchestration-only edge: the legacy pre-validation wrapper replays
            # the shared Types/Lowering consumer after its final AST regeneration.
            ".lowering.segment_global_materialization",
            ".lowering.segmented_global_loads",
            ".lowering.segmented_memory_lowering",
            ".lowering.ss_bp_substitution",
            ".lowering.stack_lowering",
            ".lowering.stack_lowering_from_facts",
            # Orchestration-only edge: aggregate proof and array typing remain
            # in lowering; postprocess may replay its bounded final consumer.
            ".lowering.stack_aggregate_objects",
            # Orchestration-only edge: Lowering owns exact BP/entry-SP storage
            # identity; final rendering may replay only its proven display name.
            ".lowering.stack_variable_display_names",
            # Compatibility-only edge: terminal-return materialization consumes
            # exact Lowering-owned BP/entry-SP identity and must not infer it.
            ".lowering.stack_variable_coordinates",
            ".lowering.stack_prototype_materialization",
            # Orchestration-only edge: final AST regeneration replays exact
            # ConditionIR access provenance before Types/Lowering consumes it.
            ".structuring.condition_provenance",
            ".structuring.loop_body_repair",
            ".structuring.loop_break_jcc",
            ".structuring.loop_exit_return_guards",
            ".structuring.return_chains",
        }
    ),
    "decompiler_postprocess_typed_conditions.py": frozenset(
        {
            ".structuring.condition_lowering",
        }
    ),
    "decompiler_postprocess_utils.py": frozenset(
        {
            ".lowering.real_mode_linear",
        }
    ),
}

_POSTPROCESS_HEADER_MARKERS: dict[str, str] = {
    "decompiler_postprocess.py": "cleanup only; proof belongs in IR, alias, widening, lowering, or structuring",
    "decompiler_postprocess_calls.py": "Do not add new source-text",
    "decompiler_postprocess_flags.py": "Do not add behavior here",
    "decompiler_postprocess_globals.py": "Do not add new global object inference",
    "decompiler_postprocess_inventory.py": "move proof production to IR, alias, lowering, or structuring",
    "decompiler_postprocess_jcc.py": "Do not add fresh semantic decoding",
    "decompiler_postprocess_loads.py": "Do not add new memory recovery",
    "decompiler_postprocess_simplify.py": "Do not add new alias",
    "decompiler_postprocess_stage.py": "do not make it a semantics layer",
    "decompiler_postprocess_typed_conditions.py": "Do not add new flag",
    "decompiler_postprocess_utils.py": "Do not add new recovery logic",
}

_LOWERING_OWNERSHIP_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "global_declarations.py": (
        "Layer: Types/Lowering",
        "Consumes alias, widening, and typed facts",
        "Do not recover semantics from COD, source, assembly, or rendered C text",
        "Postprocess and CLI may consume declarations, but proof belongs here",
    ),
    "segmented_global_loads.py": (
        "Layer: Types/Lowering",
        "Consumes alias, widening, and typed facts",
        "Do not recover semantics from COD, source, assembly, or rendered C text",
        "Postprocess and CLI may consume materialized loads, but proof belongs here",
    ),
    "stack_aggregate_objects.py": (
        "Layer: Types/Lowering",
        "Responsibility:",
        "Do not recover semantics from COD, source, assembly, or rendered C text",
        "Postprocess may replay the exported bounded consumer",
        "must not infer aggregate facts, boundaries, or array types",
    ),
    "storage_identity_facts.py": (
        "Layer: Types/Lowering",
        "Responsibility: record binary-proven segmented global storage identities",
        "Consumes alias, widening, and typed facts",
        "Do not validate final output",
    ),
}

_SEMANTIC_LAYER_OWNERSHIP_MARKERS: dict[str, tuple[str, ...]] = {
    "alias": (
        "Layer: Alias",
        "Responsibility:",
        "Owns storage identity",
        "Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here",
    ),
    "widening": (
        "Layer: Widening",
        "Responsibility:",
        "Consumes alias-proven storage identity",
        "Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence",
    ),
    "semantics": (
        "Layer: Semantics",
        "Responsibility:",
        "Owns instruction effects, flags, branch meaning, and expression interpretation",
        "Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here",
    ),
    "pipeline": (
        "Layer: Pipeline governance",
        "Responsibility:",
        "Owns runtime ordering, invariant checks, hard failures, and final emission gates",
        "Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here",
    ),
    "postprocess": (
        "Layer: Rewrite/Postprocess cleanup",
        "Responsibility:",
        "Consumes already-proven IR, alias, widening, typed, and structuring facts",
        "Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here",
    ),
    "analysis": (
        "Layer: Analysis",
        "Responsibility:",
        "Owns derived read-only analysis artifacts from typed IR",
        "Do not own alias state, materialize objects, validate acceptance, rewrite emitted C, or use rendered text as proof",
    ),
    "structuring": (
        "Layer: Structuring",
        "Responsibility:",
        "Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence",
        "Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here",
    ),
    "validation": (
        "Layer: Validation",
        "Responsibility:",
        "Owns canonical equivalence checking and validation diagnostics",
        "Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof",
    ),
    "lowering": (
        "Layer: Types/Lowering",
        "Responsibility:",
        "Consumes alias, widening, and typed facts",
        "Do not recover semantics from COD, source, assembly, or rendered C text",
    ),
    "ir": (
        "Layer: IR",
        "Responsibility:",
        "Owns typed Value, Address, Condition, instruction facts, and lossless normalization",
        "Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here",
    ),
}

_ANALYSIS_LAYER_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "alias.py": (
        "Layer: Analysis",
        "derive storage overlap facts from typed IR values and addresses",
        "owning alias state, lowering objects, or using rendered text as alias proof",
    ),
    "stack_frame_ir.py": (
        "Layer: Analysis",
        "summarize SS frame accesses from typed IR artifacts",
        "inventing locals/args without segmented SS:BP/SP evidence",
    ),
}

_SEMANTIC_LAYER_DIRS = frozenset(
    {
        "ir",
        "semantics",
        "alias",
        "widening",
        "lowering",
        "structuring",
        "pipeline",
        "analysis",
        "validation",
    }
)

_ROOT_SEMANTIC_NO_POSTPROCESS_IMPORTS = frozenset(
    {
        "callsite_stack_metadata.py",
        "segmented_memory_reasoning.py",
        "type_array_matching.py",
    }
)

_SEMANTIC_LAYER_POSTPROCESS_IMPORT_ALLOWLIST: dict[str, frozenset[str]] = {
    "structuring/condition_materialization.py": frozenset(
        {
            "..decompiler_postprocess_jcc",
            "..decompiler_postprocess_typed_conditions",
            "..postprocess.flags_cleanup",
        }
    )
}

_CLI_ALLOWED_X86_16_IMPORTS = frozenset(
    {
        "angr_platforms.X86_16.analysis_helpers",
        "angr_platforms.X86_16.annotations",
        # CLI may report syntax-only C AST cycles; semantic repair remains forbidden here.
        "angr_platforms.X86_16.c_ast_utils",
        "angr_platforms.X86_16.callee_name_normalization",
        "angr_platforms.X86_16.cod_extract",
        "angr_platforms.X86_16.cod_known_objects",
        # CLI may consume lowering-owned render metadata; it must not derive or mutate that evidence.
        "angr_platforms.X86_16.codegen_metadata",
        "angr_platforms.X86_16.compiler_helpers",
        "angr_platforms.X86_16.decompiler_postprocess_calls",
        "angr_platforms.X86_16.decompiler_postprocess_flags",
        "angr_platforms.X86_16.decompiler_postprocess_jcc",
        "angr_platforms.X86_16.decompiler_postprocess_simplify",
        "angr_platforms.X86_16.decompiler_postprocess_stage",
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions",
        "angr_platforms.X86_16.decompiler_postprocess_utils",
        # CLI only scopes an IR-owned typed publication bridge around angr lift;
        # flag effects and liveness remain owned by X86_16 Semantics and IR.
        "angr_platforms.X86_16.ir.status_flag_lift_context",
        "angr_platforms.X86_16.lowering.condition_transfer",
        # CLI may replay final typed declaration metadata before rendering.
        "angr_platforms.X86_16.lowering.callsite_prototype_declarations",
        # CLI invokes this Types/Lowering consumer before decompilation so angr
        # preserves branch-carried call arguments; stack proof remains X86_16-owned.
        "angr_platforms.X86_16.lowering.callsite_prototype_seeding",
        "angr_platforms.X86_16.lowering.fact_transfer",
        # CLI only invokes the idempotent Types/Lowering consumer after angr
        # regeneration; binary fact classification remains outside the CLI.
        "angr_platforms.X86_16.lowering.function_pointer_parameters",
        "angr_platforms.X86_16.lowering.real_mode_linear",
        # CLI invokes this Types/Lowering consumer before decompilation;
        # caller-use proof and return-type ownership remain outside the CLI.
        "angr_platforms.X86_16.lowering.return_type_evidence",
        # CLI may invoke the shared idempotent Types/Lowering replay after
        # regeneration; semantic facts and object identities remain X86_16-owned.
        "angr_platforms.X86_16.lowering.segment_global_materialization",
        # CLI regeneration replays the Structuring-owned exact condition-load
        # provenance contract before invoking the lowering consumer.
        "angr_platforms.X86_16.structuring.condition_provenance",
        # CLI passes the Structuring-owned architecture policy to third-party
        # Clinic; it does not inspect or mutate CFG/condition evidence itself.
        "angr_platforms.X86_16.structuring.clinic_option_policy",
        "angr_platforms.X86_16.lowering.segmented_global_loads",
        "angr_platforms.X86_16.lowering.segmented_memory_lowering",
        # CLI may replay this bounded Types/Lowering consumer before rendering;
        # aggregate proof and array typing remain forbidden in the CLI.
        "angr_platforms.X86_16.lowering.stack_aggregate_objects",
        "angr_platforms.X86_16.lowering.stack_lowering",
        "angr_platforms.X86_16.lowering.stack_lowering_from_facts",
        # CLI may replay Lowering-owned display names after third-party stack
        # identifier normalization; storage identity remains outside the CLI.
        "angr_platforms.X86_16.lowering.stack_variable_display_names",
        # CLI only replays the idempotent Types/Lowering width consumer after
        # codegen regeneration; Widening evidence remains owned under X86_16.
        "angr_platforms.X86_16.lowering.stack_prototype_materialization",
        # CLI only replays this idempotent Types/Lowering consumer before render;
        # terminal register classification remains owned by Semantics.
        "angr_platforms.X86_16.lowering.terminal_register_return_types",
        "angr_platforms.X86_16.lowering.stack_probe_return_facts",
        "angr_platforms.X86_16.lst_extract",
        "angr_platforms.X86_16.pipeline.architecture_guard",
        "angr_platforms.X86_16.pipeline.contracts",
        "angr_platforms.X86_16.pipeline.errors",
        # CLI submits a recovery-owned closed census to this hard gate; neither
        # expected instruction identity nor CFG ownership is derived in CLI.
        "angr_platforms.X86_16.pipeline.recovery_coverage_guard",
        "angr_platforms.X86_16.pipeline.render_authority",
        "angr_platforms.X86_16.postprocess.optimization.dce",
        "angr_platforms.X86_16.render_compat",
        # CLI invokes the read-only recovery census producer before semantic
        # passes; instruction identity and CFG ownership remain X86_16-owned.
        "angr_platforms.X86_16.recovery_instruction_coverage",
        "angr_platforms.X86_16.segmented_memory_reasoning",
        "angr_platforms.X86_16.stack_probe_fact_trace",
        # CLI orchestrates already-owned structuring helpers; semantic ownership remains in X86_16/decompiler_structuring_stage.py.
        "angr_platforms.X86_16.decompiler_structuring_stage",
        "angr_platforms.X86_16.structuring.compare32_recovery",
        "angr_platforms.X86_16.structuring.loop_body_repair",
        "angr_platforms.X86_16.structuring.simple_loop_recovery",
        "angr_platforms.X86_16.tail_validation",
        "angr_platforms.X86_16.widening.widening_copyprop_8616",
    }
)

_CLI_FORBIDDEN_SEMANTIC_CALLS = frozenset(
    {
        "prune_consumed_segmented_stack_byte_arg_stores_8616",
        "run_structuring_condition_cleanup_8616",
    }
)

_COMPATIBILITY_SHIMS = {
    "alias_model.py": ".alias.alias_model",
    "alias_domains.py": ".alias.domains",
    "alias_state.py": ".alias.state",
    "alias_transfer.py": ".alias.transfer",
    "condition_ir.py": ".ir.condition_ir",
    "widening_alias.py": ".widening.register_widening",
}

_COMPATIBILITY_SHIM_HEADER_MARKERS = (
    "Layer: Compatibility shim",
    "Forbidden: semantic ownership",
)

_VALIDATION_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "tail_validation.py": (
        "Layer: Tail Validation",
        "compare recovered behavior against observed effects and report honest deltas",
        "semantic recovery from source, COD, assembly, or rendered C text",
    ),
    "tail_validation_condition_context.py": (
        "Layer: Tail Validation",
        "build contextual condition fingerprints from recovered structured C and IR evidence",
        "semantic recovery from source, COD, assembly, or rendered C text",
    ),
    "tail_validation_frame_spills.py": (
        "Layer: Tail Validation",
        "consume closed Types/Lowering frame-prune evidence",
        "semantic recovery, frame inference, or AST cleanup in validation",
    ),
    "tail_validation_fingerprint.py": (
        "Layer: Tail Validation",
        "fingerprint recovered calls, expressions, locations, and control effects for comparison",
        "semantic recovery from source, COD, assembly, or rendered C text",
    ),
    "tail_validation_routing.py": (
        "Layer: Tail Validation",
        "route validation delta families to likely owning layers for diagnosis",
        "treating routing as proof, recovery, or validation success",
    ),
    "tail_validation_stack_policy.py": (
        "Layer: Tail Validation",
        "decide which recovered stack writes are observable validation effects",
        "stack variable recovery, alias ownership, or rewrite-stage stack repair",
    ),
    "validation_helper_report.py": (
        "Layer: Validation",
        "present typed helper-family validation summaries without changing verdicts",
        "semantic recovery from source, COD, assembly, or rendered C text",
    ),
    "validation_manifest.py": (
        "Layer: Validation",
        "declare validation lanes and families that keep checks explicit and repeatable",
        "hiding failures, fallback identities, uncollected results, or timeouts",
    ),
    "validation_calls.py": (
        "Layer: Tail validation",
        "compare typed callsite summary identity with final C call nodes",
        "semantic recovery, source/COD/assembly/rendered-C inspection",
    ),
    "validation_call_multiplicity.py": (
        "Layer: Tail validation",
        "compare binary-required callsite identities with the number of",
        "target-name inference, rendered-C/assembly inspection",
    ),
    "validation_condition_identity.py": (
        "Layer: Tail validation",
        "compare proven ConditionIR storage with its final lowered C AST",
        "semantic recovery, AST mutation, or source/COD/assembly/rendered-C inspection",
    ),
    "validation_control_flow.py": (
        "Layer: Tail validation",
        "report effectful structured branch bodies that are unreachable",
        "semantic recovery, source/COD/assembly/rendered-C inspection",
    ),
    "validation_dataflow.py": (
        "Layer: Tail validation",
        "report whether materialized C AST reads have a proven prior",
        "semantic recovery, source/COD/assembly/rendered-C inspection",
    ),
    "validation_predicates.py": (
        "Layer: Validation",
        "normalize and invert exact structured predicate tokens for",
        "semantic recovery, source/COD/assembly/rendered-C inspection",
    ),
    "validation_storage.py": (
        "Layer: Tail validation",
        "compare Types/Lowering global storage identity facts with final",
        "semantic recovery, source/COD/assembly/rendered-C inspection",
    ),
    "validation_aggregate_storage.py": (
        "Layer: Tail validation",
        "map non-pointer structured-C aggregate fields back to their",
        "semantic recovery, AST mutation, or name-based storage inference",
    ),
    "validation_required_memory_effects.py": (
        "Layer: Tail validation",
        "report final-AST loss of typed direct segmented-memory stores",
        "semantic recovery, source/COD/assembly/rendered-C inspection",
    ),
    "validation_semantics.py": (
        "Layer: Validation",
        "assert generic semantic invariants over recovered output and pipeline state",
        "source-backed, COD-backed, or sample-specific semantic recovery",
    ),
    "validation_summary.py": (
        "Layer: Validation",
        "ensure validation attribution remains honest",
        "collapsing uncollected into success, hiding fallback identities",
    ),
    "validation/canonicalize.py": (
        "Layer: Validation",
        "Owns canonical equivalence checking and validation diagnostics",
        "Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof",
    ),
    "validation/status_flag_preservation.py": (
        "Layer: Validation",
        "identify exact structured instruction sites",
        "Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof",
    ),
}

_RECOMPILABLE_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "recompilable_cases.py": (
        "Layer: Recompilable output",
        "define bounded generated-C syntax/shape cases and their expected anchors",
        "semantic recovery from source, COD, assembly, or rendered C text",
    ),
    "recompilable_checks.py": (
        "Layer: Recompilable output",
        "syntax-check and shape-check generated C without changing recovered semantics",
        "source-backed repair, fallback body selection, or semantic cleanup",
    ),
    "recompilable_cli_bridge.py": (
        "Layer: Recompilable output",
        "run bounded decompile/recompile probes against generated C",
        "selecting source-evidence fallback C or repairing recovered output text",
    ),
    "recompilable_source_evidence.py": (
        "Layer: Recompilable output",
        "preserve legacy evidence helpers as inert compatibility surfaces",
        "source-backed generated-C fallback, validation, persistence, or repair",
    ),
    "recompilable_storage_alias.py": (
        "Layer: Recompilable output",
        "export alias-proven storage identities into recompilation artifacts",
        "alias ownership, source-backed naming, or text-derived storage recovery",
    ),
    "recompilable_storage_fallback.py": (
        "Layer: Recompilable output",
        "keep storage fallback decisions explicit and currently disabled",
        "selecting source-evidence fallback C or hiding live decompile failures",
    ),
    "recompilable_storage_map.py": (
        "Layer: Recompilable output",
        "materialize proven segmented storage rows for generated-C recompilation",
        "segment flattening, guessed objects, or text-derived storage identity",
    ),
    "recompilable_storage_map_producer.py": (
        "Layer: Recompilable output",
        "convert proven codegen storage seeds into recompilation storage maps",
        "segment recovery, alias ownership, or source/COD-backed storage synthesis",
    ),
    "recompilable_storage_objects.py": (
        "Layer: Recompilable output",
        "summarize already-proven storage object artifacts for recompilation diagnostics",
        "object-shape guessing, source-backed names, or semantic recovery",
    ),
    "recompilable_subset.py": (
        "Layer: Recompilable output",
        "orchestrate bounded generated-C syntax checks over the recompilable subset",
        "semantic recovery, fallback body substitution, or source-backed output repair",
    ),
}

_ROOT_STRUCTURING_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "structuring_cross_entry.py": (
        "Layer: Structuring",
        "publish grouped-entry CFG artifacts before region structuring/codegen",
        "alias ownership, type recovery, rewrite cleanup, or source/COD/text-backed repair",
    ),
    "structuring_grouped_refusal_report.py": (
        "Layer: Structuring",
        "report explicit grouped-entry refusal reasons to validation consumers",
        "treating refusals as success, recovery proof, or rewrite-stage repair",
    ),
    "structuring_grouped_units.py": (
        "Layer: Structuring",
        "derive cross-entry grouped units from CFG ownership artifacts",
        "alias ownership, type/materialization recovery, or source/COD/text-backed grouping",
    ),
    "structuring_grouping_report.py": (
        "Layer: Structuring",
        "report CFG grouping kinds to validation and reporting consumers",
        "creating proof, hiding grouping failures, or rewriting recovered C",
    ),
    "structuring_ir_hints.py": (
        "Layer: Structuring",
        "expose IR-readiness hints that explain structuring limits",
        "semantic recovery, alias recovery, or changing structuring verdicts",
    ),
}

_OPTIONAL_EVIDENCE_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "annotations.py": (
        "Layer: Optional evidence/reporting",
        "carry source/COD annotation metadata as optional labels and comments",
        "materializing prototypes, arguments, stack aliases, or types as recovered semantics",
    ),
    "cod_comment_emitter.py": (
        "Layer: Optional evidence/reporting",
        "format optional COD/source evidence as comments only",
        "semantic recovery, validation success, or output repair from COD/source text",
    ),
    "cod_extract.py": (
        "Layer: Optional evidence/reporting",
        "parse COD listings into labels, bounds, source lines, and diagnostic metadata",
        "using COD text as required proof for arguments, types, control flow, or validation success",
    ),
    "cod_known_objects.py": (
        "Layer: Optional evidence/reporting",
        "describe known COD-visible library objects for diagnostics and guarded labels",
        "guessing object layouts or treating names as semantic proof",
    ),
    "cod_source_rewrites.py": (
        "Layer: Optional evidence/reporting",
        "expose inactive source-backed rewrite debt as an explicit compatibility surface",
        "active source-backed C body replacement or semantic recovery",
    ),
    "codeview_nb00.py": (
        "Layer: Optional evidence/reporting",
        "parse CodeView NB00 debug records into optional labels and diagnostics",
        "requiring debug symbols for arguments, types, control flow, or validation success",
    ),
    "codeview_nb02_nb04.py": (
        "Layer: Optional evidence/reporting",
        "parse CodeView debug records into optional labels and diagnostics",
        "requiring debug symbols for arguments, types, control flow, or validation success",
    ),
    "lst_extract.py": (
        "Layer: Optional evidence/reporting",
        "parse LST/debug evidence into optional labels and diagnostics",
        "requiring listing text for arguments, types, control flow, or validation success",
    ),
    "turbo_debug_tdinfo.py": (
        "Layer: Optional evidence/reporting",
        "parse Turbo Debugger TDINFO records into optional labels and diagnostics",
        "requiring debug symbols for arguments, types, control flow, or validation success",
    ),
    "fast_tracer.py": (
        "Layer: Optional evidence/reporting",
        "find fast candidate entry points from direct 16-bit trace evidence",
        "treating trace candidates as proven function boundaries without later validation",
    ),
    "flair_extract.py": (
        "Layer: Optional evidence/reporting",
        "read optional FLAIR signature metadata for startup and library reporting",
        "using signature names as semantic proof for decompiler recovery",
    ),
    "ne_resources.py": (
        "Layer: Optional evidence/reporting",
        "parse NE resource tables for reporting and artifact extraction",
        "deriving code semantics, types, or validation success from resource names",
    ),
}

_RECOVERY_REPORTING_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "correctness_goals.py": (
        "Layer: Recovery/reporting",
        "describe correctness goals and completion signals for decompiler governance",
        "changing recovery behavior, validation verdicts, or generated C",
    ),
    "corpus_recovery_artifact.py": (
        "Layer: Recovery/reporting",
        "build corpus-level recovery artifacts from bounded scan results",
        "replacing scan failures with source-backed or guessed recovery output",
    ),
    "coverage_manifest.py": (
        "Layer: Recovery/reporting",
        "record coverage manifests that steer diagnostic sweeps",
        "changing instruction semantics, verifier verdicts, or recovery behavior",
    ),
    "exact_region_diagnostics.py": (
        "Layer: Recovery/reporting",
        "exact-region recovery coverage diagnostics and region_split classification",
        "semantic recovery, postprocess ownership, text-pattern semantics",
    ),
    "ir_confidence_markers.py": (
        "Layer: Recovery/reporting",
        "attach confidence markers that expose IR assumptions and unknowns",
        "changing recovered semantics, structuring verdicts, or validation acceptance",
    ),
    "ir_readiness.py": (
        "Layer: Recovery/reporting",
        "summarize typed IR readiness from already-collected IR recovery facts",
        "manufacturing IR facts, changing structuring verdicts, or hiding unknowns",
    ),
    "ir_recovery_summary.py": (
        "Layer: Recovery/reporting",
        "summarize typed IR recovery counters from existing pipeline artifacts",
        "mutating IR, fabricating facts, or treating missing summaries as success",
    ),
    "recovery_instruction_coverage.py": (
        "Layer: Recovery/reporting",
        "classify exact instruction identity against CFG function ownership",
        "semantic recovery, validation acceptance, postprocess ownership",
    ),
    "layer_module_status.py": (
        "Layer: Recovery/reporting",
        "record whether architectural modules are production-wired",
        "admitting a pass into the pipeline or changing recovery behavior by import",
    ),
    "milestone_report.py": (
        "Layer: Recovery/reporting",
        "assemble milestone reports from existing layer descriptions and summaries",
        "collecting new proof, changing pipeline behavior, or hiding incomplete surfaces",
    ),
    "quality.py": (
        "Layer: Recovery/reporting",
        "preserve the historical X86_16 quality API",
        "CLI/reporting layer owns the implementation",
    ),
    "readability_goals.py": (
        "Layer: Recovery/reporting",
        "describe readability goals and diagnostic clusters for recovered output",
        "performing semantic recovery, rewrite cleanup, or validation acceptance",
    ),
    "readability_set.py": (
        "Layer: Recovery/reporting",
        "list golden readability anchors used by bounded diagnostics and tests",
        "substituting source-backed output or treating anchors as semantic proof",
    ),
    "corpus_scan.py": (
        "Layer: Recovery/reporting",
        "scan corpora and report decompilation, readability, and validation outcomes",
        "making scan outcomes a semantic recovery source or acceptance shortcut",
    ),
    "recovery_artifact_cache.py": (
        "Layer: Recovery/reporting",
        "cache recovery artifacts by validation-style content descriptors",
        "treating cache hits as semantic proof or validation success",
    ),
    "recovery_artifact_manifest.py": (
        "Layer: Recovery/reporting",
        "describe recovery artifact output surfaces and persistence formats",
        "writing artifacts, changing recovery behavior, or hiding missing outputs",
    ),
    "recovery_artifact_writer.py": (
        "Layer: Recovery/reporting",
        "persist already-built recovery artifacts as JSON",
        "changing artifact semantics, rerunning recovery, or masking write failures as success",
    ),
    "recovery_artifacts.py": (
        "Layer: Recovery/reporting",
        "assemble immutable recovery artifacts from already-produced summaries",
        "collecting new semantics, mutating output, or hiding failures",
    ),
    "recovery_confidence.py": (
        "Layer: Recovery/reporting",
        "classify recovery confidence from already-collected structured diagnostics",
        "creating proof, hiding assumptions, or changing recovered semantics",
    ),
    "recovery_manifest.py": (
        "Layer: Recovery/reporting",
        "declare recovery layers and focus areas for documentation and diagnostics",
        "admitting new recovery behavior or bypassing owning pipeline layers",
    ),
    "targeted_recovery_artifact.py": (
        "Layer: Recovery/reporting",
        "build targeted recovery artifacts for one bounded COD procedure",
        "replacing scan failures with source-backed or guessed recovery output",
    ),
    "verification_80286.py": (
        "Layer: Recovery/reporting",
        "run 80286 instruction verification cases and report mismatches",
        "using verification fixtures as decompiler semantic shortcuts or corpus-specific fixes",
    ),
}

_FRONTEND_RUNTIME_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "arch_86_16.py": (
        "Layer: Frontend/runtime",
        "define the 16-bit x86 archinfo register and toolchain surface",
        "decompiler semantic recovery, alias/type ownership, or rewrite cleanup",
    ),
    "bootstrap.py": (
        "Layer: Frontend/runtime",
        "install x86-16 compatibility, structuring, return, and cleanup bootstrap hooks",
        "owning decompiler semantics or adding source-backed recovery during startup",
    ),
    "compat.py": (
        "Layer: Frontend/runtime",
        "install runtime compatibility patches needed before x86-16 decompilation",
        "recovering alias, type, or validation semantics through compatibility hooks",
    ),
    "cr.py": (
        "Layer: Frontend/runtime",
        "model control-register state needed by the emulator surface",
        "protected-mode recovery shortcuts, decompiler semantics, or rewrite cleanup",
    ),
    "debug.py": (
        "Layer: Frontend/runtime",
        "provide debug printing helpers for the frontend emulator/lifter code",
        "recovery diagnostics, validation verdicts, or decompiler output changes",
    ),
    "eflags.py": (
        "Layer: Frontend/runtime",
        "expose flag register accessors for lifter and emulator instruction behavior",
        "postprocess flag cleanup, condition recovery, or validation acceptance",
    ),
    "emu.py": (
        "Layer: Frontend/runtime",
        "execute instruction side effects against emulator state during lifting",
        "decompiler semantic repair, alias/type recovery, or rendered-C rewrite",
    ),
    "emulator.py": (
        "Layer: Frontend/runtime",
        "bridge processor, interrupt, stack, and VEX value operations for the lifter",
        "decompiler semantic recovery, source/COD-backed behavior, or validation gating",
    ),
    "exception.py": (
        "Layer: Frontend/runtime",
        "define emulator exception constants and raising helpers",
        "decompiler validation decisions, semantic recovery, or output repair",
    ),
    "exec.py": (
        "Layer: Frontend/runtime",
        "dispatch decoded opcodes and register/memory operands for emulator execution",
        "decompiler output repair, alias/type ownership, or source-backed semantics",
    ),
    "hardware.py": (
        "Layer: Frontend/runtime",
        "compose processor, memory, and IO emulator state",
        "decompiler semantic recovery, alias/type ownership, or rewrite cleanup",
    ),
    "instr16.py": (
        "Layer: Frontend/runtime",
        "implement 16-bit opcode lifting and emulator-side instruction behavior",
        "decompiler postprocess repair, source/COD-backed semantics, or validation gating",
    ),
    "instr32.py": (
        "Layer: Frontend/runtime",
        "implement operand-size-32 opcode behavior reachable from the 16-bit frontend",
        "decompiler postprocess repair, source/COD-backed semantics, or validation gating",
    ),
    "instr_base.py": (
        "Layer: Frontend/runtime",
        "provide shared opcode handlers for instruction lifting/emulation",
        "decompiler semantic repair, source/COD-backed behavior, or rewrite cleanup",
    ),
    "instruction.py": (
        "Layer: Frontend/runtime",
        "define decoded instruction data and operand metadata for the lifter",
        "decompiler structuring, alias/type recovery, or rendered-C cleanup",
    ),
    "interrupt.py": (
        "Layer: Frontend/runtime",
        "model interrupt dispatch state for the 16-bit emulator surface",
        "DOS API semantic recovery, helper signature repair, or postprocess cleanup",
    ),
    "io.py": (
        "Layer: Frontend/runtime",
        "model port and memory-mapped IO behavior for lifting/emulation",
        "decompiler helper recovery, source-backed IO semantics, or validation acceptance",
    ),
    "lift_86_16.py": (
        "Layer: Frontend/runtime",
        "lift 16-bit x86 bytes into VEX/typed IR facts without later-stage repair",
        "postprocess cleanup, source/COD-backed recovery, or validation acceptance",
    ),
    "load_dos_mz.py": (
        "Layer: Frontend/runtime",
        "load DOS MZ executables into the 16-bit x86 frontend model",
        "decompiler recovery, type inference, or source/COD-backed repair",
    ),
    "load_dos_ne.py": (
        "Layer: Frontend/runtime",
        "load DOS NE executables and resource metadata into the frontend model",
        "decompiler recovery, type inference, or source/COD-backed repair",
    ),
    "low_memory_regions.py": (
        "Layer: Frontend/runtime",
        "classify real-mode low-memory segment:offset accesses for diagnostics",
        "treating low-memory labels as recovered decompiler semantics or validation proof",
    ),
    "memory.py": (
        "Layer: Frontend/runtime",
        "model emulator memory reads and writes for the 16-bit runtime surface",
        "decompiler storage recovery, alias ownership, or segment-flattening shortcuts",
    ),
    "parse.py": (
        "Layer: Frontend/runtime",
        "parse instruction prefixes, operands, and width state for the lifter",
        "decompiler semantic recovery, source/COD-backed repair, or validation acceptance",
    ),
    "processor.py": (
        "Layer: Frontend/runtime",
        "model processor registers and segment state for lifting/emulation",
        "decompiler alias/type ownership, source-backed recovery, or rendered-C cleanup",
    ),
    "simprocs_io.py": (
        "Layer: Frontend/runtime",
        "provide deterministic x86 dirty I/O SimProcedure stubs for lifting/runtime",
        "inferring decompiler semantics from port names, host devices, or I/O side effects",
    ),
    "simos_86_16.py": (
        "Layer: Frontend/runtime",
        "register the 16-bit SimOS, calling conventions, and interrupt procedures",
        "decompiler semantic recovery, source-backed signatures, or rewrite ownership",
    ),
}

_RECOVERY_METADATA_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "analysis_helpers.py": (
        "Layer: Recovery metadata",
        "provide helper metadata and interrupt surfaces consumed by recovery/reporting",
        "source/COD-backed semantic proof, validation acceptance, or emitted-C repair",
    ),
    "helper_abi.py": (
        "Layer: Recovery metadata",
        "own typed declarations and ABI shape metadata for known helpers",
        "using helper names as call-identity proof, substituting helper bodies",
    ),
    "callee_name_normalization.py": (
        "Layer: Recovery metadata",
        "normalize recovered callee labels for comparison and reporting",
        "treating names as semantic proof or synthesizing missing callees",
    ),
    "callsite_stack_metadata.py": (
        "Layer: Recovery metadata",
        "prune and report already-materialized callsite stack/segment metadata",
        "source/COD-backed argument recovery, alias ownership, or emitted-C repair",
    ),
    "caller_return_use_contracts.py": (
        "Layer: Recovery metadata",
        "retain exact caller, callsite, witness-instruction, and typed return-use observations",
        "inferring C return types, repairing emitted calls, or using source/COD/rendered-C text",
    ),
    "callsite_summary.py": (
        "Layer: Recovery metadata",
        "summarize recovered callsite targets, pushes, and return-shape facts",
        "deriving call semantics from source/COD text or repairing emitted calls",
    ),
    "codegen_metadata.py": (
        "Layer: Recovery metadata",
        "carry side metadata on codegen objects without changing semantics",
        "using metadata writes as proof, recovery, or validation acceptance",
    ),
    "compiler_helpers.py": (
        "Layer: Recovery metadata",
        "identify and hook proven compiler helper patterns such as stack probes",
        "helper signature synthesis from COD/source names or rendered C",
    ),
    "condition_trace.py": (
        "Layer: Recovery metadata",
        "record optional condition traces for diagnostics of recovered conditions",
        "condition recovery, postprocess repair, or validation acceptance from traces",
    ),
    "function_effect_summary.py": (
        "Layer: Recovery metadata",
        "summarize recovered function effects from existing structured artifacts",
        "creating proof, hiding unknowns, or changing recovered output",
    ),
    "function_interface_surface.py": (
        "Layer: Recovery metadata",
        "attach readable interface summaries from recovered function-state facts",
        "prototype recovery, source-backed signatures, or semantic repair",
    ),
    "function_state_summary.py": (
        "Layer: Recovery metadata",
        "summarize recovered register, flag, stack, and memory state effects",
        "manufacturing state facts, hiding unknowns, or changing validation verdicts",
    ),
    "function_summary.py": (
        "Layer: Recovery metadata",
        "summarize recovered function-level callsite and typed-IR signals",
        "source/COD-backed recovery, output repair, or validation acceptance",
    ),
    "helper_effect_summary.py": (
        "Layer: Recovery metadata",
        "summarize helper/wrapper eligibility from recovered function effects",
        "synthesizing helper signatures from names, source, COD, or rendered C",
    ),
    "helper_family_routing.py": (
        "Layer: Recovery metadata",
        "route helper refusal families to likely owner layers for diagnosis",
        "treating routing as proof, recovery success, or emitted-C repair",
    ),
    "runtime_trace_refinement.py": (
        "Layer: Recovery metadata",
        "summarize optional runtime trace refinement of already-collected IR readiness",
        "using runtime traces as sole semantics, validation success, or output repair",
    ),
    "stack_probe_fact_trace.py": (
        "Layer: Recovery metadata",
        "count stack-probe fact flow through existing recovery stages",
        "creating stack facts, hiding failures, or treating counts as proof",
    ),
}

_HELPER_BOUNDARY_HEADER_MARKERS: dict[str, tuple[str, ...]] = {
    "access.py": (
        "Layer: Helper boundary",
        "execute memory access while recording segmented IR facts for alias/type consumers",
        "treating linear execution addresses as semantic storage identity",
    ),
    "addressing_helpers.py": (
        "Layer: Helper boundary",
        "decode operands into segmented IR addresses plus execution-only linear addresses",
        "flattening SS/DS/ES into semantic storage identity",
    ),
    "alu_helpers.py": (
        "Layer: Helper boundary",
        "preserve the legacy ALU helper import surface while semantics live in semantics/",
        "adding fresh ALU semantics or condition recovery to this compatibility shim",
    ),
    "dev_io.py": (
        "Layer: Helper boundary",
        "define typed device and memory I/O interfaces used by frontend execution",
        "recovering decompiler semantics from device side effects or host I/O names",
    ),
    "jcc_condition.py": (
        "Layer: Helper boundary",
        "materialize explicit JCC branch conditions from typed IR condition facts",
        "recovering branch meaning from rendered assembly or postprocess text patterns",
    ),
    "stack_helpers.py": (
        "Layer: Helper boundary",
        "execute x86 stack and flag stack effects through the segmented SS memory model",
        "converting stack offsets into locals/args or inferring variable identity here",
    ),
    "string_helpers.py": (
        "Layer: Helper boundary",
        "execute string-instruction repeat, segment, direction, and branch helper effects",
        "replacing string-instruction semantics with source-backed or rendered-C rewrites",
    ),
    "string_instruction_artifact.py": (
        "Layer: Helper boundary",
        "collect structured string-instruction facts and refusals from decoded instructions",
        "using source listings or generated C text as proof for string-instruction semantics",
    ),
    "string_instruction_lowering.py": (
        "Layer: Helper boundary",
        "lower proven string-instruction artifacts into typed intrinsic records",
        "inventing string helper calls without artifact evidence and recorded refusals",
    ),
    "string_codegen_override.py": (
        "Layer: Helper boundary",
        "attach a codegen-boundary render override for fully proven string intrinsic artifacts",
        "repairing arbitrary generated C or inferring semantics from rendered output text",
    ),
    "structured_function_helpers.py": (
        "Layer: Helper boundary",
        "render narrow, decoded helper-family stubs from explicit instruction evidence",
        "using helper names, source text, or corpus-specific bodies as semantic proof",
    ),
    "type_array_matching.py": (
        "Layer: Helper boundary",
        "summarize typed IR, string-effect, and induction evidence into array-access candidates",
        "guessing arrays from names, source text, rendered C shape, or postprocess-only patterns",
    ),
    "type_equivalence_classes.py": (
        "Layer: Helper boundary",
        "summarize typed IR equivalence evidence for later type/object recovery",
        "guessing objects or types from names, source text, or rendered C shape",
    ),
    "type_storage_object_bridge.py": (
        "Layer: Helper boundary",
        "bridge recovered storage-object evidence into segmented object-lowering facts",
        "allowing object lowering when segmented evidence records a refusal",
    ),
    "type_structure_merging.py": (
        "Layer: Helper boundary",
        "merge proven field-access evidence into shared structure layout candidates",
        "inventing structs from names, source text, rendered C shape, or sample-specific offsets",
    ),
}

_AGENT_DOC_MARKERS = (
    "reference/project-map.md",
    "reference/decompiler-map.md",
    "Dot access for owned contracts",
    "avoidable `getattr`/`setattr`",
    "use `getattr`/`setattr` only at dynamic third-party/angr/codegen/plugin boundaries with a clear reason",
    "Existing avoidable dynamic attribute access is cleanup debt and should be removed when touching nearby code",
    "Docstrings and types ratchet",
    "every new or touched non-test module must state `Layer:` and `Responsibility:`",
    "legacy missing docs/types are cleanup debt",
    "Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`",
    "`make test-pipeline PYTHON=./.venv/bin/python` before claiming semantic decompiler improvements",
    "`make test-pipeline-expanded PYTHON=./.venv/bin/python` for broad slow audits",
    "Supplemental glossary and long-running-agent guidance",
)

_AGENT_DOC_FORBIDDEN_MARKERS = (
    "## Golden rules",
    "Agent execution details",
    "## Glossary",
    "## Diagnostics And Profiling",
    "## Resume Loop",
)

_AGENTS_MAX_LINES = 140
_PROJECT_MAP_MAX_LINES = 120
_DECOMPILER_MAP_MAX_LINES = 140
_AGENT_RULES_MAX_LINES = 160

_AGENT_RULES_MARKERS = (
    "AGENTS.md contains the mandatory agent rules and canonical architecture contract",
    "This file intentionally does not restate those rules",
)

_ARCHITECTURE_UNIQUE_KEY_TABLES = frozenset(
    {
        "_POSTPROCESS_LEGACY_IMPORT_ALLOWLIST",
        "_POSTPROCESS_HEADER_MARKERS",
        "_LOWERING_OWNERSHIP_HEADER_MARKERS",
        "_SEMANTIC_LAYER_OWNERSHIP_MARKERS",
        "_ANALYSIS_LAYER_HEADER_MARKERS",
        "_SEMANTIC_LAYER_POSTPROCESS_IMPORT_ALLOWLIST",
        "_COMPATIBILITY_SHIMS",
        "_VALIDATION_HEADER_MARKERS",
        "_RECOMPILABLE_HEADER_MARKERS",
        "_ROOT_STRUCTURING_HEADER_MARKERS",
        "_OPTIONAL_EVIDENCE_HEADER_MARKERS",
        "_RECOVERY_REPORTING_HEADER_MARKERS",
        "_FRONTEND_RUNTIME_HEADER_MARKERS",
        "_RECOVERY_METADATA_HEADER_MARKERS",
        "_HELPER_BOUNDARY_HEADER_MARKERS",
        "_PIPELINE_TIER_CONTRACT",
        "_OWNERSHIP_MANIFEST_FALLBACK_RULES",
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES",
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS",
        "_GATE_SCRIPT_DOCSTRING_MARKERS",
        "_CLI_BOUNDARY_RESPONSIBILITY_MARKERS",
    }
)

_OWNERSHIP_HEADER_MARKER_TABLES = frozenset(
    {
        "_LOWERING_OWNERSHIP_HEADER_MARKERS",
        "_ANALYSIS_LAYER_HEADER_MARKERS",
        "_VALIDATION_HEADER_MARKERS",
        "_RECOMPILABLE_HEADER_MARKERS",
        "_ROOT_STRUCTURING_HEADER_MARKERS",
        "_OPTIONAL_EVIDENCE_HEADER_MARKERS",
        "_RECOVERY_REPORTING_HEADER_MARKERS",
        "_FRONTEND_RUNTIME_HEADER_MARKERS",
        "_RECOVERY_METADATA_HEADER_MARKERS",
        "_HELPER_BOUNDARY_HEADER_MARKERS",
    }
)

_DOCSTRING_HEADER_MARKER_TABLES = frozenset({"_GATE_SCRIPT_DOCSTRING_MARKERS"})

_DOCSTRING_RESPONSIBILITY_MARKER_TABLES = frozenset({"_CLI_BOUNDARY_RESPONSIBILITY_MARKERS"})

_ARCHITECTURE_UNIQUE_STRING_SET_TABLES = frozenset(
    {
        "_LEGACY_SCRIPT_RESPONSIBILITY_DEBT",
        "_LEGACY_INERTIA_RESPONSIBILITY_DEBT",
    }
)

_LEGACY_SCRIPT_RESPONSIBILITY_DEBT: frozenset[str] = frozenset()

_LEGACY_INERTIA_RESPONSIBILITY_DEBT: frozenset[str] = frozenset()

_ACTIVE_REFERENCE_PATHS = (
    "reference/dosunit-execution-spec.md",
    "reference/telemetry.md",
    "reference/layer-module-status.md",
    "reference/decompiler-fix-plan.md",
)

_PROJECT_MAP_MARKERS = (
    "angr_platforms/angr_platforms/X86_16",
    "inertia_decompiler/",
    "dosunit.py",
    "signature_catalog.py",
    "scripts/test_pipeline.py",
    "fast tier is unit-focused only",
    "scripts/build_msc6_examples.py",
    "examples/msc6_constructs/",
    "reference/dosunit-execution-spec.md",
    "make architecture-check",
    "make agent-context-check",
    "make test-ownership-check",
    "make check-files",
    "changed-file module/doc/type/dot-access ratchet",
    "architecture/context guards, ownership-manifest validation, and owned tests",
    "legacy `Responsibility:` header debt explicitly",
    "remove entries from those lists as soon as the owning module docstring is fixed",
    "requires every X86_16 and inertia_decompiler module to be in the promoted typed/ruff gates or explicit promotion debt",
    "Full-promotion debt files stay out of `QA_TYPED_FILES` and `QA_RUFF_TARGETS`",
    "Ownership-manifest tests are fast-only",
    "make quality-fast",
    "make test-pipeline-fast",
    "must stay unit-focused",
    "make test-pipeline",
    "make test-pipeline-expanded",
    "libdosbox",
    ".understand-anything/config.json",
    "--no-auto-update",
)

_REFERENCE_MAP_FORBIDDEN_RULEBOOK_MARKERS = (
    "## Mission",
    "## Priority order",
    "## Core pipeline",
    "## Core model",
    "## Layer ownership",
    "## Hard rules",
    "## Agent execution rules",
    "## Anti-patterns",
    "## Execution discipline",
    "### Persistent startup contract",
    "### Function-fix acceptance contract",
    "## Review checklist",
    "## Improving code",
    "## Reference files",
)

_AGENT_RULES_FORBIDDEN_MARKERS = (
    *_REFERENCE_MAP_FORBIDDEN_RULEBOOK_MARKERS,
    "## Golden rules",
)

_DECOMPILER_MAP_MARKERS = (
    "IR -> Alias -> Widening -> Types -> Structuring -> Rewrite",
    "AGENTS.md` is the canonical rulebook",
    "reference/agent-rules.md` is supplemental glossary",
    "make quality-fast PYTHON=./.venv/bin/python",
    "make test-pipeline-fast PYTHON=./.venv/bin/python",
    "make test-pipeline PYTHON=./.venv/bin/python",
    "make test-pipeline-expanded PYTHON=./.venv/bin/python",
    "fast tier",
    "unit-focused only",
    "default tier",
    "expanded tier",
    "runtime guard entrypoints",
    "docs/types/dot-access ratchets",
)

_DECOMPILER_MAP_FORBIDDEN_MARKERS = (
    *_REFERENCE_MAP_FORBIDDEN_RULEBOOK_MARKERS,
    "detailed rulebook is `AGENTS.md` and",
)

_MAKEFILE_MARKERS = (
    "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
    "check-all: ruff-all pyright-all type-ratchet-changed architecture-check agent-context-check test-ownership-check pytest-all",
    "$(PYTHON) scripts/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
    "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
    "RUFF_SELECTED_FILES := $(filter $(QA_RUFF_TARGETS),$(PY_FILES))",
    "RUFF_SKIPPED_FILES := $(filter-out $(QA_RUFF_TARGETS),$(PY_FILES))",
    "$(PYTHON) -m ruff check --fix $(RUFF_OUTPUT_FLAGS) $(RUFF_SELECTED_FILES)",
    "ruff-files: skipped legacy files not in QA_RUFF_TARGETS:",
    "TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)",
    "quality: linters type-ratchet-changed decompiler-check",
    "quality-fast: linters type-ratchet-changed decompiler-check-fast",
    "type-ratchet-changed:",
    "$(PYTHON) scripts/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
    "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
    "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check test-pipeline-fast",
    "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
    "test-pipeline:",
    "$(PYTHON) scripts/test_pipeline.py --require-external",
    "test-pipeline-fast:",
    "$(PYTHON) scripts/test_pipeline.py --tier fast --require-external",
    "test-pipeline-expanded:",
    "$(PYTHON) scripts/test_pipeline.py --tier expanded --require-external",
)

_MAKEFILE_FORBIDDEN_MARKERS = (
    "QA_TYPE_RATCHET_LEGACY_FILES",
    "TYPE_RATCHET_SKIPPED_FILES",
    "type-ratchet-files: skipped explicit legacy debt:",
)

_PIPELINE_TIER_CONTRACT = {
    "fast": ("unit-focused",),
    "default": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),
    "expanded": (
        "unit-focused",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
        "sortd-sidecar-free",
        "sortdemo-status",
    ),
}

_PROMOTED_TYPED_FILES = (
    "angr_platforms/angr_platforms/X86_16/ail_displacement_compat.py",
    "angr_platforms/angr_platforms/X86_16/call_cleanup_compat.py",
    "angr_platforms/angr_platforms/X86_16/codegen_parentheses.py",
    "angr_platforms/angr_platforms/X86_16/direction_step.py",
    "angr_platforms/angr_platforms/X86_16/ir/ail_register_displacement.py",
    "angr_platforms/angr_platforms/X86_16/ir/stack_pointer_provenance.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_bit_source.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_integer_displacement.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape_publication.py",
    "angr_platforms/angr_platforms/X86_16/lowering/machine_stack_names.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_return_contract.py",
    "angr_platforms/angr_platforms/X86_16/stack_value_use.py",
    "angr_platforms/angr_platforms/X86_16/ir/register_live_in.py",
    "monkeytype_config.py",
    "angr_platforms/angr_platforms/X86_16/capstone_memory_segment.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_store_consumption.py",
    "angr_platforms/angr_platforms/X86_16/__init__.py",
    "angr_platforms/angr_platforms/X86_16/alias/__init__.py",
    "angr_platforms/angr_platforms/X86_16/alias_model.py",
    "angr_platforms/angr_platforms/X86_16/alias_domains.py",
    "angr_platforms/angr_platforms/X86_16/alias_state.py",
    "angr_platforms/angr_platforms/X86_16/alias_transfer.py",
    "angr_platforms/angr_platforms/X86_16/alias/alias_model.py",
    "angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py",
    "angr_platforms/angr_platforms/X86_16/alias/callsite_stack_merge.py",
    "angr_platforms/angr_platforms/X86_16/alias/register_reaching_source.py",
    "angr_platforms/angr_platforms/X86_16/alias/partial_register_address_break.py",
    "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_destinations.py",
    "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_sources.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_classification.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_program.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/storage_fact_join.py",
    "angr_platforms/angr_platforms/X86_16/alias/terminal_memory_outputs.py",
    "angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_outputs.py",
    "angr_platforms/angr_platforms/X86_16/alias/condition_register_carriers.py",
    "angr_platforms/angr_platforms/X86_16/alias/condition_register_liveness.py",
    "angr_platforms/angr_platforms/X86_16/alias/domains.py",
    "angr_platforms/angr_platforms/X86_16/alias/state.py",
    "angr_platforms/angr_platforms/X86_16/alias/stack_lowering.py",
    "angr_platforms/angr_platforms/X86_16/alias/segment_stack_fragments.py",
    "angr_platforms/angr_platforms/X86_16/alias/segment_stack_restore.py",
    "angr_platforms/angr_platforms/X86_16/alias/logical_stack_memory_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/stack_memory_access_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/stack_coordinate_projection.py",
    "angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa.py",
    "angr_platforms/angr_platforms/X86_16/alias/stack_memory_ssa_contracts.py",
    "angr_platforms/angr_platforms/X86_16/alias/transfer.py",
    "angr_platforms/angr_platforms/X86_16/analysis/__init__.py",
    "angr_platforms/angr_platforms/X86_16/analysis/alias.py",
    "angr_platforms/angr_platforms/X86_16/analysis/stack_frame_ir.py",
    "angr_platforms/angr_platforms/X86_16/analysis_helpers.py",
    "angr_platforms/angr_platforms/X86_16/interrupt_contract.py",
    "angr_platforms/angr_platforms/X86_16/arch_86_16.py",
    "angr_platforms/angr_platforms/X86_16/access.py",
    "angr_platforms/angr_platforms/X86_16/addressing_helpers.py",
    "angr_platforms/angr_platforms/X86_16/segment_offset_execution.py",
    "angr_platforms/angr_platforms/X86_16/address_ir.py",
    "angr_platforms/angr_platforms/X86_16/alu_helpers.py",
    "angr_platforms/angr_platforms/X86_16/annotations.py",
    "angr_platforms/angr_platforms/X86_16/borrow_verification.py",
    "angr_platforms/angr_platforms/X86_16/condition_ir.py",
    "angr_platforms/angr_platforms/X86_16/condition_trace.py",
    "angr_platforms/angr_platforms/X86_16/condition_call_effects.py",
    "angr_platforms/angr_platforms/X86_16/function_evidence_inventory.py",
    "angr_platforms/angr_platforms/X86_16/helper_abi.py",
    "angr_platforms/angr_platforms/X86_16/regs.py",
    "angr_platforms/angr_platforms/X86_16/ir/__init__.py",
    "angr_platforms/angr_platforms/X86_16/ir/address_ir.py",
    "angr_platforms/angr_platforms/X86_16/ir/native_stack_anchor.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_fingerprint_masks.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_ir.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_register_bindings.py",
    "angr_platforms/angr_platforms/X86_16/ir/core.py",
    "angr_platforms/angr_platforms/X86_16/ir/function_artifact.py",
    "angr_platforms/angr_platforms/X86_16/ir/function_condition_artifact.py",
    "angr_platforms/angr_platforms/X86_16/ir/block_ownership.py",
    "angr_platforms/angr_platforms/X86_16/ir/effects.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_access_normalization.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_evidence.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_trace.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_evidence.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_pipeline.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidate_helpers.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidates.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_evidence.py",
    "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_witnesses.py",
    "angr_platforms/angr_platforms/X86_16/ir/ir_canonicalize_8616.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_capture.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_matching.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_rebase.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_resolution.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_value_trace.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_write_value.py",
    "angr_platforms/angr_platforms/X86_16/ir/regs.py",
    "angr_platforms/angr_platforms/X86_16/ir/scalar_definitions.py",
    "angr_platforms/angr_platforms/X86_16/ir/scalar_affine_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/scalar_affine_sources.py",
    "angr_platforms/angr_platforms/X86_16/ir/scalar_affine_trace.py",
    "angr_platforms/angr_platforms/X86_16/ir/status_flag_binary_cfg.py",
    "angr_platforms/angr_platforms/X86_16/ir/status_flag_cfg_projection.py",
    "angr_platforms/angr_platforms/X86_16/ir/status_flag_lift_context.py",
    "angr_platforms/angr_platforms/X86_16/ir/segment_contract.py",
    "angr_platforms/angr_platforms/X86_16/ir/segment_state.py",
    "angr_platforms/angr_platforms/X86_16/ir/segment_state_solver.py",
    "angr_platforms/angr_platforms/X86_16/ir/segment_state_transfer.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_cfg.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_cfg_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_function.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_memory.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_call_liveness.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_contracts.py",
    "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_ranges.py",
    "angr_platforms/angr_platforms/X86_16/ir/string_effects.py",
    "angr_platforms/angr_platforms/X86_16/ir/value_ir.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_addressing.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_condition_lifting.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_condition_transport.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_control_flow.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_import.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_types.py",
    "angr_platforms/angr_platforms/X86_16/segment_function_summary.py",
    "angr_platforms/angr_platforms/X86_16/segment_program_layout.py",
    "angr_platforms/angr_platforms/X86_16/segment_program_layout_codec.py",
    "angr_platforms/angr_platforms/X86_16/segment_program_layout_contract.py",
    "angr_platforms/angr_platforms/X86_16/function_effect_summary.py",
    "angr_platforms/angr_platforms/X86_16/helper_effect_summary.py",
    "angr_platforms/angr_platforms/X86_16/helper_family_routing.py",
    "angr_platforms/angr_platforms/X86_16/function_interface_surface.py",
    "angr_platforms/angr_platforms/X86_16/function_summary.py",
    "angr_platforms/angr_platforms/X86_16/function_state_summary.py",
    "angr_platforms/angr_platforms/X86_16/callsite_target_inventory.py",
    "angr_platforms/angr_platforms/X86_16/caller_return_use_contracts.py",
    "angr_platforms/angr_platforms/X86_16/callsite_summary.py",
    "angr_platforms/angr_platforms/X86_16/callsite_register_provenance.py",
    "angr_platforms/angr_platforms/X86_16/register_source_block_inventory.py",
    "angr_platforms/angr_platforms/X86_16/synthetic_call_stub_evidence.py",
    "angr_platforms/angr_platforms/X86_16/call_target_identity.py",
    "angr_platforms/angr_platforms/X86_16/callsite_stack_metadata.py",
    "angr_platforms/angr_platforms/X86_16/stack_probe_fact_trace.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_condition_context.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_frame_spills.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_generation.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_generation_atoms.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_generation.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/result_contracts.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/structured_ast_query_index.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/pass_validation_policy.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/bootstrap_orchestration.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/pass_runtime.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/pass_transaction.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/runtime_configuration.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/rollback_snapshot_cache.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/validation_contracts.py",
    "angr_platforms/angr_platforms/X86_16/validation/control_flow_ast_index.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_routing.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_selector_returns.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation_stack_policy.py",
    "angr_platforms/angr_platforms/X86_16/targeted_recovery_artifact.py",
    "angr_platforms/angr_platforms/X86_16/layer_module_status.py",
    "angr_platforms/angr_platforms/X86_16/coverage_manifest.py",
    "angr_platforms/angr_platforms/X86_16/corpus_scan.py",
    "angr_platforms/angr_platforms/X86_16/milestone_report.py",
    "angr_platforms/angr_platforms/X86_16/exact_region_diagnostics.py",
    "angr_platforms/angr_platforms/X86_16/frontend_function_boundary.py",
    "angr_platforms/angr_platforms/X86_16/frontend_function_boundary_index.py",
    "angr_platforms/angr_platforms/X86_16/frontend_direct_callsite_index.py",
    "angr_platforms/angr_platforms/X86_16/frontend_function_instructions.py",
    "angr_platforms/angr_platforms/X86_16/frontend_instruction_kinds.py",
    "angr_platforms/angr_platforms/X86_16/frontend_instruction_reachability.py",
    "angr_platforms/angr_platforms/X86_16/recovery_instruction_coverage.py",
    "angr_platforms/angr_platforms/X86_16/flair_extract.py",
    "angr_platforms/angr_platforms/X86_16/fast_tracer.py",
    "angr_platforms/angr_platforms/X86_16/jcc_condition.py",
    "angr_platforms/angr_platforms/X86_16/lift_86_16.py",
    "angr_platforms/angr_platforms/X86_16/load_dos_mz.py",
    "angr_platforms/angr_platforms/X86_16/load_dos_ne.py",
    "angr_platforms/angr_platforms/X86_16/lst_extract.py",
    "angr_platforms/angr_platforms/X86_16/ne_exe_parse.py",
    "angr_platforms/angr_platforms/X86_16/ne_resources.py",
    "angr_platforms/angr_platforms/X86_16/recovery_manifest.py",
    "angr_platforms/angr_platforms/X86_16/recovery_artifacts.py",
    "angr_platforms/angr_platforms/X86_16/recovery_confidence.py",
    "angr_platforms/angr_platforms/X86_16/recovery_artifact_cache.py",
    "angr_platforms/angr_platforms/X86_16/recovery_artifact_manifest.py",
    "angr_platforms/angr_platforms/X86_16/recovery_artifact_writer.py",
    "angr_platforms/angr_platforms/X86_16/corpus_recovery_artifact.py",
    "angr_platforms/angr_platforms/X86_16/confidence_and_assumptions.py",
    "angr_platforms/angr_platforms/X86_16/ir_recovery_summary.py",
    "angr_platforms/angr_platforms/X86_16/ir_readiness.py",
    "angr_platforms/angr_platforms/X86_16/ir_confidence_markers.py",
    "angr_platforms/angr_platforms/X86_16/runtime_trace_refinement.py",
    "angr_platforms/angr_platforms/X86_16/structuring_ir_hints.py",
    "angr_platforms/angr_platforms/X86_16/structuring_abnormal_loops.py",
    "angr_platforms/angr_platforms/X86_16/structuring_analysis.py",
    "angr_platforms/angr_platforms/X86_16/structuring_cfg_ownership.py",
    "angr_platforms/angr_platforms/X86_16/structuring_cfg_indirect.py",
    "angr_platforms/angr_platforms/X86_16/structuring_cfg_grouping.py",
    "angr_platforms/angr_platforms/X86_16/structuring_loops.py",
    "angr_platforms/angr_platforms/X86_16/structuring_cfg_snapshot.py",
    "angr_platforms/angr_platforms/X86_16/structuring_graph_builder.py",
    "angr_platforms/angr_platforms/X86_16/structuring_grouped_graph_builder.py",
    "angr_platforms/angr_platforms/X86_16/structuring_region.py",
    "angr_platforms/angr_platforms/X86_16/structuring_codegen.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_structuring_stage.py",
    "angr_platforms/angr_platforms/X86_16/structuring_grouped_pass.py",
    "angr_platforms/angr_platforms/X86_16/structuring_grouped_units.py",
    "angr_platforms/angr_platforms/X86_16/structured_function_helpers.py",
    "angr_platforms/angr_platforms/X86_16/string_helpers.py",
    "angr_platforms/angr_platforms/X86_16/string_instruction_artifact.py",
    "angr_platforms/angr_platforms/X86_16/string_instruction_lowering.py",
    "angr_platforms/angr_platforms/X86_16/string_codegen_override.py",
    "angr_platforms/angr_platforms/X86_16/type_array_matching.py",
    "angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py",
    "angr_platforms/angr_platforms/X86_16/type_structure_merging.py",
    "angr_platforms/angr_platforms/X86_16/type_storage_object_bridge.py",
    "angr_platforms/angr_platforms/X86_16/bootstrap.py",
    "angr_platforms/angr_platforms/X86_16/cod_comment_emitter.py",
    "angr_platforms/angr_platforms/X86_16/cod_analysis_image.py",
    "angr_platforms/angr_platforms/X86_16/cod_extract.py",
    "angr_platforms/angr_platforms/X86_16/cod_known_objects.py",
    "angr_platforms/angr_platforms/X86_16/cod_source_rewrites.py",
    "angr_platforms/angr_platforms/X86_16/codeview_nb00.py",
    "angr_platforms/angr_platforms/X86_16/codeview_nb02_nb04.py",
    "angr_platforms/angr_platforms/X86_16/codegen_metadata.py",
    "angr_platforms/angr_platforms/X86_16/compiler_helpers.py",
    "angr_platforms/angr_platforms/X86_16/cr.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_globals.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_utils.py",
    "angr_platforms/angr_platforms/X86_16/compat.py",
    "angr_platforms/angr_platforms/X86_16/call_frame_compat.py",
    "angr_platforms/angr_platforms/X86_16/stack_anchor_compat.py",
    "angr_platforms/angr_platforms/X86_16/lowering/runtime_push_carrier.py",
    "angr_platforms/angr_platforms/X86_16/calling_convention_compat.py",
    "angr_platforms/angr_platforms/X86_16/render_compat.py",
    "angr_platforms/angr_platforms/X86_16/patch_dirty.py",
    "angr_platforms/angr_platforms/X86_16/c_ast_utils.py",
    "angr_platforms/angr_platforms/X86_16/callee_name_normalization.py",
    "angr_platforms/angr_platforms/X86_16/low_memory_regions.py",
    "angr_platforms/angr_platforms/X86_16/simos_86_16.py",
    "angr_platforms/angr_platforms/X86_16/exception.py",
    "angr_platforms/angr_platforms/X86_16/hardware.py",
    "angr_platforms/angr_platforms/X86_16/simprocs_io.py",
    "angr_platforms/angr_platforms/X86_16/debug.py",
    "angr_platforms/angr_platforms/X86_16/exepack.py",
    "angr_platforms/angr_platforms/X86_16/mz_image.py",
    "angr_platforms/angr_platforms/X86_16/packed_mz.py",
    "angr_platforms/angr_platforms/X86_16/dev_io.py",
    "angr_platforms/angr_platforms/X86_16/io.py",
    "angr_platforms/angr_platforms/X86_16/instruction.py",
    "angr_platforms/angr_platforms/X86_16/instr_base.py",
    "angr_platforms/angr_platforms/X86_16/vex_value_contract.py",
    "angr_platforms/angr_platforms/X86_16/instr16.py",
    "angr_platforms/angr_platforms/X86_16/instr32.py",
    "angr_platforms/angr_platforms/X86_16/parse.py",
    "angr_platforms/angr_platforms/X86_16/exec.py",
    "angr_platforms/angr_platforms/X86_16/emu.py",
    "angr_platforms/angr_platforms/X86_16/emulator.py",
    "angr_platforms/angr_platforms/X86_16/eflags.py",
    "angr_platforms/angr_platforms/X86_16/memory.py",
    "angr_platforms/angr_platforms/X86_16/processor.py",
    "angr_platforms/angr_platforms/X86_16/interrupt.py",
    "angr_platforms/angr_platforms/X86_16/stack_compat.py",
    "angr_platforms/angr_platforms/X86_16/typehoon_compat.py",
    "angr_platforms/angr_platforms/X86_16/type_clinic_return_compat.py",
    "angr_platforms/angr_platforms/X86_16/stack_helpers.py",
    "angr_platforms/angr_platforms/X86_16/correctness_goals.py",
    "angr_platforms/angr_platforms/X86_16/readability_set.py",
    "angr_platforms/angr_platforms/X86_16/readability_goals.py",
    "angr_platforms/angr_platforms/X86_16/quality.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_flags.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_jcc.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_loads.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_simplify.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_postprocess_typed_conditions.py",
    "angr_platforms/angr_platforms/X86_16/decompiler_return_compat.py",
    "angr_platforms/angr_platforms/X86_16/ailment_variant_access.py",
    "angr_platforms/angr_platforms/X86_16/tail_validation.py",
    "angr_platforms/angr_platforms/X86_16/validation_manifest.py",
    "angr_platforms/angr_platforms/X86_16/validation_helper_report.py",
    "angr_platforms/angr_platforms/X86_16/validation_summary.py",
    "angr_platforms/angr_platforms/X86_16/validation_calls.py",
    "angr_platforms/angr_platforms/X86_16/validation_call_multiplicity.py",
    "angr_platforms/angr_platforms/X86_16/validation_call_argument_sources.py",
    "angr_platforms/angr_platforms/X86_16/validation_call_return_storage.py",
    "angr_platforms/angr_platforms/X86_16/validation_stack_projection.py",
    "angr_platforms/angr_platforms/X86_16/validation_branch_conditions.py",
    "angr_platforms/angr_platforms/X86_16/validation_materialized_condition_storage.py",
    "angr_platforms/angr_platforms/X86_16/validation_condition_identity.py",
    "angr_platforms/angr_platforms/X86_16/validation_control_flow.py",
    "angr_platforms/angr_platforms/X86_16/validation_control_flow_obligations.py",
    "angr_platforms/angr_platforms/X86_16/validation_dataflow.py",
    "angr_platforms/angr_platforms/X86_16/validation_semantic_failures.py",
    "angr_platforms/angr_platforms/X86_16/validation_predicates.py",
    "angr_platforms/angr_platforms/X86_16/validation_storage.py",
    "angr_platforms/angr_platforms/X86_16/validation_aggregate_storage.py",
    "angr_platforms/angr_platforms/X86_16/validation_additive_terms.py",
    "angr_platforms/angr_platforms/X86_16/validation_required_memory_effects.py",
    "angr_platforms/angr_platforms/X86_16/validation_semantics.py",
    "angr_platforms/angr_platforms/X86_16/verification_80286.py",
    "angr_platforms/angr_platforms/X86_16/turbo_debug_tdinfo.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_cases.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_checks.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_cli_bridge.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_source_evidence.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_subset.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_storage_alias.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_storage_fallback.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_storage_map.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_storage_map_producer.py",
    "angr_platforms/angr_platforms/X86_16/recompilable_storage_objects.py",
    "angr_platforms/angr_platforms/X86_16/structuring_diagnostics.py",
    "angr_platforms/angr_platforms/X86_16/structuring_grouping_report.py",
    "angr_platforms/angr_platforms/X86_16/structuring_grouped_refusal_report.py",
    "angr_platforms/angr_platforms/X86_16/structuring_cross_entry.py",
    "angr_platforms/angr_platforms/X86_16/structuring_sequences.py",
    "angr_platforms/angr_platforms/X86_16/lowering/__init__.py",
    "angr_platforms/angr_platforms/X86_16/lowering/annotated_global_refs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_shape.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_arity_ownership.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_expression.py",
    "angr_platforms/angr_platforms/X86_16/lowering/runtime_call_results.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_semantic_token.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_state.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_call_preservation.py",
    "angr_platforms/angr_platforms/X86_16/callsite_argument_value_sources.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_replay.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_execution_frame_runtime.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_object_replay.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_carrier_liveness.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_return_frame.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_output_stack_objects.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_output_object_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/authoritative_function_prototypes.py",
    "angr_platforms/angr_platforms/X86_16/lowering/near_return_address_arguments.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direct_stack_consumer_generation.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direct_stack_replay_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/register_local_declarations.py",
    "angr_platforms/angr_platforms/X86_16/lowering/register_variable_identity.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_address_coordinates.py",
    "angr_platforms/angr_platforms/X86_16/lowering/register_reload_consumers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_storage_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_bindings.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_stores.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py",
    "angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_abi.py",
    "angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_globals.py",
    "angr_platforms/angr_platforms/X86_16/lowering/dos_interrupt_aggregate_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/named_type_definitions.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_seeding.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callsite_pointer_tables.py",
    "angr_platforms/angr_platforms/X86_16/lowering/signed_global_declarations.py",
    "angr_platforms/angr_platforms/X86_16/lowering/project_global_signedness.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_census.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_argument_count_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_argument_width_evidence.py",
    "angr_platforms/angr_platforms/X86_16/ir/function_ssa_registry.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_object_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_objects.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_validation.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_collection_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_function_solver.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_flow.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_paths.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_slot_join.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_pipeline.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_outputs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_application.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_source_defs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_defs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_condition_graph.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_conditions.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_collection_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_materialization.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_caller_context.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_collection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_block.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_flow.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_stack.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_witness.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_defs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_expression_defs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_target_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_targets.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_outputs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_type_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_physical_defs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_input_preflight.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_collection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_solver.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_simtypes.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_transaction.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_argument_interface.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_collection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/global_object_program_requirement.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_interface.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_sources.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_global_object_type_surface.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/indexed_global_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/indexed_address_collector_parity.py",
    "angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory.py",
    "angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/bounded_global_array_declarations.py",
    "angr_platforms/angr_platforms/X86_16/lowering/global_declaration_extents.py",
    "angr_platforms/angr_platforms/X86_16/lowering/helper_call_interfaces.py",
    "angr_platforms/angr_platforms/X86_16/lowering/far_pointer_constant_flow.py",
    "angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/far_pointer_segmented_load_materialization.py",
    "angr_platforms/angr_platforms/X86_16/lowering/register_constant_segmented_store.py",
    "angr_platforms/angr_platforms/X86_16/lowering/near_pointer_argument.py",
    "angr_platforms/angr_platforms/X86_16/lowering/near_pointer_type.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_cache.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift_contracts.py",
    "scripts/check_generated_translation_unit.py",
    "scripts/generated_translation_unit_assembly.py",
    "scripts/indexed_address_parity_inventory.py",
    "inertia_decompiler/cli_batch_c_output.py",
    "inertia_decompiler/indexed_alias_program_context.py",
    "inertia_decompiler/indexed_alias_program_publication.py",
    "inertia_decompiler/indexed_alias_program_recovery.py",
    "inertia_decompiler/indexed_global_object_cache.py",
    "inertia_decompiler/direct_global_object_cache.py",
    "inertia_decompiler/direct_global_object_context.py",
    "inertia_decompiler/generated_external_function_contracts.py",
    "inertia_decompiler/generated_c_function_extraction.py",
    "inertia_decompiler/generated_translation_unit_assembly.py",
    "scripts/check_sortd_generated_sort_core.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_cleanup_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/runtime_segment_access.py",
    "angr_platforms/angr_platforms/X86_16/lowering/runtime_memory_helpers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_fact_arbitration.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_argument_type_facts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_argument_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_scalar_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_stack_operands.py",
    "angr_platforms/angr_platforms/X86_16/lowering/condition_stack_projection_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/assignment_lvalue_casts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/c_runtime_header.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_saved_frame.py",
    "angr_platforms/angr_platforms/X86_16/lowering/dead_register_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direct_global_register_update_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/explicit_char_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/fixed_stack_probe_frames.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_probe_callsite_lowering.py",
    "angr_platforms/angr_platforms/X86_16/lowering/frame_prologue_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/frame_carrier_liveness.py",
    "angr_platforms/angr_platforms/X86_16/lowering/gp_stack_restore.py",
    "angr_platforms/angr_platforms/X86_16/lowering/register_overwrite_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py",
    "angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameter_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/function_pointer_parameters.py",
    "angr_platforms/angr_platforms/X86_16/lowering/cod_global_identity.py",
    "angr_platforms/angr_platforms/X86_16/lowering/global_declarations.py",
    "angr_platforms/angr_platforms/X86_16/lowering/global_symbol_names.py",
    "angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py",
    "angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py",
    "angr_platforms/angr_platforms/X86_16/lowering/physical_registers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/positive_bp_argument_plan.py",
    "angr_platforms/angr_platforms/X86_16/lowering/positive_bp_arguments.py",
    "angr_platforms/angr_platforms/X86_16/lowering/project_global_object_layout.py",
    "angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py",
    "angr_platforms/angr_platforms/X86_16/lowering/linear_global_decomposition_cache.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callsite_inventory_presence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callsite_segment_provenance.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segment_access_coverage.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segment_codegen_access_provenance.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segment_access_policy.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segment_global_materialization.py",
    "angr_platforms/angr_platforms/X86_16/lowering/semantic_cast.py",
    "angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/return_liveness_replay.py",
    "angr_platforms/angr_platforms/X86_16/lowering/unobserved_call_results.py",
    "angr_platforms/angr_platforms/X86_16/lowering/unobserved_returns.py",
    "angr_platforms/angr_platforms/X86_16/lowering/unused_void_return_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/scalar_return_types.py",
    "angr_platforms/angr_platforms/X86_16/validation_condition_precision.py",
    "angr_platforms/angr_platforms/X86_16/validation_terminal_returns.py",
    "angr_platforms/angr_platforms/X86_16/validation_switch_loop_tail_breaks.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segment_register_state.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segmented_global_loads.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py",
    "angr_platforms/angr_platforms/X86_16/lowering/ir_segmented_load_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/register_indirect_call_targets.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_pointer_snapshot.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_value_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_argument_identity.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_declaration_identity.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_argument_stack_sources.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_return_stack_conditions.py",
    "angr_platforms/angr_platforms/X86_16/lowering/structured_intrinsics.py",
    "angr_platforms/angr_platforms/X86_16/lowering/terminal_call_return_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_values.py",
    "angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/terminal_return_expressions.py",
    "angr_platforms/angr_platforms/X86_16/lowering/terminal_return_render_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_calls.py",
    "angr_platforms/angr_platforms/X86_16/segmented_memory_reasoning.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_objects.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_aggregate_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_c_ast_matching.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_stack_storage.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_ast.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_placement.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_predicate.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_scope.py",
    "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_values.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_ast.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_placement.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_replay.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignments.py",
    "angr_platforms/angr_platforms/X86_16/lowering/call_return_frame_arguments.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_return_recombine.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/instruction_bp_stack_access.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_projection_retirement.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_coordinate_rebinding.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_variable_coordinates.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_function_coordinates.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_variable_display_names.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_materialization.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_word_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_impl.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_materialization.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_stack_argument_views.py",
    "angr_platforms/angr_platforms/X86_16/lowering/indexed_load_subviews.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_result.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_variable_binding.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_stack_pair_evidence.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/__init__.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/__init__.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/call_argument_transaction.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/cleanup.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/flags_cleanup.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/simplify.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/value_flow.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/const_prop.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/copy_prop.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_noop_conditionals.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_purity.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce_walk.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_liveness.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_read_keys.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/local_declarations.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_setup.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dead_condition_carriers.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/pass_driver.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/structured_braces.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py",
    "angr_platforms/angr_platforms/X86_16/semantics/__init__.py",
    "angr_platforms/angr_platforms/X86_16/semantics/alias_query.py",
    "angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py",
    "angr_platforms/angr_platforms/X86_16/semantics/binary_call_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/branch_target_return.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_register_effects.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_effects.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_return_segment.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_projections.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_outputs.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_pipeline.py",
    "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effects.py",
    "angr_platforms/angr_platforms/X86_16/callsite_setup_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/consumed_stack_address_setup.py",
    "angr_platforms/angr_platforms/X86_16/semantics/register_entry_overwrite.py",
    "angr_platforms/angr_platforms/X86_16/semantics/register_value_preservation.py",
    "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_cfg.py",
    "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py",
    "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py",
    "angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py",
    "angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py",
    "angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py",
    "angr_platforms/angr_platforms/X86_16/semantics/flag_semantics.py",
    "angr_platforms/angr_platforms/X86_16/semantics/immediate_semantics.py",
    "angr_platforms/angr_platforms/X86_16/semantics/direct_call_result_storage.py",
    "angr_platforms/angr_platforms/X86_16/semantics/direct_global_ordering.py",
    "angr_platforms/angr_platforms/X86_16/semantics/memory_semantics.py",
    "angr_platforms/angr_platforms/X86_16/semantics/software_interrupt_inputs.py",
    "angr_platforms/angr_platforms/X86_16/semantics/status_flag_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/status_flag_cfg_liveness.py",
    "angr_platforms/angr_platforms/X86_16/semantics/status_flag_liveness.py",
    "angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_call_paths.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_outputs.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_outputs.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_return_passthrough.py",
    "angr_platforms/angr_platforms/X86_16/semantics/return_register_preservation.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_register_returns.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_return_storage.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_value_roles.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_stack_cleanup.py",
    "angr_platforms/angr_platforms/X86_16/structuring/branch_return_expressions.py",
    "angr_platforms/angr_platforms/X86_16/structuring/tagged_terminal_return_values.py",
    "angr_platforms/angr_platforms/X86_16/structuring/compare32_recovery.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_argument_join_conditions.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_argument_joins.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_return_conditions.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_return_register_placement.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_return_store_placement.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_contracts.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_occurrences.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_assignment_ast.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_assignments.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_result_registers.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_early_exit.py",
    "angr_platforms/angr_platforms/X86_16/structuring/stored_call_return_operands.py",
    "angr_platforms/angr_platforms/X86_16/structuring/control_flow.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_exit_normalization.py",
    "angr_platforms/angr_platforms/X86_16/structuring/single_branch_return_orientation.py",
    "angr_platforms/angr_platforms/X86_16/structuring/shared_call_occurrence_finalization.py",
    "angr_platforms/angr_platforms/X86_16/structuring/shared_call_result_aliases.py",
    "angr_platforms/angr_platforms/X86_16/structuring/shared_tail_call_ownership.py",
    "angr_platforms/angr_platforms/X86_16/structuring/shared_tail_cfg_topology.py",
    "angr_platforms/angr_platforms/X86_16/structuring/shared_tail_structured_ancestry.py",
    "angr_platforms/angr_platforms/X86_16/structuring/multi_arm_condition_ownership.py",
    "angr_platforms/angr_platforms/X86_16/structuring/clinic_option_policy.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_condition_materialization.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_binding.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_provenance.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_ownership.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_replay.py",
    "angr_platforms/angr_platforms/X86_16/structuring/expression_substitution.py",
    "angr_platforms/angr_platforms/X86_16/structuring/multi_arm_return_chains.py",
    "angr_platforms/angr_platforms/X86_16/structuring/total_return_suffixes.py",
    "angr_platforms/angr_platforms/X86_16/structuring/switch_loop_tail_breaks.py",
    "angr_platforms/angr_platforms/X86_16/structuring/wide_call_return_guard_chains.py",
    "angr_platforms/angr_platforms/X86_16/structuring/wide_stack_condition_chains.py",
    "angr_platforms/angr_platforms/X86_16/structuring/local_wide_stack_condition_chains.py",
    "angr_platforms/angr_platforms/X86_16/structuring/wide_stack_predicate_graphs.py",
    "angr_platforms/angr_platforms/X86_16/structuring/wide_stack_return_predicates.py",
    "angr_platforms/angr_platforms/X86_16/structuring/wide_stack_single_branches.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_binary_value.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py",
    "angr_platforms/angr_platforms/X86_16/structuring/unused_call_result_self_xor.py",
    "angr_platforms/angr_platforms/X86_16/structuring/indexed_condition_values.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_rendering.py",
    "angr_platforms/angr_platforms/X86_16/structuring/indexed_stack_ranges.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_branches.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_ownership.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_entries.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_immediate_loop_entries.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_linear_prefix_cfg.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_linear_prefixes.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_body.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_body_evidence.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_evidence.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_sites.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_pretest_initializers.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loops.py",
    "angr_platforms/angr_platforms/X86_16/structuring/direct_stack_move_loop_tail_replay.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_refresh.py",
    "angr_platforms/angr_platforms/X86_16/structuring/canonical_for_loops.py",
    "angr_platforms/angr_platforms/X86_16/structuring/induction_comparisons.py",
    "angr_platforms/angr_platforms/X86_16/structuring/pretest_initializer_placement.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_exit_return_guards.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_recovery.py",
    "angr_platforms/angr_platforms/X86_16/structuring/natural_loop_topology.py",
    "angr_platforms/angr_platforms/X86_16/structuring/return_chain_condition_selection.py",
    "angr_platforms/angr_platforms/X86_16/structuring/return_chains.py",
    "angr_platforms/angr_platforms/X86_16/structuring/guard_decisions.py",
    "angr_platforms/angr_platforms/X86_16/structuring/pass_effects.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_storage_identity.py",
    "angr_platforms/angr_platforms/X86_16/structuring/surplus_guard_contracts.py",
    "angr_platforms/angr_platforms/X86_16/structuring/return_chain_integrity.py",
    "angr_platforms/angr_platforms/X86_16/structuring/selector_return_projection.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_carried_terminal_return_contracts.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_carried_terminal_returns.py",
    "angr_platforms/angr_platforms/X86_16/structuring/terminal_register_values.py",
    "angr_platforms/angr_platforms/X86_16/structuring/software_interrupt_returns.py",
    "angr_platforms/angr_platforms/X86_16/structuring/scalar_return_evidence.py",
    "angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py",
    "angr_platforms/angr_platforms/X86_16/structuring/typed_switch_seqnode.py",
    "angr_platforms/angr_platforms/X86_16/structuring/switch_selector_binding.py",
    "angr_platforms/angr_platforms/X86_16/structuring/register_dependencies.py",
    "angr_platforms/angr_platforms/X86_16/structuring/wide_return_values.py",
    "angr_platforms/angr_platforms/X86_16/structuring/__init__.py",
    "angr_platforms/angr_platforms/X86_16/validation/__init__.py",
    "angr_platforms/angr_platforms/X86_16/validation/canonicalize.py",
    "angr_platforms/angr_platforms/X86_16/validation/callsite_completeness.py",
    "angr_platforms/angr_platforms/X86_16/validation/entry_stack_ranges.py",
    "angr_platforms/angr_platforms/X86_16/validation/status_flag_preservation.py",
    "angr_platforms/angr_platforms/X86_16/validation_interrupt_calls.py",
    "angr_platforms/angr_platforms/X86_16/widening_alias.py",
    "angr_platforms/angr_platforms/X86_16/widening_model.py",
    "angr_platforms/angr_platforms/X86_16/widening/__init__.py",
    "angr_platforms/angr_platforms/X86_16/widening/global_object_layout.py",
    "angr_platforms/angr_platforms/X86_16/widening/direct_global_object_layout_codec.py",
    "angr_platforms/angr_platforms/X86_16/widening/global_object_layout_codec.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_range_codec.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_ranges.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_layouts.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_recovery.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_solver.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_ranges.py",
    "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_layout.py",
    "angr_platforms/angr_platforms/X86_16/widening/register_widening.py",
    "angr_platforms/angr_platforms/X86_16/widening/segmented_load_identity.py",
    "angr_platforms/angr_platforms/X86_16/widening/segmented_load_widening.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_argument_widths.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects_contracts.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_word_register_transfers.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_widening.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_subview_expression.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_subview_proof.py",
    "angr_platforms/angr_platforms/X86_16/widening/stack_subview_coordinates.py",
    "angr_platforms/angr_platforms/X86_16/widening/store_width.py",
    "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_pipeline.py",
    "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_storage.py",
    "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_values.py",
    "angr_platforms/angr_platforms/X86_16/widening/terminal_memory_output_views.py",
    "angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_views.py",
    "angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py",
    "angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py",
    "angr_platforms/angr_platforms/X86_16/widening/widening_rules.py",
    "angr_platforms/angr_platforms/X86_16/widening/word_projection_recomposition.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/contracts.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/errors.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/invariants.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/linear_guard.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/recovery_coverage_guard.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/render_authority.py",
    "inertia_decompiler/__init__.py",
    "inertia_decompiler/acceptance_scorecard.py",
    "inertia_decompiler/analysis_timeout.py",
    "inertia_decompiler/architecture_import_attestation.py",
    "inertia_decompiler/architecture_runtime_guard.py",
    "inertia_decompiler/project_evidence_transport.py",
    "inertia_decompiler/cod_module_caller_evidence.py",
    "inertia_decompiler/c_text_cleanup.py",
    "inertia_decompiler/cache.py",
    "inertia_decompiler/cache_file_digest.py",
    "inertia_decompiler/direct_indexed_alias_local_cache.py",
    "inertia_decompiler/function_ir_ssa_cache.py",
    "inertia_decompiler/function_ir_ssa_cache_codec.py",
    "inertia_decompiler/function_ir_ssa_cache_identity.py",
    "inertia_decompiler/cache_io.py",
    "inertia_decompiler/cache_lock.py",
    "inertia_decompiler/cache_runtime_contract.py",
    "inertia_decompiler/cache_source_manifest.py",
    "inertia_decompiler/function_ir_ssa_source_scope.py",
    "inertia_decompiler/direct_request_cache.py",
    "inertia_decompiler/direct_request_fast_path.py",
    "inertia_decompiler/direct_request_identity.py",
    "inertia_decompiler/cli.py",
    "inertia_decompiler/cli_core.py",
    "inertia_decompiler/serial_clean_worker_evidence.py",
    "inertia_decompiler/serial_clean_worker_cli.py",
    "inertia_decompiler/serial_worker_cache.py",
    "inertia_decompiler/discovery_cache_contract.py",
    "inertia_decompiler/segment_program_layout_reporting.py",
    "inertia_decompiler/function_worker_policy.py",
    "inertia_decompiler/generated_c_artifacts.py",
    "inertia_decompiler/cli_decompilation.py",
    "inertia_decompiler/cli_c_ast_rewrites.py",
    "inertia_decompiler/cli_c_text_postprocess.py",
    "inertia_decompiler/cli_fallback_decompilation.py",
    "inertia_decompiler/cli_function_discovery.py",
    "inertia_decompiler/function_graph_extent_repair.py",
    "inertia_decompiler/cli_access_object_hints.py",
    "inertia_decompiler/cli_access_profiles.py",
    "inertia_decompiler/cli_access_traits.py",
    "inertia_decompiler/cli_access_trait_rewrite.py",
    "inertia_decompiler/cli_access_rewrite_artifact.py",
    "inertia_decompiler/cli_arg_parser.py",
    "inertia_decompiler/cli_cod_global_statements.py",
    "inertia_decompiler/cli_cod_globals.py",
    "inertia_decompiler/cli_dead_local_prune.py",
    "inertia_decompiler/cli_semantic_rollback.py",
    "inertia_decompiler/cli_helper_modeling.py",
    "inertia_decompiler/cli_interrupt_modeling.py",
    "inertia_decompiler/cli_linear_aliases.py",
    "inertia_decompiler/cli_induction_rewrite.py",
    "inertia_decompiler/cli_linear_recurrence.py",
    "inertia_decompiler/cli_linear_recurrence_rules.py",
    "inertia_decompiler/cli_linear_recurrence_state.py",
    "inertia_decompiler/cli_mkfp_simplify.py",
    "inertia_decompiler/cli_memory_prune.py",
    "inertia_decompiler/cli_local_prune.py",
    "inertia_decompiler/cli_local_rewrites.py",
    "inertia_decompiler/cli_far_pointer_stack.py",
    "inertia_decompiler/cli_segmented.py",
    "inertia_decompiler/cli_segmented_compare.py",
    "inertia_decompiler/cli_segmented_elision.py",
    "inertia_decompiler/cli_segmented_load_coalesce.py",
    "inertia_decompiler/cli_segmented_lowering.py",
    "inertia_decompiler/cli_segmented_store_coalesce.py",
    "inertia_decompiler/cli_stack_coalesce.py",
    "inertia_decompiler/cli_stack_cvars.py",
    "inertia_decompiler/cli_stack_byte_offsets.py",
    "inertia_decompiler/cli_stack_locals.py",
    "inertia_decompiler/cli_storage_objects.py",
    "inertia_decompiler/cli_string_timeout_fallback.py",
    "inertia_decompiler/cli_timeout.py",
    "inertia_decompiler/cli_output.py",
    "inertia_decompiler/cli_word_loads.py",
    "inertia_decompiler/cli_word_global_helpers.py",
    "inertia_decompiler/default_signature_catalog.py",
    "inertia_decompiler/decompile_file_summary.py",
    "inertia_decompiler/decompilation_quality.py",
    "inertia_decompiler/direct_addr_failure_family.py",
    "inertia_decompiler/direct_addr_stage_bundle.py",
    "inertia_decompiler/discovery_evidence_project.py",
    "inertia_decompiler/disassembly_helpers.py",
    "inertia_decompiler/flair_paths.py",
    "inertia_decompiler/fork_timeout.py",
    "inertia_decompiler/function_cache_context.py",
    "inertia_decompiler/gdb_client.py",
    "inertia_decompiler/gdb_tui.py",
    "inertia_decompiler/library_function_classifier.py",
    "inertia_decompiler/debug_dos.py",
    "inertia_decompiler/debugger_gdb.py",
    "inertia_decompiler/debugger_tui.py",
    "inertia_decompiler/signature_matching_policy.py",
    "inertia_decompiler/msc51_local_hash.py",
    "inertia_decompiler/non_optimized_fallback.py",
    "inertia_decompiler/packer_detect.py",
    "inertia_decompiler/prefork_job_pool.py",
    "inertia_decompiler/project_loading.py",
    "inertia_decompiler/rizin_evidence.py",
    "inertia_decompiler/rizin_discovery.py",
    "inertia_decompiler/recompile_check.py",
    "inertia_decompiler/recompile_check_contract.py",
    "inertia_decompiler/runtime_support.py",
    "inertia_decompiler/sidecar_cache.py",
    "inertia_decompiler/sidecar_metadata.py",
    "inertia_decompiler/sidecar_policy.py",
    "inertia_decompiler/sidecar_parsers.py",
    "inertia_decompiler/slice_recovery.py",
    "inertia_decompiler/source_sidecar.py",
    "inertia_decompiler/tail_validation.py",
    "inertia_decompiler/telemetry.py",
    "inertia_decompiler/tui_widgets.py",
    "inertia_decompiler/variable_recovery_sub_guard.py",
    "inertia_decompiler/work_items.py",
    "inertia_decompiler/x86_16_exact_slice.py",
    "inertia_decompiler/monkeytype_tools.py",
    "scripts/collect_monkeytype_pytest.py",
    "scripts/apply_monkeytype_annotations.py",
    "scripts/export_monkeytype_stubs.py",
    "scripts/agent_context_check.py",
    "scripts/check_decompiler_architecture.py",
    "scripts/test_pipeline.py",
    "scripts/test_ownership_manifest.py",
    "scripts/check_changed_non_test_types.py",
    "scripts/sortdemo_decompiler_status.py",
    "inertia_decompiler/accepted_payload_integrity.py",
    "inertia_decompiler/angr_codegen_tags.py",
    "angr_platforms/angr_platforms/X86_16/alias/condition_register_bindings.py",
    "angr_platforms/angr_platforms/X86_16/callsite_register_instruction_facts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/consumed_call_push_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/frame_instruction_evidence.py",
    "angr_platforms/angr_platforms/X86_16/lowering/frame_register_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_prototype_layout.py",
    "angr_platforms/angr_platforms/X86_16/msvc_x87_interrupts.py",
    "angr_platforms/angr_platforms/X86_16/structured_tags.py",
    "angr_platforms/angr_platforms/X86_16/structuring/boolean_condition_ites.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_argument_branch_carriers.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_conditions.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_argument_path_joins.py",
    "angr_platforms/angr_platforms/X86_16/verification_80386.py",
    "angr_platforms/angr_platforms/X86_16/alias/logical_stack_storage_identity.py",
    "angr_platforms/angr_platforms/X86_16/ir/logical_memory_scalar_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direct_global_register_updates.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direct_stack_segmented_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/logical_word_memory_copy_materialization.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_frame_projection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_word_recomposition.py",
    "angr_platforms/angr_platforms/X86_16/pipeline/structured_assignment_index.py",
    "angr_platforms/angr_platforms/X86_16/structuring/tagged_subtree_projection.py",
    "angr_platforms/angr_platforms/X86_16/widening/logical_word_memory_copies.py",
    "inertia_decompiler/indexed_alias_program_parallel.py",
    "inertia_decompiler/program_callsite_cache.py",
    "inertia_decompiler/project_argument_evidence_ranges.py",
    "angr_platforms/angr_platforms/X86_16/callsite_summary_codec.py",
    "angr_platforms/angr_platforms/X86_16/callsite_summary_program.py",
    "angr_platforms/angr_platforms/X86_16/callsite_summary_program_codec.py",
    "angr_platforms/angr_platforms/X86_16/frontend_block_inventory.py",
    "angr_platforms/angr_platforms/X86_16/frontend_caller_return_use_program.py",
    "angr_platforms/angr_platforms/X86_16/frontend_capstone_block.py",
    "angr_platforms/angr_platforms/X86_16/frontend_capstone_decode.py",
    "angr_platforms/angr_platforms/X86_16/frontend_function_block_decode.py",
    "angr_platforms/angr_platforms/X86_16/frontend_indirect_jump_targets.py",
    "angr_platforms/angr_platforms/X86_16/ir/condition_lift_capture.py",
    "angr_platforms/angr_platforms/X86_16/ir/function_ir_registry.py",
    "angr_platforms/angr_platforms/X86_16/ir/status_flag_lift_codec.py",
    "angr_platforms/angr_platforms/X86_16/ir/vex_condition_demand.py",
    "angr_platforms/angr_platforms/X86_16/lowering/balanced_memory_stack_restore.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_codec.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_callsite_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_codec.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_pointer_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/callee_range_callsite_facts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/caller_observed_byte_return_types.py",
    "angr_platforms/angr_platforms/X86_16/lowering/control_stack_escape.py",
    "angr_platforms/angr_platforms/X86_16/lowering/direction_flag_state.py",
    "angr_platforms/angr_platforms/X86_16/lowering/global_object_source_codec.py",
    "angr_platforms/angr_platforms/X86_16/lowering/gp_register_state.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_collection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_collection_contracts.py",
    "angr_platforms/angr_platforms/X86_16/lowering/packed_flags_state.py",
    "angr_platforms/angr_platforms/X86_16/lowering/project_callee_callsite_collection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/project_global_object_source_collection.py",
    "angr_platforms/angr_platforms/X86_16/lowering/segment_stack_restore_carriers.py",
    "angr_platforms/angr_platforms/X86_16/lowering/software_interrupt_status_outputs.py",
    "angr_platforms/angr_platforms/X86_16/lowering/stack_word_load_candidate.py",
    "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_carriers.py",
    "angr_platforms/angr_platforms/X86_16/postprocess/affine_compound_assignment.py",
    "angr_platforms/angr_platforms/X86_16/semantics/callsite_summary_request.py",
    "angr_platforms/angr_platforms/X86_16/semantics/terminal_register_restore.py",
    "angr_platforms/angr_platforms/X86_16/structuring/call_return_register_index.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_chain_provenance.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_evidence_closure.py",
    "angr_platforms/angr_platforms/X86_16/structuring/condition_stack_views.py",
    "angr_platforms/angr_platforms/X86_16/structuring/identical_return_guards.py",
    "angr_platforms/angr_platforms/X86_16/structuring/loop_condition_ownership.py",
    "angr_platforms/angr_platforms/X86_16/structuring/pretest_condition_surface.py",
    "angr_platforms/angr_platforms/X86_16/structuring/string_io_loop_carriers.py",
    "angr_platforms/angr_platforms/X86_16/structuring/switch_artifact_identity.py",
    "angr_platforms/angr_platforms/X86_16/validation_condition_chains.py",
    "angr_platforms/angr_platforms/X86_16/validation_condition_closure_delta.py",
    "angr_platforms/angr_platforms/X86_16/validation_identical_return_guards.py",
    "angr_platforms/angr_platforms/X86_16/validation_observable_compaction.py",
    "angr_platforms/angr_platforms/X86_16/validation_pointer_parameter_output_contracts.py",
    "angr_platforms/angr_platforms/X86_16/validation_pointer_parameter_outputs.py",
)

_INERTIA_TYPED_PROMOTION_DEBT_FILES = ()

_X86_16_TYPED_PROMOTION_DEBT_FILES = ()

_PYRIGHT_ONLY_TYPED_PROMOTION_FILES: tuple[str, ...] = ()

# This is an exact debt ratchet, not an exemption. The fingerprint locks every
# qualified private/nested annotation gap so debt cannot move or grow invisibly.
_DECOMPILER_ANNOTATION_ROOTS = (
    "angr_platforms/angr_platforms/X86_16",
    "inertia_decompiler",
)

_DECOMPILER_ANNOTATION_DEBT_BASELINE: dict[str, tuple[int, str]] = {}

_FOCUSED_PYTEST_MARKERS = (
    "angr_platforms/tests/test_test_pipeline.py",
    "angr_platforms/tests/test_check_changed_non_test_types.py",
    "angr_platforms/tests/test_cli_regeneration.py",
    "angr_platforms/tests/test_x86_16_condition_lowering.py",
    "angr_platforms/tests/test_x86_16_callsite_replay_safety.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py",
    "angr_platforms/tests/test_x86_16_validation_canonicalize.py",
    "angr_platforms/tests/test_x86_16_structuring_condition_materialization.py",
    "angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py",
    "angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",
    "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_expression_defs.py",
    "angr_platforms/tests/test_x86_16_scalar_affine_trace.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py",
    "angr_platforms/tests/test_x86_16_unused_void_return_types.py",
    "angr_platforms/tests/test_x86_16_object_lowering.py",
    "angr_platforms/tests/test_x86_16_semantics_alias_query.py",
    "angr_platforms/tests/test_x86_16_semantics_expression_analysis.py",
    "angr_platforms/tests/test_x86_16_terminal_pointer_outputs.py",
    "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py",
    "angr_platforms/tests/test_x86_16_terminal_pointer_output_views.py",
    "angr_platforms/tests/test_x86_16_dce_optimization.py",
    "angr_platforms/tests/test_x86_16_trivial_copy_optimization.py",
    "angr_platforms/tests/test_x86_16_widening_copyprop.py",
    "angr_platforms/tests/test_x86_16_widening_copyprop_width.py",
    "angr_platforms/tests/test_x86_16_linear_global_decomposition_cache.py",
    "angr_platforms/tests/test_x86_16_widening_memory_fold.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py",
    "angr_platforms/tests/test_x86_16_widening_rules.py",
)

_FOCUSED_PYTEST_FORBIDDEN_MARKERS = (
    "angr_platforms/tests/test_x86_16_cli.py",
    "angr_platforms/tests/test_x86_16_cod_samples.py",
    "angr_platforms/tests/test_x86_16_cod_regressions.py",
    "angr_platforms/tests/test_x86_16_life_decompile_regressions.py",
    "angr_platforms/tests/test_x86_16_msc6_regressions.py",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py",
)

_DYNAMIC_ATTR_BOUNDARY_TERMS = frozenset(("third-party", "angr", "codegen", "plugin", "compatibility"))

_OWNERSHIP_MANIFEST_FALLBACK_RULES = {
    "ir-layer-fallback": "angr_platforms/angr_platforms/X86_16/ir",
    "semantics-layer-fallback": "angr_platforms/angr_platforms/X86_16/semantics",
    "alias-layer-fallback": "angr_platforms/angr_platforms/X86_16/alias",
    "widening-layer-fallback": "angr_platforms/angr_platforms/X86_16/widening",
    "lowering-layer-fallback": "angr_platforms/angr_platforms/X86_16/lowering",
    "structuring-layer-fallback": "angr_platforms/angr_platforms/X86_16/structuring",
    "pipeline-layer-fallback": "angr_platforms/angr_platforms/X86_16/pipeline",
    "analysis-layer-fallback": "angr_platforms/angr_platforms/X86_16/analysis",
    "postprocess-package-fallback": "angr_platforms/angr_platforms/X86_16/postprocess",
    "validation-layer-fallback": "angr_platforms/angr_platforms/X86_16/validation",
}

_OWNERSHIP_MANIFEST_REQUIRED_RULES = {
    "architecture-guard": ("decompile.py",
        "inertia_decompiler/architecture_import_attestation.py",
        "inertia_decompiler/architecture_runtime_guard.py",
        "inertia_decompiler/cli.py",
        "inertia_decompiler/cli_core.py",
        "inertia_decompiler/serial_clean_worker_cli.py",
        "scripts/decompile_cod_dir.py",
        "scripts/check_decompiler_architecture.py",
    ),
    "tail-validation-family": ("angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py",),
    "cli-regeneration": ("inertia_decompiler/cli_decompilation.py",),
    "x86-16-alias-model-impl": ("angr_platforms/angr_platforms/X86_16/alias/alias_model_impl.py",),
    "x86-16-lowering-fact-transfer": ("angr_platforms/angr_platforms/X86_16/lowering/fact_transfer.py",),
    "x86-16-lowering-segmented": ("angr_platforms/angr_platforms/X86_16/lowering/segmented_lowering.py",),
    "x86-16-lowering-segmented-runtime": (
        "angr_platforms/angr_platforms/X86_16/lowering/segmented_memory_lowering.py",
        "angr_platforms/angr_platforms/X86_16/lowering/ir_segmented_load_carriers.py",
        "angr_platforms/angr_platforms/X86_16/lowering/register_indirect_call_targets.py",
    ),
    "x86-16-positive-bp-argument-plan": (
        "angr_platforms/angr_platforms/X86_16/lowering/positive_bp_argument_plan.py",
        "angr_platforms/angr_platforms/X86_16/lowering/positive_bp_arguments.py",
    ),
    "x86-16-condition-lowering": ("angr_platforms/angr_platforms/X86_16/structuring/condition_lowering.py",),
    "x86-16-structuring-condition-materialization": (
        "angr_platforms/angr_platforms/X86_16/structuring/condition_materialization.py",
    ),
    "x86-16-structuring-loop-body-repair": ("angr_platforms/angr_platforms/X86_16/structuring/loop_body_repair.py",),
    "x86-16-structuring-loop-break-jcc": ("angr_platforms/angr_platforms/X86_16/structuring/loop_break_jcc.py",),
    "x86-16-structuring-simple-loop-recovery": (
        "angr_platforms/angr_platforms/X86_16/structuring/simple_loop_recovery.py",
    ),
    "x86-16-dce-optimization": ("angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py",),
    "x86-16-trivial-copy-optimization": (
        "angr_platforms/angr_platforms/X86_16/postprocess/optimization/trivial_copy.py",
    ),
    "pipeline-architecture-final-emission-guard": (
        "angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py",
    ),
    "x86-16-validation-dataflow": ("angr_platforms/angr_platforms/X86_16/validation_dataflow.py",
        "angr_platforms/angr_platforms/X86_16/validation_predicates.py",
    ),
    "x86-16-validation-semantic-failures": ("angr_platforms/angr_platforms/X86_16/validation_semantic_failures.py",),
    "x86-16-validation-calls": ("angr_platforms/angr_platforms/X86_16/validation_calls.py",
        "angr_platforms/angr_platforms/X86_16/validation_call_multiplicity.py",
    ),
    "x86-16-validation-control-flow": ("angr_platforms/angr_platforms/X86_16/validation_condition_identity.py",
        "angr_platforms/angr_platforms/X86_16/validation_control_flow.py",
    ),
    "x86-16-validation-storage": ("angr_platforms/angr_platforms/X86_16/validation_storage.py",),
    "x86-16-callsite-prototype-declarations": (
        "angr_platforms/angr_platforms/X86_16/lowering/callsite_prototype_declarations.py",
    ),
    "x86-16-frontend-function-boundaries": (
        "angr_platforms/angr_platforms/X86_16/frontend_function_boundary.py",
        "angr_platforms/angr_platforms/X86_16/frontend_function_boundary_index.py",
    ),
    "x86-16-return-type-evidence": ("angr_platforms/angr_platforms/X86_16/lowering/return_type_evidence.py",),
    "x86-16-return-liveness-replay": (
        "angr_platforms/angr_platforms/X86_16/lowering/return_liveness_replay.py",
    ),
    "x86-16-unobserved-return-lowering": ("angr_platforms/angr_platforms/X86_16/lowering/unobserved_returns.py",
        "angr_platforms/angr_platforms/X86_16/lowering/unused_void_return_types.py",
    ),
    "x86-16-terminal-return-lowering": (
        "angr_platforms/angr_platforms/X86_16/lowering/terminal_register_return_values.py",
        "angr_platforms/angr_platforms/X86_16/lowering/terminal_return_expressions.py",
        "angr_platforms/angr_platforms/X86_16/lowering/terminal_return_render_projection.py",
    ),
    "x86-16-frame-carrier-lowering": ("angr_platforms/angr_platforms/X86_16/lowering/callee_saved_frame.py",
        "angr_platforms/angr_platforms/X86_16/lowering/frame_prologue_carriers.py",
        "angr_platforms/angr_platforms/X86_16/lowering/frame_carrier_liveness.py",
        "angr_platforms/angr_platforms/X86_16/lowering/physical_registers.py",
    ),
    "x86-16-validation-semantics": ("angr_platforms/angr_platforms/X86_16/validation_semantics.py",),
    "x86-16-widening-copyprop": ("angr_platforms/angr_platforms/X86_16/widening/widening_copyprop_8616.py",),
    "x86-16-widening-memory-fold": ("angr_platforms/angr_platforms/X86_16/widening/widening_memory_fold_8616.py",),
    "x86-16-widening-rules": ("angr_platforms/angr_platforms/X86_16/widening/widening_rules.py",),
    "x86-16-stack-subview-projection": ("angr_platforms/angr_platforms/X86_16/widening/stack_subview_expression.py",
        "angr_platforms/angr_platforms/X86_16/widening/stack_subview_projection.py",
        "angr_platforms/angr_platforms/X86_16/widening/stack_subview_proof.py",
        "angr_platforms/angr_platforms/X86_16/widening/stack_subview_coordinates.py",
    ),
    "x86-16-stack-memory-object-widening": ("angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects.py",
        "angr_platforms/angr_platforms/X86_16/widening/stack_memory_objects_contracts.py",
        "angr_platforms/angr_platforms/X86_16/widening/stack_word_register_transfers.py",
    ),
    "x86-16-semantics-expression-analysis": ("angr_platforms/angr_platforms/X86_16/semantics/expression_analysis.py",),
    "x86-16-semantics-alias-query": ("angr_platforms/angr_platforms/X86_16/semantics/alias_query.py",),
    "x86-16-semantics-alu": ("angr_platforms/angr_platforms/X86_16/semantics/alu_semantics.py",),
    "x86-16-semantics-condition-recovery": ("angr_platforms/angr_platforms/X86_16/semantics/condition_recovery.py",),
    "x86-16-semantics-stack-frame-recovery": ("angr_platforms/angr_platforms/X86_16/semantics/stack_frame_recovery.py",
    ),
    "x86-16-lowering-stack-probe-return-facts": (
        "angr_platforms/angr_platforms/X86_16/lowering/stack_probe_return_facts.py",
    ),
    "x86-16-lowering-storage-identity-facts": (
        "angr_platforms/angr_platforms/X86_16/lowering/storage_identity_facts.py",
    ),
    "x86-16-lowering-ss-bp-substitution": ("angr_platforms/angr_platforms/X86_16/lowering/ss_bp_substitution.py",),
    "x86-16-lowering-object-lowering": ("angr_platforms/angr_platforms/X86_16/lowering/object_lowering.py",),
    "x86-16-lowering-pointer-memory-idioms": ("angr_platforms/angr_platforms/X86_16/lowering/pointer_memory_idioms.py",
    ),
    "x86-16-ir-condition-cache-relift": (
        "angr_platforms/angr_platforms/X86_16/ir/condition_cache_relift.py",
        "angr_platforms/angr_platforms/X86_16/ir/function_condition_artifact.py",
    ),
    "x86-16-lowering-condition-transfer": ("angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py",),
    "x86-16-lowering-call-return-selectors": ("angr_platforms/angr_platforms/X86_16/lowering/call_return_selectors.py",
    ),
    "x86-16-lowering-stack-coordinator": ("angr_platforms/angr_platforms/X86_16/lowering/stack_lowering.py",),
    "x86-16-lowering-stack-from-facts": ("angr_platforms/angr_platforms/X86_16/lowering/stack_lowering_from_facts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa.py",
        "angr_platforms/angr_platforms/X86_16/lowering/stack_memory_ssa_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/stack_projection_retirement.py",
    ),
    "x86-16-interprocedural-storage-contracts": ("angr_platforms/angr_platforms/X86_16/ir/function_ssa_registry.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_collection_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_function_solver.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_flow.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_live_out_paths.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_slot_join.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_pipeline.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_application.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_prototype_types.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_expression_defs.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_target_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_caller_targets.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_source_defs.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_defs.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_passthrough.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_type_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_condition_graph.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split_conditions.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_split.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_collection_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_materialization.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_caller_context.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_trial_collection.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_block.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_flow.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_stack.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_pointer_witness.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_return_types.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_reaching_defs.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_types.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_input_preflight.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_trial_collection.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_solver.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_simtypes.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_storage_transaction.py",
    ),
    "x86-16-terminal-memory-output-semantics": (
        "angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/semantics/terminal_memory_outputs.py",
    ),
    "x86-16-terminal-memory-output-alias": ("angr_platforms/angr_platforms/X86_16/alias/terminal_memory_outputs.py",),
    "x86-16-terminal-memory-output-widening": (
        "angr_platforms/angr_platforms/X86_16/widening/terminal_memory_output_views.py",
    ),
    "x86-16-terminal-pointer-output-semantics": (
        "angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/semantics/terminal_pointer_outputs.py",
    ),
    "x86-16-terminal-pointer-output-alias": (
        "angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/alias/terminal_pointer_outputs.py",
    ),
    "x86-16-terminal-pointer-output-widening": (
        "angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/widening/terminal_pointer_output_views.py",
    ),
    "x86-16-pointer-parameter-output-lowering": (
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_outputs.py",
    ),
    "x86-16-interprocedural-memory-output-objects": (
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_object_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_objects.py",
        "angr_platforms/angr_platforms/X86_16/lowering/interprocedural_memory_output_validation.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_memory_outputs.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_type_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/pointer_parameter_object_types.py",
    ),
    "x86-16-call-semantics": ("angr_platforms/angr_platforms/X86_16/lowering/call_argument_carrier_liveness.py",
        "angr_platforms/angr_platforms/X86_16/lowering/call_return_frame.py",
        "angr_platforms/angr_platforms/X86_16/alias/partial_register_address_break.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_register_effects.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_return_frame_effects.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_return_segment.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_output_contracts.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_outputs.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_contracts.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effect_pipeline.py",
        "angr_platforms/angr_platforms/X86_16/semantics/call_stack_effects.py",
        "angr_platforms/angr_platforms/X86_16/callsite_setup_evidence.py",
        "angr_platforms/angr_platforms/X86_16/lowering/consumed_stack_address_setup.py",
        "angr_platforms/angr_platforms/X86_16/semantics/register_entry_overwrite.py",
        "angr_platforms/angr_platforms/X86_16/semantics/register_value_preservation.py",
        "angr_platforms/angr_platforms/X86_16/synthetic_call_stub_evidence.py",
    ),
    "x86-16-ir-ssa": ("angr_platforms/angr_platforms/X86_16/ir/ssa.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_cfg.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_cfg_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_function.py",
    ),
    "x86-16-ir-logical-memory": ("angr_platforms/angr_platforms/X86_16/access.py",
        "angr_platforms/angr_platforms/X86_16/lift_86_16.py",
        "angr_platforms/angr_platforms/X86_16/segment_offset_execution.py",
        "angr_platforms/angr_platforms/X86_16/alias/logical_stack_memory_projection.py",
        "angr_platforms/angr_platforms/X86_16/ir/function_artifact.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_capture.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_matching.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_resolution.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_register_transfer_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_value_trace.py",
        "angr_platforms/angr_platforms/X86_16/ir/logical_memory_write_value.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_function.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_memory.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/ssa_memory_ranges.py",
        "angr_platforms/angr_platforms/X86_16/ir/vex_import.py",
        "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py",
        "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py",
        "angr_platforms/angr_platforms/X86_16/semantics/evidence_cache.py",
    ),
    "x86-16-indexed-address-evidence": (
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_access_normalization.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_evidence.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_copy_trace.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_evidence.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_pipeline.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidate_helpers.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_candidates.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_evidence.py",
        "angr_platforms/angr_platforms/X86_16/ir/indexed_address_range_witnesses.py",
        "angr_platforms/angr_platforms/X86_16/ir/scalar_definitions.py",
        "angr_platforms/angr_platforms/X86_16/ir/scalar_affine_contracts.py",
        "angr_platforms/angr_platforms/X86_16/ir/scalar_affine_sources.py",
        "angr_platforms/angr_platforms/X86_16/ir/scalar_affine_trace.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_classification.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_access_contracts.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_contracts.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_contracts.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_copy_projection.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_projection.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_program.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_contracts.py",
        "angr_platforms/angr_platforms/X86_16/alias/indexed_address_range_projection.py",
        "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_range_codec.py",
        "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_program_ranges.py",
        "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_layouts.py",
        "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_recovery.py",
        "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_range_solver.py",
        "angr_platforms/angr_platforms/X86_16/widening/indexed_global_object_ranges.py",
        "angr_platforms/angr_platforms/X86_16/lowering/bounded_global_array_declarations.py",
        "angr_platforms/angr_platforms/X86_16/lowering/global_declaration_extents.py",
        "angr_platforms/angr_platforms/X86_16/lowering/indexed_address_collector_parity.py",
        "angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory.py",
        "angr_platforms/angr_platforms/X86_16/lowering/indexed_address_parity_inventory_contracts.py",
        "scripts/indexed_address_parity_inventory.py",
        "angr_platforms/tests/x86_16_indexed_global_object_range_fixtures.py",
    ),
    "x86-16-carry-borrow-widening": ("angr_platforms/angr_platforms/X86_16/alias/carry_borrow_contracts.py",
        "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_destinations.py",
        "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_projection.py",
        "angr_platforms/angr_platforms/X86_16/alias/carry_borrow_sources.py",
        "angr_platforms/angr_platforms/X86_16/alias/storage_fact_join.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_ast.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_placement.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_predicate.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_scope.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_bit_values.py",
        "angr_platforms/angr_platforms/X86_16/lowering/carry_borrow_stack_storage.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_ast.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_contracts.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_evidence.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_placement.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignment_replay.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_output_assignments.py",
        "angr_platforms/angr_platforms/X86_16/lowering/wide_call_return_recombine.py",
        "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_cfg.py",
        "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_contracts.py",
        "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_links.py",
        "angr_platforms/angr_platforms/X86_16/semantics/carry_borrow_ssa.py",
        "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_pipeline.py",
        "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_storage.py",
        "angr_platforms/angr_platforms/X86_16/widening/carry_borrow_values.py",
    ),
}

_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {
    "x86-16-positive-bp-argument-plan": (
        "angr_platforms/tests/test_x86_16_positive_bp_argument_plan.py",
    ),
    "x86-16-indexed-address-evidence": ("angr_platforms/tests/test_x86_16_indexed_address_copies.py::"
        "test_main_path_publishes_ir_and_alias_copy_evidence_atomically",
        "angr_platforms/tests/test_x86_16_indexed_address_aliases.py::"
        "test_indexed_load_projects_symbolic_target_and_exact_stack_source",
        "angr_platforms/tests/test_x86_16_indexed_address_collector_parity.py::"
        "test_real_indexed_load_collectors_have_exact_identity_parity",
        "angr_platforms/tests/test_x86_16_indexed_address_parity_inventory.py::"
        "test_identity_conflict_is_classified_on_exact_instruction_site",
        "angr_platforms/tests/test_x86_16_indexed_address_range_candidates.py",
        "angr_platforms/tests/test_x86_16_scalar_affine_trace.py",
        "angr_platforms/tests/test_x86_16_indexed_global_object_program_ranges.py",
        "angr_platforms/tests/test_x86_16_indexed_global_object_ranges.py",
        "angr_platforms/tests/test_x86_16_bounded_global_array_declarations.py",
        "angr_platforms/tests/test_x86_16_sortd_indexed_loop_topology.py",
    ),
    "pipeline-architecture-final-emission-guard": ("angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_rejects_raw_linear_segment_arithmetic",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_ignores_forbidden_tokens_inside_comments",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_rejects_unreachable_call_after_return",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_rejects_unary_not_shift_precedence_leak",
    ),
    "x86-16-validation-dataflow": ("angr_platforms/tests/test_x86_16_validation_dataflow.py",
        "angr_platforms/tests/test_x86_16_validation_predicates.py",
        "angr_platforms/tests/test_x86_16_validation_virtual_carriers.py",
    ),
    "x86-16-validation-semantic-failures": ("angr_platforms/tests/test_x86_16_validation_semantic_failures.py",),
    "x86-16-lowering-call-return-selectors": ("angr_platforms/tests/test_x86_16_call_return_selectors.py",),
    "x86-16-validation-calls": ("angr_platforms/tests/test_x86_16_validation_calls.py",
        "angr_platforms/tests/test_x86_16_validation_call_multiplicity.py",
    ),
    "x86-16-validation-control-flow": ("angr_platforms/tests/test_x86_16_validation_control_flow.py",),
    "x86-16-validation-storage": ("angr_platforms/tests/test_x86_16_validation_storage.py",),
    "x86-16-lowering-storage-identity-facts": ("angr_platforms/tests/test_x86_16_validation_storage.py",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_materialize_direct_global_inc_instruction_from_binary_evidence",
    ),
    "x86-16-callsite-prototype-declarations": ("angr_platforms/tests/test_x86_16_callsite_prototype_declarations.py",),
    "x86-16-interprocedural-storage-contracts": (
        "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_memory_outputs.py",
        "angr_platforms/tests/test_x86_16_pointer_parameter_object_types.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_expression_defs.py",
        "angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py::"
        "test_sortd_swaps_materializes_pointer_outputs_through_storage_pipeline",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_cfg.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_stack.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_split.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_passthrough.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py",
    ),
    "x86-16-stack-memory-object-widening": (
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_stack.py",
        "angr_platforms/tests/test_x86_16_stack_memory_object_widening.py",
        "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
    ),
    "x86-16-terminal-memory-output-semantics": ("angr_platforms/tests/test_x86_16_terminal_memory_outputs.py",),
    "x86-16-terminal-memory-output-alias": ("angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
    ),
    "x86-16-terminal-memory-output-widening": (
        "angr_platforms/tests/test_x86_16_terminal_memory_output_views.py",
        "angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
    ),
    "x86-16-terminal-pointer-output-semantics": (
        "angr_platforms/tests/test_x86_16_terminal_pointer_outputs.py",
    ),
    "x86-16-terminal-pointer-output-alias": (
        "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::"
        "test_every_store_site_binds_to_one_exact_positive_bp_parameter",
        "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::"
        "test_unknown_or_non_parameter_source_refuses_atomically",
        "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::"
        "test_competing_parameter_sources_refuse_without_partial_fact",
    ),
    "x86-16-terminal-pointer-output-widening": (
        "angr_platforms/tests/test_x86_16_terminal_pointer_output_views.py",
    ),
    "x86-16-pointer-parameter-output-lowering": (
        "angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py",
        "angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py",
    ),
    "x86-16-interprocedural-memory-output-objects": (
        "angr_platforms/tests/test_x86_16_interprocedural_memory_output_objects.py",
        "angr_platforms/tests/test_x86_16_interprocedural_memory_output_validation.py",
        "angr_platforms/tests/test_x86_16_pointer_parameter_memory_outputs.py",
        "angr_platforms/tests/test_x86_16_pointer_parameter_object_types.py",
        "angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py",
    ),
    "x86-16-call-semantics": (
        "angr_platforms/tests/test_x86_16_call_outputs.py",
        "angr_platforms/tests/test_x86_16_call_stack_effects.py",
        "angr_platforms/tests/test_x86_16_partial_register_address_break.py",
    ),
    "x86-16-ir-condition-cache-relift": (
        "angr_platforms/tests/test_x86_16_condition_cache_relift.py",
        "angr_platforms/tests/test_x86_16_function_condition_artifact.py",
    ),
    "x86-16-ir-ssa": (
        "angr_platforms/tests/test_x86_16_ir_ssa.py",
        "angr_platforms/tests/test_x86_16_ssa_cfg.py",
    ),
    "x86-16-frontend-function-boundaries": (
        "angr_platforms/tests/test_x86_16_frontend_function_boundary_index.py",
    ),
    "x86-16-ir-logical-memory": (
        "angr_platforms/tests/test_x86_16_semantics_evidence_cache.py",
        "angr_platforms/tests/test_x86_16_vex_import.py",
        "angr_platforms/tests/test_x86_16_vex_memory_access_fidelity.py",
        "angr_platforms/tests/test_x86_16_interprocedural_storage_return_pointer_stack.py",
        "angr_platforms/tests/test_x86_16_logical_memory_write_value.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_cfg.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_sources.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_stack_storage.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_widening.py",
    ),
    "x86-16-carry-borrow-widening": (
        "angr_platforms/tests/test_x86_16_carry_borrow_call_output.py",
        "angr_platforms/tests/test_x86_16_wide_call_output_assignments.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_cfg.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_bit_cfg_ownership.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_bit_lowering.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_sources.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_stack_storage.py",
        "angr_platforms/tests/test_x86_16_carry_borrow_widening.py",
    ),
    "x86-16-return-type-evidence": ("angr_platforms/tests/test_x86_16_return_type_evidence.py",),
    "x86-16-return-liveness-replay": (
        "angr_platforms/tests/test_x86_16_return_liveness_replay.py",
    ),
    "x86-16-validation-semantics": ("angr_platforms/tests/test_x86_16_validation_semantics.py",),
}

_GATE_SCRIPT_FILES = (
    "scripts/check_decompiler_architecture.py",
    "scripts/test_pipeline.py",
    "scripts/test_ownership_manifest.py",
    "scripts/check_changed_non_test_types.py",
    "scripts/agent_context_check.py",
    "scripts/decompile_cod_dir.py",
    "scripts/sortdemo_decompiler_status.py",
    "decompile.py",
)

_GATE_SCRIPT_DOCSTRING_MARKERS: dict[str, tuple[str, ...]] = {
    "scripts/check_decompiler_architecture.py": (
        "Layer: Tooling/gates",
        "Responsibility: enforce decompiler architecture, documentation, and ownership ratchets",
    ),
    "scripts/test_pipeline.py": (
        "Layer: Tooling/gates",
        "Responsibility: run curated fast/default/expanded decompiler regression tiers",
    ),
    "scripts/test_ownership_manifest.py": (
        "Layer: Tooling/gates",
        "Responsibility: map changed files to focused fast ownership tests",
    ),
    "scripts/check_changed_non_test_types.py": (
        "Layer: Tooling/gates",
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets",
    ),
    "scripts/agent_context_check.py": (
        "Layer: Tooling/gates",
        "Responsibility: report agent discovery context and approved fallback guidance",
    ),
    "scripts/decompile_cod_dir.py": (
        "Layer: Tooling/gates",
        "Responsibility: run bounded COD-directory decompilation batches with validation reporting",
    ),
    "scripts/sortdemo_decompiler_status.py": (
        "Layer: Tooling/gates",
        "Responsibility: summarize SORTDEMO decompiler status from generated reports",
    ),
    "decompile.py": (
        "Layer: CLI/fallback/reporting",
        "Responsibility: enter the CLI only after the runtime architecture guard",
    ),
}

_ROOT_CONTRACT_FILES = (
    "decompile.py",
    "signature_catalog.py",
    "omf_pat.py",
    "dosunit.py",
    "z3func.py",
)

_CLI_BOUNDARY_FILES = (
    "inertia_decompiler/cli.py",
    "inertia_decompiler/cli_core.py",
    "inertia_decompiler/serial_clean_worker_cli.py",
    "inertia_decompiler/cli_decompilation.py",
    "inertia_decompiler/cli_fallback_decompilation.py",
    "inertia_decompiler/cli_c_text_postprocess.py",
    "inertia_decompiler/cli_arg_parser.py",
    "inertia_decompiler/cli_c_ast_rewrites.py",
    "inertia_decompiler/cli_helper_modeling.py",
    "inertia_decompiler/cli_function_discovery.py",
    "inertia_decompiler/cli_output.py",
)

_CLI_BOUNDARY_COMMON_HEADER_MARKERS = (
    "Layer: CLI/fallback/reporting",
    "Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair",
)

_CLI_BOUNDARY_DEFAULT_RESPONSIBILITY_MARKER = (
    "Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers"
)

_CLI_BOUNDARY_RESPONSIBILITY_MARKERS: dict[str, str] = {
    "inertia_decompiler/cli.py": "Responsibility: expose the command entrypoint and compatibility imports",
    "inertia_decompiler/serial_clean_worker_cli.py": (
        "Responsibility: enter one isolated serial function worker through the typed CLI core"
    ),
    "inertia_decompiler/cli_arg_parser.py": (
        "Responsibility: define command-line options and parse user-selected execution policy"
    ),
    "inertia_decompiler/cli_c_ast_rewrites.py": (
        "Responsibility: coordinate legacy AST cleanup helpers around already-recovered facts"
    ),
    "inertia_decompiler/cli_c_text_postprocess.py": (
        "Responsibility: perform final emitted-C text cleanup and reporting-only normalization"
    ),
    "inertia_decompiler/cli_core.py": (
        "Responsibility: orchestrate commands, fallback lanes, diagnostics, and output policy"
    ),
    "inertia_decompiler/cli_decompilation.py": (
        "Responsibility: sequence decompilation passes, diagnostics, timeouts, and validated fallbacks"
    ),
    "inertia_decompiler/cli_fallback_decompilation.py": (
        "Responsibility: run bounded fallback lanes and report their validation outcome"
    ),
    "inertia_decompiler/cli_function_discovery.py": (
        "Responsibility: discover and select function work items for orchestrated decompilation"
    ),
    "inertia_decompiler/cli_helper_modeling.py": (
        "Responsibility: format known helper call/declaration text from explicit helper evidence"
    ),
    "inertia_decompiler/cli_output.py": (
        "Responsibility: render timestamps, diagnostics, and fallback text to output streams"
    ),
}

_BANNED_C_TEXT_SEMANTIC_HELPERS = frozenset(
    {
        "_rewrite_linear_segment_word_dereferences",
        "_synthesize_ellipsis_word_borrow_arithmetic",
        "_rewrite_unresolved_boolean_ellipsis_conditions",
        "_rewrite_unresolved_for_updates",
        "_rewrite_unresolved_missing_label_gotos",
        "_rewrite_unresolved_ellipsis_assignments",
        "_rewrite_invalid_void_object_decls",
        "_prune_unreachable_after_return",
    }
)

_BANNED_CLI_FALLBACK_SOURCE_HELPERS = frozenset(
    {
        "_inject_bp_arg_comments",
        "_inject_cod_global_annotation",
        "_normalize_source_fallback_style",
        "_render_cod_comment_source_fallback",
        "_render_cod_source_function_text",
        "_restore_collapsed_cod_source_function_text",
        "_rewrite_source_backed_assignments_8616",
        "_collect_source_assignments_8616",
        "_match_source_assignments_to_windows_8616",
        "_apply_source_decl_to_header_8616",
        "source_prototype",
        "source_cc",
        "source_returning",
        "prototype_synced",
        "calling_convention_synced",
        "returning_synced",
    }
)


_PYTHON_AST_CACHE: dict[Path, tuple[tuple[int, int], ast.Module]] = {}
_TEXT_CACHE: dict[Path, tuple[tuple[int, int], str]] = {}
_AST_WALK_CACHE: dict[int, tuple[ast.AST, ...]] = {}
_FIXED_NAME_GETATTR_CACHE: dict[ast.AST, tuple[tuple[str, str], ...]] = {}
_ASSIGNED_AST_NAMES_CACHE: dict[ast.stmt, frozenset[str]] = {}
_DYNAMIC_BOUNDARY_DOCSTRING_CACHE: dict[
    ast.Module,
    tuple[bool, tuple[tuple[int, int, bool], ...]],
] = {}
_DEFINITION_INDEX_CACHE: dict[
    ast.Module,
    tuple[
        dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        dict[str, ast.ClassDef],
    ],
] = {}


@dataclass(frozen=True, slots=True)
class ArchitectureViolation:
    """Structured architecture guard failure."""

    path: str
    rule: str
    detail: str

    def format(self) -> str:
        """Return a stable user-facing violation line."""

        return f"{self.path}: {self.rule}: {self.detail}"


def _file_cache_key(path: Path) -> tuple[int, int] | None:
    """Return a lightweight invalidation key for one existing file."""

    try:
        stat_result = path.stat()
    except FileNotFoundError:
        return None
    return stat_result.st_mtime_ns, stat_result.st_size


def _parse_python(path: Path) -> ast.Module:
    cache_key = _file_cache_key(path)
    if cache_key is None:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    cached = _PYTHON_AST_CACHE.get(path)
    if cached is not None and cached[0] == cache_key:
        return cached[1]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    _PYTHON_AST_CACHE[path] = (cache_key, tree)
    return tree


def _walk_ast(node: ast.AST) -> tuple[ast.AST, ...]:
    """Return a cached preorder traversal for repeated architecture scans."""

    cache_key = id(node)
    cached = _AST_WALK_CACHE.get(cache_key)
    if cached is not None:
        return cached
    walked = tuple(ast.walk(node))
    _AST_WALK_CACHE[cache_key] = walked
    return walked


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _fixed_name_getattr_calls(node: ast.AST) -> tuple[tuple[str, str], ...]:
    """Return ordered fixed-field getattr calls below one AST node."""

    cached = _FIXED_NAME_GETATTR_CACHE.get(node)
    if cached is not None:
        return cached
    calls: list[tuple[str, str]] = []
    for child in _walk_ast(node):
        if not (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == "getattr"
            and len(child.args) >= 2
            and isinstance(child.args[0], ast.Name)
        ):
            continue
        field_name = _string_constant(child.args[1])
        if field_name is not None:
            calls.append((child.args[0].id, field_name))
    result = tuple(calls)
    _FIXED_NAME_GETATTR_CACHE[node] = result
    return result


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _import_modules(tree: ast.Module) -> tuple[str, ...]:
    modules: list[str] = []
    for node in _walk_ast(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(f"{'.' * node.level}{node.module or ''}")
    return tuple(modules)


def _imported_names_from_module(tree: ast.Module, module: str) -> frozenset[str]:
    names: set[str] = set()
    for node in _walk_ast(tree):
        if isinstance(node, ast.ImportFrom) and f"{'.' * node.level}{node.module or ''}" == module:
            names.update(alias.name for alias in node.names)
    return frozenset(names)


def _contains_marker(text: str, marker: str) -> bool:
    return " ".join(marker.lower().split()) in " ".join(text.lower().split())


def _literal_string_value(node: ast.AST) -> str | None:
    """Return a literal string value from an AST node, if present."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _assignment_targets_and_value(
    statement: ast.Assign | ast.AnnAssign | ast.AugAssign,
) -> tuple[tuple[ast.expr, ...], ast.expr | None]:
    """Normalize assignment target shapes for static architecture scans."""
    if isinstance(statement, ast.Assign):
        return tuple(statement.targets), statement.value
    if isinstance(statement, ast.AnnAssign):
        return (statement.target,), statement.value
    return (statement.target,), None


def _dict_literal_duplicate_string_keys(
    tree: ast.Module,
    *,
    table_names: frozenset[str],
) -> tuple[tuple[str, str, int], ...]:
    """Return duplicate literal string keys in selected module-level dict tables."""

    duplicates: list[tuple[str, str, int]] = []
    for stmt in tree.body:
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(stmt)
        table_name = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if table_name not in table_names or not isinstance(value, ast.Dict):
            continue
        seen: set[str] = set()
        for key_node in value.keys:
            if key_node is None:
                continue
            key = _literal_string_value(key_node)
            if key is None:
                continue
            if key in seen:
                duplicates.append((table_name, key, key_node.lineno))
            seen.add(key)
    return tuple(duplicates)


def _module_string_set_duplicate_values(
    tree: ast.Module,
    *,
    table_names: frozenset[str],
) -> tuple[tuple[str, str, int], ...]:
    """Return duplicate string values in selected module-level frozenset tables."""

    duplicates: list[tuple[str, str, int]] = []
    for stmt in tree.body:
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(stmt)
        table_name = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if table_name not in table_names:
            continue
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Set | ast.Tuple | ast.List)
        ):
            continue
        seen: set[str] = set()
        for item in value.args[0].elts:
            item_value = _literal_string_value(item)
            if item_value is None:
                continue
            if item_value in seen:
                duplicates.append((table_name, item_value, item.lineno))
            seen.add(item_value)
    return tuple(duplicates)


def _dict_literal_tuple_values(
    tree: ast.Module,
    *,
    table_names: frozenset[str],
) -> tuple[tuple[str, str, tuple[str, ...], int], ...]:
    """Return literal tuple string values in selected module-level dict tables."""

    values: list[tuple[str, str, tuple[str, ...], int]] = []
    for stmt in tree.body:
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(stmt)
        table_name = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if table_name not in table_names or not isinstance(value, ast.Dict):
            continue
        for key_node, value_node in zip(value.keys, value.values, strict=True):
            if key_node is None:
                continue
            key = _literal_string_value(key_node)
            if key is None or not isinstance(value_node, ast.Tuple):
                continue
            values.append((table_name, key, _ordered_tuple_string_constants(value_node), key_node.lineno))
    return tuple(values)


def _dict_literal_string_values(
    tree: ast.Module,
    *,
    table_names: frozenset[str],
) -> tuple[tuple[str, str, str, int], ...]:
    """Return literal string values in selected module-level dict tables."""

    values: list[tuple[str, str, str, int]] = []
    for stmt in tree.body:
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(stmt)
        table_name = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if table_name not in table_names or not isinstance(value, ast.Dict):
            continue
        for key_node, value_node in zip(value.keys, value.values, strict=True):
            if key_node is None:
                continue
            key = _literal_string_value(key_node)
            value_text = _literal_string_value(value_node)
            if key is None or value_text is None:
                continue
            values.append((table_name, key, value_text, key_node.lineno))
    return tuple(values)


def _module_frozenset_string_constant(tree: ast.Module, name: str) -> frozenset[str] | None:
    """Return a module-level frozenset string constant, if it is literal."""

    for stmt in tree.body:
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(stmt)
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset"
            and len(value.args) == 1
        ):
            return None
        values = _ordered_tuple_string_constants(value.args[0])
        if not values:
            return None
        return frozenset(values)
    return None


def _read_text_if_present(path: Path) -> str | None:
    cache_key = _file_cache_key(path)
    if cache_key is None:
        return None
    cached = _TEXT_CACHE.get(path)
    if cached is not None and cached[0] == cache_key:
        return cached[1]
    text = path.read_text(encoding="utf-8")
    _TEXT_CACHE[path] = (cache_key, text)
    return text


def _definition_index(
    tree: ast.Module,
) -> tuple[
    dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    dict[str, ast.ClassDef],
]:
    """Return first definitions by name from one cached module traversal."""

    cached = _DEFINITION_INDEX_CACHE.get(tree)
    if cached is not None:
        return cached
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    classes: dict[str, ast.ClassDef] = {}
    for node in _walk_ast(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.setdefault(node.name, node)
        elif isinstance(node, ast.ClassDef):
            classes.setdefault(node.name, node)
    result = functions, classes
    _DEFINITION_INDEX_CACHE[tree] = result
    return result


def _find_function(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the first function definition with the requested name."""

    functions, _classes = _definition_index(tree)
    return functions.get(name)


def _find_class(tree: ast.Module, name: str) -> ast.ClassDef | None:
    """Return the first class definition with the requested name."""

    _functions, classes = _definition_index(tree)
    return classes.get(name)


def _is_protected_import(module: str) -> bool:
    return module.startswith(_PROTECTED_IMPORT_PREFIXES)


def _postprocess_import_paths(root: Path) -> tuple[Path, ...]:
    """Return deterministic root compatibility modules guarded by import ownership."""

    return tuple(sorted(root.glob("decompiler_postprocess_*.py")))


def _check_postprocess_file_imports(
    root: Path,
    path: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Check protected imports for one root postprocess compatibility module."""

    violations: list[ArchitectureViolation] = []
    tree = _parse_python(path)
    allowed = _POSTPROCESS_LEGACY_IMPORT_ALLOWLIST.get(path.name, frozenset())
    for module in _import_modules(tree):
        if _is_protected_import(module) and module not in allowed:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "postprocess-protected-import",
                    f"{module!r} is not an admitted compatibility exception",
                )
            )
    return tuple(violations)


def _check_postprocess_imports(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Check protected imports for every root postprocess compatibility module."""

    return tuple(
        violation
        for path in _postprocess_import_paths(root)
        for violation in _check_postprocess_file_imports(root, path)
    )


def _check_postprocess_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    paths = [root / "decompiler_postprocess.py"] if (root / "decompiler_postprocess.py").exists() else []
    paths.extend(sorted(root.glob("decompiler_postprocess_*.py")))
    for path in paths:
        marker = _POSTPROCESS_HEADER_MARKERS.get(path.name)
        if marker is None:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "postprocess-header",
                    "new postprocess module must declare allowed work, forbidden work, and owning layer",
                )
            )
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not _contains_marker(doc, marker):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "postprocess-header",
                    f"missing guard marker {marker!r}",
                )
            )
    return tuple(violations)


def _check_postprocess_source_text_recovery(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for path in sorted(root.glob("decompiler_postprocess_*.py")):
        tree = _parse_python(path)
        for node in _walk_ast(tree):
            uses_source_lines = (
                (isinstance(node, ast.Attribute) and node.attr == "source_lines")
                or (isinstance(node, ast.Name) and node.id == "source_lines")
                or (isinstance(node, ast.Constant) and node.value == "source_lines")
            )
            if uses_source_lines:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "postprocess-source-text-recovery",
                        "postprocess must not recover semantic names or facts by parsing COD/source text lines",
                    )
                )
                break
    return tuple(violations)


def _relative_import_module(node: ast.ImportFrom) -> str:
    return f"{'.' * node.level}{node.module or ''}"


def _semantic_layer_import_targets(tree: ast.Module) -> tuple[str, ...]:
    modules: list[str] = []
    for node in _walk_ast(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = _relative_import_module(node)
            if node.module:
                modules.extend(f"{module}.{alias.name}" for alias in node.names)
            else:
                modules.extend(f"{module}{alias.name}" for alias in node.names)
    return tuple(modules)


def _is_postprocess_import(module: str) -> bool:
    return (
        "decompiler_postprocess" in module or module.startswith(("angr_platforms.X86_16.postprocess", ".postprocess", "..postprocess"))
    )


def _semantic_layer_no_postprocess_import_paths(root: Path) -> tuple[Path, ...]:
    """Return deterministic earlier-layer modules guarded from Rewrite imports."""

    paths: list[Path] = []
    for filename in sorted(_ROOT_SEMANTIC_NO_POSTPROCESS_IMPORTS):
        path = root / filename
        if path.exists():
            paths.append(path)
    for layer_name in sorted(_SEMANTIC_LAYER_DIRS):
        layer_root = root / layer_name
        if not layer_root.exists():
            continue
        paths.extend(sorted(layer_root.rglob("*.py")))
    return tuple(paths)


def _check_semantic_layer_file_does_not_import_postprocess(
    root: Path,
    path: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Check that one earlier-layer module does not depend on Rewrite."""

    violations: list[ArchitectureViolation] = []
    rel = _relative(path, root)
    allowed = _SEMANTIC_LAYER_POSTPROCESS_IMPORT_ALLOWLIST.get(rel, frozenset())
    tree = _parse_python(path)
    for module in _semantic_layer_import_targets(tree):
        if _is_postprocess_import(module) and module not in allowed:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "semantic-layer-postprocess-import",
                    f"{module!r} makes an earlier semantic layer depend on rewrite/postprocess",
                )
            )
    return tuple(violations)


def _check_semantic_layers_do_not_import_postprocess(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Check that every earlier-layer module remains independent of Rewrite."""

    return tuple(
        violation
        for path in _semantic_layer_no_postprocess_import_paths(root)
        for violation in _check_semantic_layer_file_does_not_import_postprocess(root, path)
    )


def _check_cli_imports(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Reject CLI dependencies and calls that cross the orchestration boundary."""
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []
    for module in _import_modules(tree):
        if not module.startswith("angr_platforms.X86_16."):
            continue
        if module not in _CLI_ALLOWED_X86_16_IMPORTS:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-x86-16-import",
                    f"{module!r} is not in the CLI orchestration compatibility allowlist",
                )
            )
    forbidden_imports = (
        _imported_names_from_module(
            tree,
            "angr_platforms.X86_16.decompiler_postprocess_calls",
        )
        & _CLI_FORBIDDEN_SEMANTIC_CALLS
    )
    for name in sorted(forbidden_imports):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "cli-semantic-mutation",
                f"{name!r} mutates semantic AST state and must run in the validated X86_16 pipeline",
            )
        )
    imported_violations = set(forbidden_imports)
    for node in _walk_ast(tree):
        if not isinstance(node, ast.Call):
            continue
        called_name: str | None
        if isinstance(node.func, ast.Name):
            called_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            called_name = node.func.attr
        else:
            called_name = None
        if called_name not in _CLI_FORBIDDEN_SEMANTIC_CALLS or called_name in imported_violations:
            continue
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "cli-semantic-mutation",
                f"{called_name!r} mutates semantic AST state and must run in the validated X86_16 pipeline",
            )
        )
    doc = ast.get_docstring(tree) or ""
    marker = "must not become the owner of decompiler semantics"
    if not _contains_marker(doc, marker):
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "cli-header",
                f"missing guard marker {marker!r}",
            )
        )
    return tuple(violations)


def _check_cli_c_text_cleanup(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _BANNED_C_TEXT_SEMANTIC_HELPERS:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-c-text-semantic-recovery",
                    f"{node.name!r} recovers semantics from rendered C text; move proof to X86_16 layers",
                )
            )
    return tuple(violations)


def _check_cli_fallback_source_body_recovery(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in _BANNED_CLI_FALLBACK_SOURCE_HELPERS
        ):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-fallback-source-body-recovery",
                    "fallback decompilation must not replace failed recovery with COD/source function bodies",
                )
            )
            break
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
            alias.name in _BANNED_CLI_FALLBACK_SOURCE_HELPERS for alias in node.names
        ):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-fallback-source-body-recovery",
                    "fallback decompilation must not replace failed recovery with COD/source function bodies",
                )
            )
            break
        uses_banned_name = (isinstance(node, ast.Name) and node.id in _BANNED_CLI_FALLBACK_SOURCE_HELPERS) or (
            isinstance(node, ast.Attribute) and node.attr in _BANNED_CLI_FALLBACK_SOURCE_HELPERS
        )
        if uses_banned_name:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-fallback-source-body-recovery",
                    "fallback decompilation must not replace failed recovery with COD/source function bodies",
                )
            )
            break
    return tuple(violations)


def _check_cli_source_header_recovery_inactive(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    guarded_functions = {
        "_materialize_annotated_cod_declarations_text",
        "_repair_missing_cod_function_header_text",
        "_finalize_cod_annotation_text_8616",
        "_format_known_helper_calls",
        "_annotate_cod_proc_output",
    }
    banned_calls = {
        "_source_decl_from_cod_source_lines",
        "_source_args_from_cod_source_lines",
        "_source_function_prototype_decls_from_cod_source_lines",
        "_restore_codegen_header_for_unmaterialized_source_args_8616",
        "_source_void_forward_decl_8616",
    }
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in guarded_functions:
            continue
        for child in _walk_ast(node):
            if not isinstance(child, ast.Call):
                if (
                    isinstance(child, ast.Subscript)
                    and isinstance(child.value, ast.Attribute)
                    and child.value.attr == "call_names"
                ):
                    violations.append(
                        ArchitectureViolation(
                            _relative(path, REPO_ROOT),
                            "cli-source-header-recovery",
                            "CLI postprocess must not rewrite emitted calls by indexing COD call-name evidence",
                        )
                    )
                    return tuple(violations)
                continue
            call_name = None
            if isinstance(child.func, ast.Name):
                call_name = child.func.id
            elif isinstance(child.func, ast.Attribute):
                call_name = child.func.attr
            if call_name in banned_calls:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cli-source-header-recovery",
                        "CLI postprocess must not repair function headers or prototypes from COD/source declarations",
                    )
                )
                return tuple(violations)
    return tuple(violations)


def _check_cli_acceptance_not_source_evidence_gated(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []

    for node in _walk_ast(tree):
        imports_source_sidecar = (
            isinstance(node, ast.ImportFrom) and (node.module or "") == "inertia_decompiler.source_sidecar"
        )
        if imports_source_sidecar:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-source-evidence-acceptance-gate",
                    "CLI acceptance must not load source sidecars for emitted C validation",
                )
            )
            break

    for helper_name in ("_with_source_evidence_comments_8616", "_source_evidence_payload_for_function_8616"):
        if _find_function(tree, helper_name) is not None:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-source-evidence-acceptance-gate",
                    f"CLI acceptance must not define obsolete source-evidence helper {helper_name}",
                )
            )

    guarded = _find_function(tree, "_validated_generated_c_acceptance_8616")
    if guarded is None:
        return tuple(violations)
    banned_calls = {
        "assess_source_backed_c_text",
        "_source_evidence_return_blocker_8616",
        "_missing_expected_return_values_from_embedded_evidence_8616",
        "_missing_expected_calls_from_embedded_evidence_8616",
        "_missing_expected_call_multiplicity_8616",
        "_arg_class_violations_8616",
        "_call_order_gate_violations_8616",
        "_loop_presence_violation_8616",
        "_loop_hoisted_call_violation_8616",
        "_side_effect_floor_violation_8616",
        "_stack_slot_evidence_violation_8616",
    }
    for node in _walk_ast(guarded):
        if not isinstance(node, ast.Call):
            continue
        call_name = None
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name in banned_calls:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-source-evidence-acceptance-gate",
                    "CLI acceptance must not accept or reject emitted C by comparing against source/COD evidence",
                ),
            )
    return tuple(violations)


def _check_cli_not_source_backed_quality_gated(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)

    def _function_returns_constant_zero(function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
        if function is None or len(function.body) != 1:
            return False
        stmt = function.body[0]
        return isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value == 0

    cod_signature_score = _find_function(tree, "_cod_signature_and_stack_alias_score_8616")
    if cod_signature_score is not None and not _function_returns_constant_zero(cod_signature_score):
        return (
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "cli-source-backed-quality-gate",
                "CLI must not rank emitted C by COD stack aliases or source signatures",
            ),
        )

    expected_globals = _find_function(tree, "_candidate_expected_global_names_8616")
    if expected_globals is not None:
        for node in _walk_ast(expected_globals):
            if (isinstance(node, ast.Attribute) and node.attr == "global_names") or (
                isinstance(node, ast.Constant) and node.value == "global_names"
            ):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cli-source-backed-quality-gate",
                        "CLI must not rank emitted C by COD global-name coverage",
                    ),
                )

    banned_calls = {
        "assess_source_backed_c_text",
        "_source_evidence_return_blocker_8616",
        "_missing_expected_return_values_from_embedded_evidence_8616",
        "_missing_expected_calls_from_embedded_evidence_8616",
        "_missing_expected_call_multiplicity_8616",
        "_arg_class_violations_8616",
        "_call_order_gate_violations_8616",
        "_loop_presence_violation_8616",
        "_loop_hoisted_call_violation_8616",
        "_side_effect_floor_violation_8616",
        "_stack_slot_evidence_violation_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_expected_source_call_arity_counter_8616",
        "_call_arity_from_call_text_8616",
        "_rendered_call_arity_counter_8616",
        "_split_call_args_for_score_8616",
        "_cod_proc_has_call_heavy_helper_profile",
        "collect_local_source_sidecar_return_types",
        "render_local_source_sidecar_function",
    }
    for node in _walk_ast(tree):
        if (
            (isinstance(node, ast.Attribute) and node.attr == "call_sources")
            or (isinstance(node, ast.Constant) and node.value == "call_sources")
            or (isinstance(node, ast.Name) and node.id == "call_sources")
        ):
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-source-backed-quality-gate",
                    "CLI must not use COD call_sources text as emitted C recovery, scoring, or retry evidence",
                ),
            )
        if isinstance(node, ast.ImportFrom):
            imported = {alias.name for alias in node.names}
            if imported.intersection(banned_calls):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cli-source-backed-quality-gate",
                        "CLI must not import source/COD evidence gates for emitted C acceptance, ranking, or cache policy",
                    ),
                )
        if isinstance(node, ast.Import):
            imported = {alias.name.rsplit(".", 1)[-1] for alias in node.names}
            if imported.intersection(banned_calls):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cli-source-backed-quality-gate",
                        "CLI must not import source/COD evidence gates for emitted C acceptance, ranking, or cache policy",
                    ),
                )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in banned_calls:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-source-backed-quality-gate",
                    "CLI must not define source/COD evidence gates for emitted C acceptance, ranking, or cache policy",
                ),
            )
        if not isinstance(node, ast.Call):
            continue
        call_name = None
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name in banned_calls:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cli-source-backed-quality-gate",
                    "CLI must not accept, reject, rank, or cache-bypass C by comparing emitted code against source/COD evidence",
                ),
            )
    return ()


def _check_cli_ast_cod_callee_names_inert(ast_path: Path, cli_path: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    if ast_path.exists():
        tree = _parse_python(ast_path)
        helper = _find_function(tree, "_attach_cod_callee_names")
        if helper is not None:
            for node in _walk_ast(helper):
                if (
                    (isinstance(node, ast.Attribute) and node.attr == "call_names")
                    or (isinstance(node, ast.Constant) and node.value == "call_names")
                    or (isinstance(node, ast.Name) and node.id == "call_names")
                    or (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "annotate_function"
                    )
                ):
                    violations.append(
                        ArchitectureViolation(
                            _relative(ast_path, REPO_ROOT),
                            "cli-ast-cod-callee-name-recovery",
                            "CLI AST rewrite must not assign callee names/signatures from COD call-name order",
                        )
                    )
                    break
    if cli_path.exists():
        tree = _parse_python(cli_path)
        for node in _walk_ast(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = None
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            if call_name == "_attach_cod_callee_names":
                violations.append(
                    ArchitectureViolation(
                        _relative(cli_path, REPO_ROOT),
                        "cli-ast-cod-callee-name-recovery",
                        "CLI orchestration must not run COD call-name AST callee recovery",
                    )
                )
                break
    return tuple(violations)


def _check_cli_cod_call_names_not_semantic(
    cli_path: Path, helper_path: Path, text_postprocess_path: Path
) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []

    if cli_path.exists():
        tree = _parse_python(cli_path)
        register_helper = _find_function(tree, "_register_direct_call_target_function_stubs")
        if register_helper is not None:
            for node in _walk_ast(register_helper):
                uses_call_names = (
                    (isinstance(node, ast.Attribute) and node.attr == "call_names")
                    or (isinstance(node, ast.Constant) and node.value == "call_names")
                    or (isinstance(node, ast.Name) and node.id == "call_names")
                )
                if uses_call_names:
                    violations.append(
                        ArchitectureViolation(
                            _relative(cli_path, REPO_ROOT),
                            "cli-cod-call-name-stub-recovery",
                            "CLI must not use COD call_names to create or name direct-call stubs",
                        )
                    )
                    break
        for banned_name in {"_call_name_by_callsite_8616", "_proven_cod_call_name_for_candidates_8616"}:
            if _find_function(tree, banned_name) is not None:
                violations.append(
                    ArchitectureViolation(
                        _relative(cli_path, REPO_ROOT),
                        "cli-cod-call-name-stub-recovery",
                        "CLI must not use COD call_names to create or name direct-call stubs",
                    )
                )
                break

    if helper_path.exists():
        tree = _parse_python(helper_path)
        known_helper = _find_function(tree, "_known_helper_declarations")
        if known_helper is not None:
            inert = False
            if len(known_helper.body) == 1:
                stmt = known_helper.body[0]
                inert = isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.List) and len(stmt.value.elts) == 0
            if not inert:
                violations.append(
                    ArchitectureViolation(
                        _relative(helper_path, REPO_ROOT),
                        "cli-cod-call-name-helper-decls",
                        "CLI must not synthesize helper declarations from COD call_names",
                    )
                )
            for node in _walk_ast(known_helper):
                uses_call_names = (
                    (isinstance(node, ast.Attribute) and node.attr == "call_names")
                    or (isinstance(node, ast.Constant) and node.value == "call_names")
                    or (isinstance(node, ast.Name) and node.id == "call_names")
                )
                if uses_call_names:
                    violations.append(
                        ArchitectureViolation(
                            _relative(helper_path, REPO_ROOT),
                            "cli-cod-call-name-helper-decls",
                            "CLI must not synthesize helper declarations from COD call_names",
                        )
                    )
                    break

    if text_postprocess_path.exists():
        tree = _parse_python(text_postprocess_path)
        generic_prototype_helper = _find_function(tree, "_materialize_missing_direct_call_prototypes_text")
        if generic_prototype_helper is not None:
            inert = False
            if len(generic_prototype_helper.body) == 1:
                stmt = generic_prototype_helper.body[0]
                inert = isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name) and stmt.value.id == "c_text"
            if not inert:
                violations.append(
                    ArchitectureViolation(
                        _relative(text_postprocess_path, REPO_ROOT),
                        "cli-text-prototype-recovery",
                        "CLI text postprocess must not synthesize missing direct-call prototypes",
                    )
                )
        materialize_helper = _find_function(tree, "_collect_missing_annotated_cod_declarations")
        if materialize_helper is not None:
            for node in _walk_ast(materialize_helper):
                uses_call_names = (
                    (isinstance(node, ast.Attribute) and node.attr == "call_names")
                    or (isinstance(node, ast.Constant) and node.value == "call_names")
                    or (isinstance(node, ast.Name) and node.id == "call_names")
                )
                if uses_call_names:
                    violations.append(
                        ArchitectureViolation(
                            _relative(text_postprocess_path, REPO_ROOT),
                            "cli-cod-call-name-prototype-recovery",
                            "CLI text postprocess must not synthesize prototypes from COD call_names",
                        )
                    )
                    break

    return tuple(violations)


def _function_returns_name(function: ast.FunctionDef | ast.AsyncFunctionDef | None, name: str) -> bool:
    if function is None:
        return False
    body = _body_without_leading_docstring(function.body)
    if len(body) != 1:
        return False
    stmt = body[0]
    return isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name) and stmt.value.id == name


def _body_without_leading_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if not body:
        return body
    first = body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return body[1:]
    return body


def _check_cli_cod_stack_alias_rewrites_inert(
    ast_path: Path, text_postprocess_path: Path
) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    if ast_path.exists():
        tree = _parse_python(ast_path)
        helper = _find_function(tree, "_attach_cod_variable_names")
        if helper is not None and not _function_returns_only_constant(helper, False):
            violations.append(
                ArchitectureViolation(
                    _relative(ast_path, REPO_ROOT),
                    "cli-cod-stack-alias-rewrite",
                    "CLI AST rewrite must not rename recovered variables from COD stack_aliases",
                )
            )
    if text_postprocess_path.exists():
        tree = _parse_python(text_postprocess_path)
        helper = _find_function(tree, "_collapse_annotated_stack_aliases_text")
        if helper is not None and not _function_returns_name(helper, "c_text"):
            violations.append(
                ArchitectureViolation(
                    _relative(text_postprocess_path, REPO_ROOT),
                    "cli-cod-stack-alias-rewrite",
                    "CLI text cleanup must not collapse or rename stack variables from COD stack_alias annotations",
                )
            )
        for helper_name in ("_annotate_cod_proc_output", "_normalize_mk_fp_segment_names"):
            helper = _find_function(tree, helper_name)
            if helper is not None and not _function_returns_name(helper, "c_text"):
                violations.append(
                    ArchitectureViolation(
                        _relative(text_postprocess_path, REPO_ROOT),
                        "cli-cod-stack-alias-rewrite",
                        "CLI text cleanup must not annotate or rewrite emitted C from COD stack/global/call metadata",
                    )
                )
        simplify_helper = _find_function(tree, "_simplify_x86_16_stack_byte_pointers")
        if simplify_helper is not None:
            for node in _walk_ast(simplify_helper):
                if (
                    (isinstance(node, ast.Attribute) and node.attr == "stack_aliases")
                    or (isinstance(node, ast.Constant) and node.value == "stack_aliases")
                    or (isinstance(node, ast.Name) and node.id == "stack_aliases")
                ):
                    violations.append(
                        ArchitectureViolation(
                            _relative(text_postprocess_path, REPO_ROOT),
                            "cli-cod-stack-alias-rewrite",
                            "CLI text cleanup must not infer stack pointer names from COD stack_aliases",
                        )
                    )
                    break
        globals_helper = _find_function(tree, "_materialize_missing_synthetic_global_declarations_text")
        if globals_helper is not None:
            for node in _walk_ast(globals_helper):
                if (
                    (isinstance(node, ast.Attribute) and node.attr == "global_names")
                    or (isinstance(node, ast.Constant) and node.value == "global_names")
                    or (isinstance(node, ast.Name) and node.id == "global_names")
                ):
                    violations.append(
                        ArchitectureViolation(
                            _relative(text_postprocess_path, REPO_ROOT),
                            "cli-cod-stack-alias-rewrite",
                            "CLI text cleanup must not materialize declarations from COD global_names",
                        )
                    )
                    break
    return tuple(violations)


def _check_cod_source_rewrites_are_inert(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(tree):
        uses_source_lines = (
            (isinstance(node, ast.Attribute) and node.attr in {"source_lines", "source_line_set"})
            or (isinstance(node, ast.Constant) and node.value in {"source_lines", "source_line_set"})
            or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "has_source_lines"
            )
        )
        if uses_source_lines:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cod-source-rewrite-active",
                    "cod_source_rewrites.py must stay an inert compatibility/reporting surface",
                )
            )
            break
    return tuple(violations)


def _check_source_annotations_do_not_materialize_types(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []
    guarded_functions = {"_apply_source_prototype_annotations_8616", "_source_function_pointer_local_types_8616"}
    banned_calls = {"annotate_function", "_parse_c_prototype_8616", "_source_args_from_cod_source_lines"}

    def _function_returns_only_constant(function: ast.FunctionDef | ast.AsyncFunctionDef | None, value: object) -> bool:
        if function is None:
            return False
        body = _body_without_leading_docstring(function.body)
        if len(body) != 1:
            return False
        stmt = body[0]
        return isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value is value

    inert_none_helpers = {
        "_source_decl_from_cod_source_lines",
        "_source_decl_from_cod_source_lines_cached_8616",
        "_source_args_from_cod_source_lines",
    }
    for helper_name in inert_none_helpers:
        if not _function_returns_only_constant(_find_function(tree, helper_name), None):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "source-annotation-semantic-materialization",
                    "source annotations must not parse COD/source text into declarations or arguments",
                )
            )
            return tuple(violations)

    if not _function_returns_only_constant(_find_function(tree, "_apply_known_helper_signatures"), False):
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "source-annotation-semantic-materialization",
                "COD call names must not materialize helper signatures",
            )
        )
        return tuple(violations)

    for node in _walk_ast(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in guarded_functions:
            continue
        for child in _walk_ast(node):
            if isinstance(child, ast.Call):
                call_name = None
                if isinstance(child.func, ast.Name):
                    call_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    call_name = child.func.attr
                if call_name in banned_calls:
                    violations.append(
                        ArchitectureViolation(
                            _relative(path, REPO_ROOT),
                            "source-annotation-semantic-materialization",
                            "source annotations must not materialize prototypes, argument names, or local types",
                        )
                    )
                    return tuple(violations)
            if isinstance(child, ast.Name) and child.id == "SimTypePointer":
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "source-annotation-semantic-materialization",
                        "source annotations must not materialize prototypes, argument names, or local types",
                    )
                )
                return tuple(violations)

    apply_metadata = _find_function(tree, "apply_x86_16_metadata_annotations")
    if apply_metadata is not None:
        for child in _walk_ast(apply_metadata):
            uses_banned_metadata = (
                (isinstance(child, ast.Attribute) and child.attr in {"stack_aliases", "source_lines", "call_names"})
                or (isinstance(child, ast.Constant) and child.value in {"stack_aliases", "source_lines", "call_names"})
                or (isinstance(child, ast.Name) and child.id in {"stack_aliases", "source_lines", "call_names"})
            )
            calls_semantic_materializer = isinstance(child, ast.Call) and (
                (isinstance(child.func, ast.Name) and child.func.id in {"annotate_function", "known_cod_object_spec"})
                or (
                    isinstance(child.func, ast.Attribute)
                    and child.func.attr in {"annotate_function", "known_cod_object_spec"}
                )
            )
            if uses_banned_metadata or calls_semantic_materializer:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "source-annotation-semantic-materialization",
                        "metadata annotations must not materialize stack, type, prototype, or helper semantics from COD/source evidence",
                    )
                )
                return tuple(violations)
    return tuple(violations)


def _check_lowering_not_cod_name_backed(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    lowering_root = root / "lowering"
    if not lowering_root.exists():
        return ()
    for path in sorted(lowering_root.glob("*.py")):
        tree = _parse_python(path)
        for node in _walk_ast(tree):
            uses_cod_global_names = (
                (isinstance(node, ast.Attribute) and node.attr == "global_names")
                or (isinstance(node, ast.Constant) and node.value == "global_names")
                or (isinstance(node, ast.Name) and node.id == "global_names")
            )
            if uses_cod_global_names:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "lowering-cod-name-evidence",
                        "lowering must not recover storage names from COD global_names; use labels, synthetic globals, or recovered facts",
                    )
                )
                break
    return tuple(violations)


def _check_lowering_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    lowering_root = root / "lowering"
    for filename, markers in _LOWERING_OWNERSHIP_HEADER_MARKERS.items():
        path = lowering_root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "lowering-module-ownership-header",
                    f"missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_semantic_layer_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    repo_root = root.parents[2] if len(root.parents) >= 3 else REPO_ROOT
    for layer, layer_markers in _SEMANTIC_LAYER_OWNERSHIP_MARKERS.items():
        layer_root = root / layer
        if not layer_root.exists():
            continue
        for path in sorted(layer_root.rglob("*.py")):
            markers = layer_markers
            if layer == "analysis":
                markers = _ANALYSIS_LAYER_HEADER_MARKERS.get(path.name, layer_markers)
            doc = ast.get_docstring(_parse_python(path)) or ""
            missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
            if missing_markers:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, repo_root),
                        "semantic-layer-ownership-header",
                        f"{layer} module missing ownership markers: "
                        f"{', '.join(repr(marker) for marker in missing_markers)}",
                    )
                )
    return tuple(violations)


def _check_validation_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    validation_paths = (
        sorted(root.glob("tail_validation*.py"))
        + sorted(root.glob("validation*.py"))
        + sorted((root / "validation").glob("*.py"))
    )
    for path in validation_paths:
        if path.name == "__init__.py":
            continue
        marker_key = path.relative_to(root).as_posix()
        markers = _VALIDATION_HEADER_MARKERS.get(marker_key)
        if markers is None:
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "validation-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_recompilable_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for path in sorted(root.glob("recompilable_*.py")):
        markers = _RECOMPILABLE_HEADER_MARKERS.get(path.name)
        if markers is None:
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "recompilable-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_root_structuring_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, markers in _ROOT_STRUCTURING_HEADER_MARKERS.items():
        path = root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "root-structuring-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_optional_evidence_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, markers in _OPTIONAL_EVIDENCE_HEADER_MARKERS.items():
        path = root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "optional-evidence-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_recovery_reporting_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, markers in _RECOVERY_REPORTING_HEADER_MARKERS.items():
        path = root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "recovery-reporting-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_frontend_runtime_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, markers in _FRONTEND_RUNTIME_HEADER_MARKERS.items():
        path = root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "frontend-runtime-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_recovery_metadata_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, markers in _RECOVERY_METADATA_HEADER_MARKERS.items():
        path = root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "recovery-metadata-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_helper_boundary_ownership_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, markers in _HELPER_BOUNDARY_HEADER_MARKERS.items():
        path = root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "helper-boundary-ownership-header",
                    f"{path.name} missing ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_root_module_docstrings(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for path in sorted(root.glob("*.py")):
        if path.name == "__init__.py":
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not doc.strip():
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "root-module-docstring",
                    "root X86_16 modules must state their architecture ownership contract",
                )
            )
    return tuple(violations)


def _check_x86_16_module_layer_headers(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Require every X86_16 module docstring to declare its architecture layer."""

    violations: list[ArchitectureViolation] = []
    for path in sorted(root.rglob("*.py")):
        doc = ast.get_docstring(_parse_python(path)) or ""
        if "Layer:" not in doc:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "x86-16-module-layer-header",
                    "X86_16 module docstrings must include a 'Layer:' architecture ownership header",
                )
            )
    return tuple(violations)


def _check_python_module_layer_headers(
    root: Path,
    *,
    rule: str,
    expected_layer: str,
) -> tuple[ArchitectureViolation, ...]:
    """Require Python modules under `root` to declare the expected architecture layer."""

    violations: list[ArchitectureViolation] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        if expected_layer not in doc:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    rule,
                    f"module docstring must include '{expected_layer}'",
                )
            )
    return tuple(violations)


def _check_pipeline_lane_contracts_use_dot_access(root: Path) -> tuple[ArchitectureViolation, ...]:
    path = root / "pipeline" / "contracts.py"
    if not path.exists():
        return ()
    lane_names = {"stack_lane", "condition_lane", "lane"}
    lane_fields = {"name", "raw", "normalized", "classified", "bound", "materialized", "verified", "failures"}
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(_parse_python(path)):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "setattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in lane_names
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name not in lane_fields:
            continue
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "owned-lane-dot-access",
                f"SemanticLaneState field {node.args[0].id}.{field_name} must use dot access, not {node.func.id}()",
            )
        )
    return tuple(violations)


def _check_postprocess_stage_runs_pipeline_contract_gate(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Require the main postprocess stage to run closed-loop pipeline contracts."""

    path = root / "decompiler_postprocess_stage.py"
    if not path.exists():
        return ()
    tree = _parse_python(path)
    imported_names = _imported_names_from_module(tree, ".pipeline.contracts")
    violations: list[ArchitectureViolation] = []
    if "assert_pipeline_contracts_8616" not in imported_names:
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "postprocess-stage-pipeline-contract-gate",
                "postprocess stage must import assert_pipeline_contracts_8616 from pipeline.contracts",
            )
        )

    gate = _find_function(tree, "_run_pipeline_contract_gate")
    if gate is None:
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "postprocess-stage-pipeline-contract-gate",
                "postprocess stage must keep _run_pipeline_contract_gate before rewrite",
            )
        )
        return tuple(violations)

    has_gate_call = any(
        isinstance(node, ast.Call) and _call_name(node.func) == "assert_pipeline_contracts_8616"
        for node in _walk_ast(gate)
    )
    if not has_gate_call:
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "postprocess-stage-pipeline-contract-gate",
                "_run_pipeline_contract_gate must call assert_pipeline_contracts_8616(codegen)",
            )
        )
    return tuple(violations)


def _check_identical_assignment_arm_structuring_ownership(
    root: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Require redundant assignment-diamond mutation to remain Structuring-owned."""

    owner_path = root / "structuring" / "return_chains.py"
    stage_path = root / "decompiler_structuring_stage.py"
    postprocess_paths = tuple(sorted(root.glob("decompiler_postprocess_*.py")))
    if not owner_path.exists() and not stage_path.exists() and not postprocess_paths:
        return ()

    rule = "identical-assignment-arm-structuring-owner"
    owner_names = (
        "identical_assignment_arm_condition_8616",
        "collapse_surplus_identical_assignment_arms_8616",
    )
    violations: list[ArchitectureViolation] = []
    if owner_path.exists():
        owner_tree = _parse_python(owner_path)
        for name in owner_names:
            if _find_function(owner_tree, name) is None:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(owner_path, REPO_ROOT),
                        rule,
                        f"Structuring owner must define {name}",
                    )
                )
    else:
        violations.append(
            ArchitectureViolation(
                _relative(owner_path, REPO_ROOT),
                rule,
                "redundant assignment-diamond owner is missing",
            )
        )

    if stage_path.exists():
        stage_tree = _parse_python(stage_path)
        imported_names = _imported_names_from_module(
            stage_tree,
            ".structuring.return_chains",
        )
        collapse_name = "collapse_surplus_identical_assignment_arms_8616"
        if collapse_name not in imported_names:
            violations.append(
                ArchitectureViolation(
                    _relative(stage_path, REPO_ROOT),
                    rule,
                    f"structuring stage must import {collapse_name} from structuring.return_chains",
                )
            )
        stage_function = _find_function(
            stage_tree,
            "_materialize_structuring_return_chains_8616",
        )
        has_collapse_call = stage_function is not None and any(
            isinstance(node, ast.Call) and _call_name(node.func) == collapse_name for node in _walk_ast(stage_function)
        )
        if not has_collapse_call:
            violations.append(
                ArchitectureViolation(
                    _relative(stage_path, REPO_ROOT),
                    rule,
                    "_materialize_structuring_return_chains_8616 must call the Structuring-owned collapse",
                )
            )
    else:
        violations.append(
            ArchitectureViolation(
                _relative(stage_path, REPO_ROOT),
                rule,
                "structuring stage entry point is missing",
            )
        )

    for path in postprocess_paths:
        tree = _parse_python(path)
        for name in owner_names:
            if _find_function(tree, name) is not None:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        rule,
                        f"{name} must not be defined in postprocess",
                    )
                )
    return tuple(violations)


def _check_terminal_call_result_structuring_ownership(
    root: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Require terminal call-result return materialization to remain in Structuring."""

    owner_path = root / "structuring" / "return_chains.py"
    stage_path = root / "decompiler_structuring_stage.py"
    postprocess_paths = tuple(
        sorted(
            {
                *root.glob("decompiler_postprocess_*.py"),
                *(root / "postprocess").rglob("*.py"),
            }
        )
    )
    if not owner_path.exists() and not stage_path.exists() and not postprocess_paths:
        return ()

    rule = "terminal-call-result-structuring-owner"
    materializer_name = "materialize_terminal_call_result_return_8616"
    owner_class_names = (
        "TerminalCallResultReturnCallbacks8616",
        "TerminalCallResultReturnStats8616",
        "TerminalCallResultReturnStatus8616",
    )
    owner_names = (*owner_class_names, materializer_name)
    violations: list[ArchitectureViolation] = []
    if owner_path.exists():
        owner_tree = _parse_python(owner_path)
        if _find_function(owner_tree, materializer_name) is None:
            violations.append(
                ArchitectureViolation(
                    _relative(owner_path, REPO_ROOT),
                    rule,
                    f"Structuring owner must define {materializer_name}",
                )
            )
        owner_classes = {node.name for node in _walk_ast(owner_tree) if isinstance(node, ast.ClassDef)}
        for class_name in owner_class_names:
            if class_name not in owner_classes:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(owner_path, REPO_ROOT),
                        rule,
                        f"Structuring owner must define typed contract {class_name}",
                    )
                )
    else:
        violations.append(
            ArchitectureViolation(
                _relative(owner_path, REPO_ROOT),
                rule,
                "terminal call-result return owner is missing",
            )
        )

    if stage_path.exists():
        stage_tree = _parse_python(stage_path)
        imported_names = _imported_names_from_module(
            stage_tree,
            ".structuring.return_chains",
        )
        if materializer_name not in imported_names:
            violations.append(
                ArchitectureViolation(
                    _relative(stage_path, REPO_ROOT),
                    rule,
                    f"structuring stage must import {materializer_name} from structuring.return_chains",
                )
            )

        stage_wrapper_name = "_materialize_structuring_terminal_call_result_return_8616"
        stage_wrapper = _find_function(stage_tree, stage_wrapper_name)
        wrapper_calls_owner = stage_wrapper is not None and any(
            isinstance(node, ast.Call) and _call_name(node.func) == materializer_name
            for node in _walk_ast(stage_wrapper)
        )
        if not wrapper_calls_owner:
            violations.append(
                ArchitectureViolation(
                    _relative(stage_path, REPO_ROOT),
                    rule,
                    f"{stage_wrapper_name} must call the Structuring-owned materializer",
                )
            )

        prime_name = "_prime_structuring_validation_semantics_8616"
        prime = _find_function(stage_tree, prime_name)
        prime_call_lines: dict[str, int] = {}
        if prime is not None:
            for node in _walk_ast(prime):
                if not isinstance(node, ast.Call):
                    continue
                call_name = _call_name(node.func)
                if call_name in {
                    "_replay_structuring_lowering_before_validation_8616",
                    stage_wrapper_name,
                }:
                    prime_call_lines.setdefault(call_name, node.lineno)
        replay_line = prime_call_lines.get("_replay_structuring_lowering_before_validation_8616")
        terminal_line = prime_call_lines.get(stage_wrapper_name)
        if replay_line is None or terminal_line is None or terminal_line <= replay_line:
            violations.append(
                ArchitectureViolation(
                    _relative(stage_path, REPO_ROOT),
                    rule,
                    f"{prime_name} must run terminal call-result materialization after final lowering replay",
                )
            )
    else:
        violations.append(
            ArchitectureViolation(
                _relative(stage_path, REPO_ROOT),
                rule,
                "structuring stage entry point is missing",
            )
        )

    for path in postprocess_paths:
        tree = _parse_python(path)
        defined_names: set[str] = set()
        imported_owner_names: set[str] = set()
        for node in _walk_ast(tree):
            if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                defined_names.add(node.name)
            elif isinstance(node, ast.ImportFrom):
                imported_owner_names.update(alias.name for alias in node.names if alias.name in owner_names)
        forbidden_names = sorted((defined_names | imported_owner_names).intersection(owner_names))
        for name in forbidden_names:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    rule,
                    f"{name} must not be defined or imported in postprocess",
                )
            )
    return tuple(violations)


def _check_shared_body_wide_condition_ownership(
    root: Path,
) -> tuple[ArchitectureViolation, ...]:
    """Keep shared-body CFG recovery in Structuring and DX:AX joining in Lowering."""

    lowering_path = root / "lowering" / "call_output_stack_objects.py"
    structuring_path = root / "structuring" / "condition_materialization.py"
    postprocess_paths = tuple(sorted(root.glob("decompiler_postprocess_*.py")))
    if not lowering_path.exists() and not structuring_path.exists() and not postprocess_paths:
        return ()

    rule = "shared-body-wide-condition-layer-owner"
    lowering_name = "lower_wide_call_return_condition_chain_8616"
    structuring_name = "_materialize_cfg_shared_body_condition_chain_expr_8616"
    violations: list[ArchitectureViolation] = []

    if lowering_path.exists():
        lowering_tree = _parse_python(lowering_path)
        if _find_function(lowering_tree, lowering_name) is None:
            violations.append(
                ArchitectureViolation(
                    _relative(lowering_path, REPO_ROOT),
                    rule,
                    f"Types/Lowering owner must define {lowering_name}",
                )
            )
    else:
        violations.append(
            ArchitectureViolation(
                _relative(lowering_path, REPO_ROOT),
                rule,
                "wide call-return condition Lowering owner is missing",
            )
        )

    if structuring_path.exists():
        structuring_tree = _parse_python(structuring_path)
        imported_names = _imported_names_from_module(
            structuring_tree,
            "..lowering.call_output_stack_objects",
        )
        if lowering_name not in imported_names:
            violations.append(
                ArchitectureViolation(
                    _relative(structuring_path, REPO_ROOT),
                    rule,
                    f"Structuring must import {lowering_name} from Types/Lowering",
                )
            )
        shared_body_owner = _find_function(structuring_tree, structuring_name)
        if shared_body_owner is None:
            violations.append(
                ArchitectureViolation(
                    _relative(structuring_path, REPO_ROOT),
                    rule,
                    f"Structuring owner must define {structuring_name}",
                )
            )
        elif not any(
            isinstance(node, ast.Call) and _call_name(node.func) == lowering_name
            for node in _walk_ast(shared_body_owner)
        ):
            violations.append(
                ArchitectureViolation(
                    _relative(structuring_path, REPO_ROOT),
                    rule,
                    f"{structuring_name} must call the Types/Lowering-owned wide join",
                )
            )
    else:
        violations.append(
            ArchitectureViolation(
                _relative(structuring_path, REPO_ROOT),
                rule,
                "shared-body condition Structuring owner is missing",
            )
        )

    protected_names = (lowering_name, structuring_name)
    for path in postprocess_paths:
        tree = _parse_python(path)
        postprocess_imported_names: set[str] = set()
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            for alias in node.names:
                postprocess_imported_names.add(alias.name)
                if alias.asname is not None:
                    postprocess_imported_names.add(alias.asname)
        for name in protected_names:
            if _find_function(tree, name) is not None or name in postprocess_imported_names:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        rule,
                        f"{name} must not be owned or imported by postprocess",
                    )
                )
    return tuple(violations)


def _check_condition_lane_counters_use_dot_access(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Require condition-lane materialization counters to use typed dot access."""

    violations: list[ArchitectureViolation] = []
    for filename in ("decompiler_postprocess_jcc.py", "decompiler_postprocess_typed_conditions.py"):
        path = root / filename
        if not path.exists():
            continue
        for node in _walk_ast(_parse_python(path)):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "lane"
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name not in {"classified", "materialized"}:
                continue
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "condition-lane-dot-access",
                    f"condition lane counter lane.{field_name} must use dot access, not getattr()",
                )
            )
    return tuple(violations)


def _check_condition_origin_tags_use_dot_access(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Require typed ConditionIR provenance tags to use explicit fields."""

    path = root / "structuring" / "condition_lowering.py"
    if not path.exists():
        return ()
    function = _find_function(_parse_python(path), "condition_origin_tags_8616")
    if function is None:
        return ()
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(function):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "condition-origin-tags-dot-access",
                    "condition_origin_tags_8616 must use typed ConditionIR fields, not getattr()",
                )
            )
    return tuple(violations)


def _check_pipeline_invariants_alias_contracts_use_dot_access(root: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit alias contract fields in pre-rewrite invariant checks."""

    path = root / "pipeline" / "invariants.py"
    if not path.exists():
        return ()
    guard = _find_function(_parse_python(path), "_check_stack_slots_materialized")
    if guard is None:
        return ()
    banned_fields = {"identity_val": {"offset"}, "fact": {"identity", "offset", "reason"}}
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(guard):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"getattr", "setattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
        ):
            continue
        target_name = node.args[0].id
        field_name = _string_constant(node.args[1])
        if field_name not in banned_fields.get(target_name, set()):
            continue
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "pipeline-invariants-alias-dot-access",
                f"pipeline invariant alias field {target_name}.{field_name} must use dot access, not {node.func.id}()",
            )
        )
    return tuple(violations)


def _decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


def _annotation_type_names(node: ast.AST | None) -> frozenset[str]:
    if node is None:
        return frozenset()
    if isinstance(node, ast.Name):
        return frozenset({node.id})
    if isinstance(node, ast.Attribute):
        return frozenset({node.attr})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return _annotation_type_names(ast.parse(node.value, mode="eval").body)
        except SyntaxError:
            return frozenset()
    if isinstance(node, ast.Subscript):
        return _annotation_type_names(node.value) | _annotation_type_names(node.slice)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _annotation_type_names(node.left) | _annotation_type_names(node.right)
    if isinstance(node, ast.Tuple | ast.List):
        names: set[str] = set()
        for item in node.elts:
            names.update(_annotation_type_names(item))
        return frozenset(names)
    return frozenset()


def _collect_owned_dataclass_fields(root: Path) -> dict[str, frozenset[str]]:
    """Collect fields for module-level dataclass and Protocol contracts under ``root``."""
    fields_by_class: dict[str, set[str]] = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = _read_text_if_present(path)
        if text is None or ("dataclass" not in text and "Protocol" not in text):
            continue
        tree = _parse_python(path)
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            is_dataclass = any(_decorator_name(decorator) == "dataclass" for decorator in node.decorator_list)
            is_protocol = any("Protocol" in _annotation_type_names(base) for base in node.bases)
            if not (is_dataclass or is_protocol):
                continue
            field_names = fields_by_class.setdefault(node.name, set())
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    field_names.add(stmt.target.id)
    return {name: frozenset(fields) for name, fields in fields_by_class.items() if fields}


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _OwnedContractDynamicAccessVisitor(ast.NodeVisitor):
    """Find dynamic field access on variables typed as owned contracts."""

    def __init__(self, path: Path, fields_by_class: dict[str, frozenset[str]]) -> None:
        """Initialize visitor state for one Python source file."""
        self.path = path
        self.fields_by_class = fields_by_class
        self.violations: list[ArchitectureViolation] = []
        self._typed_names: list[dict[str, str]] = [{}]
        self._dataclass_stack: list[str | None] = []

    def _push_scope(self) -> None:
        self._typed_names.append({})

    def _pop_scope(self) -> None:
        self._typed_names.pop()

    def _remember_typed_name(self, name: str, annotation: ast.AST | None) -> None:
        for type_name in _annotation_type_names(annotation):
            if type_name in self.fields_by_class:
                self._typed_names[-1][name] = type_name
                return

    def _remember_constructor_assignment(self, name: str, value: ast.AST | None) -> None:
        if not isinstance(value, ast.Call):
            return
        type_name = _call_name(value.func)
        if type_name in self.fields_by_class:
            self._typed_names[-1][name] = type_name

    def _remember_narrowed_name(self, name: str, type_name: str) -> None:
        """Record a branch-local name narrowed by ``isinstance``."""
        if type_name in self.fields_by_class:
            self._typed_names[-1][name] = type_name

    def _isinstance_narrowings(self, node: ast.AST) -> tuple[tuple[str, str], ...]:
        """Return positive owned-dataclass narrowings from a branch condition."""
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            narrowings: list[tuple[str, str]] = []
            for value in node.values:
                narrowings.extend(self._isinstance_narrowings(value))
            return tuple(narrowings)
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and len(node.args) == 2
            and isinstance(node.args[0], ast.Name)
        ):
            return ()
        name = node.args[0].id
        type_names = _annotation_type_names(node.args[1])
        return tuple((name, type_name) for type_name in type_names if type_name in self.fields_by_class)

    def _typed_contract_for_name(self, name: str) -> str | None:
        if name == "self" and self._dataclass_stack and self._dataclass_stack[-1] in self.fields_by_class:
            return self._dataclass_stack[-1]
        for scope in reversed(self._typed_names):
            type_name = scope.get(name)
            if type_name is not None:
                return type_name
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track owned-contract ``self`` fields while visiting class bodies."""
        self._dataclass_stack.append(node.name if node.name in self.fields_by_class else None)
        self._push_scope()
        for stmt in node.body:
            self.visit(stmt)
        self._pop_scope()
        self._dataclass_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track typed function parameters for a synchronous function."""
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track typed function parameters for an async function."""
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._push_scope()
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self._remember_typed_name(arg.arg, arg.annotation)
        if node.args.vararg is not None:
            self._remember_typed_name(node.args.vararg.arg, node.args.vararg.annotation)
        if node.args.kwarg is not None:
            self._remember_typed_name(node.args.kwarg.arg, node.args.kwarg.annotation)
        for stmt in node.body:
            self.visit(stmt)
        self._pop_scope()

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Track local names that are explicitly annotated as owned contracts."""
        if isinstance(node.target, ast.Name):
            self._remember_typed_name(node.target.id, node.annotation)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track local names initialized from owned contract constructors."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._remember_constructor_assignment(target.id, node.value)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Track positive isinstance narrowing inside branch-local scopes."""
        self.visit(node.test)
        self._push_scope()
        for name, type_name in self._isinstance_narrowings(node.test):
            self._remember_narrowed_name(name, type_name)
        for stmt in node.body:
            self.visit(stmt)
        self._pop_scope()
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Call(self, node: ast.Call) -> None:
        """Reject getattr/setattr on known owned contract fields."""
        if isinstance(node.func, ast.Name) and node.func.id in {"getattr", "setattr"} and len(node.args) >= 2:
            target = node.args[0]
            field_name = _string_constant(node.args[1])
            if isinstance(target, ast.Name) and field_name is not None:
                type_name = self._typed_contract_for_name(target.id)
                if type_name is not None and field_name in self.fields_by_class[type_name]:
                    self.violations.append(
                        ArchitectureViolation(
                            _relative(self.path, REPO_ROOT),
                            "owned-contract-dot-access",
                            f"{type_name} field {target.id}.{field_name} must use dot access, not {node.func.id}()",
                        )
                    )
        self.generic_visit(node)


def _check_owned_contracts_use_dot_access(root: Path) -> tuple[ArchitectureViolation, ...]:
    fields_by_class = _collect_owned_dataclass_fields(root)
    if not fields_by_class:
        return ()
    owned_type_names = tuple(fields_by_class)
    violations: list[ArchitectureViolation] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = _read_text_if_present(path)
        if text is None or ("getattr" not in text and "setattr" not in text):
            continue
        if not any(type_name in text for type_name in owned_type_names):
            continue
        visitor = _OwnedContractDynamicAccessVisitor(path, fields_by_class)
        visitor.visit(_parse_python(path))
        violations.extend(visitor.violations)
    return tuple(violations)


def _check_semantic_layers_not_cod_raw_text_backed(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    paths = (
        root / "lowering" / "segmented_global_loads.py",
        root / "decompiler_postprocess_stage.py",
    )
    for path in paths:
        if not path.exists():
            continue
        tree = _parse_python(path)
        for node in _walk_ast(tree):
            uses_cod_raw_entries = (
                (isinstance(node, ast.Attribute) and node.attr == "cod_raw_entries")
                or (isinstance(node, ast.Constant) and node.value == "cod_raw_entries")
                or (isinstance(node, ast.Name) and node.id == "cod_raw_entries")
            )
            if uses_cod_raw_entries:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cod-raw-text-semantic-evidence",
                        "semantic lowering/postprocess must not parse COD raw listing text as storage or control evidence",
                    )
                )
                break
    return tuple(violations)


def _check_postprocess_calls_source_evidence_is_inert(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []

    def _function_returns_constant_false(function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
        if function is None or len(function.body) != 1:
            return False
        stmt = function.body[0]
        return isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value is False

    def _function_returns_empty_tuple(function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
        if function is None or len(function.body) != 1:
            return False
        stmt = function.body[0]
        return isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Tuple) and len(stmt.value.elts) == 0

    gate = _find_function(tree, "_source_call_floor_enabled_8616")
    if gate is None or not _function_returns_constant_false(gate):
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "source-call-floor-default",
                "source-call floor recovery must stay inert",
            )
        )

    width_helper = _find_function(tree, "_source_prototype_arg_widths_8616")
    if width_helper is not None:
        banned_call_names = {"_parse_c_prototype_8616", "_prototype_arg_widths_8616", "read_text", "finditer"}
        for node in _walk_ast(width_helper):
            call_name = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
            uses_banned_call = isinstance(call_name, str) and call_name in banned_call_names
            uses_source_metadata = isinstance(node, ast.Attribute) and node.attr in {
                "cod_path",
                "source_lines",
                "source_line_set",
            }
            if uses_banned_call or uses_source_metadata:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "source-prototype-width-recovery",
                        "postprocess calls must not recover argument widths from COD/source prototypes",
                    )
                )
                break

    source_arg_helper = _find_function(tree, "_source_call_arg_semantic_kind_8616")
    if source_arg_helper is not None:
        banned_call_names = {"read_text", "compile", "finditer", "_source_arg_kind_from_part_8616"}
        for node in _walk_ast(source_arg_helper):
            call_name = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
            uses_banned_call = isinstance(call_name, str) and call_name in banned_call_names
            uses_source_metadata = isinstance(node, ast.Attribute) and node.attr in {
                "cod_path",
                "_inertia_lst_metadata",
                "_inertia_original_project",
            }
            if uses_banned_call or uses_source_metadata:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "source-call-arg-semantic-recovery",
                        "postprocess calls must not classify argument pointer/value semantics from COD/source signatures",
                    )
                )
                break

    call_names_helper = _find_function(tree, "_cod_source_call_names_8616")
    if call_names_helper is not None:
        if not _function_returns_empty_tuple(call_names_helper):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cod-call-name-source-evidence",
                    "postprocess calls must not read COD call_names as call recovery evidence",
                )
            )
        for node in _walk_ast(call_names_helper):
            if (
                (isinstance(node, ast.Attribute) and node.attr == "call_sources")
                or (isinstance(node, ast.Constant) and node.value == "call_sources")
                or (isinstance(node, ast.Name) and node.id == "call_sources")
            ):
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cod-call-source-text-evidence",
                        "postprocess calls must not use COD call_sources text as call recovery evidence",
                    )
                )
                break
            if (
                (isinstance(node, ast.Attribute) and node.attr == "call_names")
                or (isinstance(node, ast.Constant) and node.value == "call_names")
                or (isinstance(node, ast.Name) and node.id == "call_names")
            ):
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cod-call-name-source-evidence",
                        "postprocess calls must not read COD call_names as call recovery evidence",
                    )
                )
                break

    symbol_call_names_helper = _find_function(tree, "_cod_source_call_names_for_symbol_8616")
    if symbol_call_names_helper is not None:
        if not _function_returns_empty_tuple(symbol_call_names_helper):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "cod-call-name-source-evidence",
                    "postprocess calls must not read COD call_names as call recovery evidence",
                )
            )
        for node in _walk_ast(symbol_call_names_helper):
            if (
                (isinstance(node, ast.Attribute) and node.attr == "call_names")
                or (isinstance(node, ast.Constant) and node.value == "call_names")
                or (isinstance(node, ast.Name) and node.id == "call_names")
            ):
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cod-call-name-source-evidence",
                        "postprocess calls must not read COD call_names as call recovery evidence",
                    )
                )
                break

    align_helper = _find_function(tree, "_align_cod_call_names_8616")
    if align_helper is not None and not _function_returns_constant_false(align_helper):
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "cod-call-name-alignment-default",
                "COD call-name alignment must stay inert",
            )
        )
    if align_helper is not None:
        for node in _walk_ast(align_helper):
            uses_call_names = (
                (isinstance(node, ast.Attribute) and node.attr == "call_names")
                or (isinstance(node, ast.Constant) and node.value == "call_names")
                or (isinstance(node, ast.Name) and node.id == "call_names")
            )
            uses_cod_metadata = isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id == "_cod_metadata_for_function_8616")
                or (isinstance(node.func, ast.Attribute) and node.func.attr == "_cod_metadata_for_function_8616")
            )
            if uses_call_names or uses_cod_metadata:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "cod-call-name-alignment-default",
                        "COD call-name alignment must stay inert",
                    )
                )
                break

    return tuple(violations)


def _check_postprocess_return_shape_not_source_backed(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    banned_names = {
        "_source_return_shape_8616",
        "_collect_source_return_annotation_8616",
        "_local_source_return_decl_is_void_8616",
        "collect_local_source_sidecar_return_types",
    }
    for node in _walk_ast(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {
            "_source_annotation_lines_8616",
            "_merge_source_annotations_if_missing_8616",
            "_attach_project_cod_source_annotations_if_missing_8616",
        }:
            expected = () if node.name == "_source_annotation_lines_8616" else False
            if not _function_returns_only_constant(node, expected):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "postprocess-source-return-shape",
                        "postprocess must not attach COD/source annotations after semantic recovery",
                    ),
                )
            for child in _walk_ast(node):
                if (
                    (
                        isinstance(child, ast.Attribute)
                        and child.attr in {"source_lines", "source_return_lines", "stack_aliases"}
                    )
                    or (
                        isinstance(child, ast.Constant)
                        and child.value in {"source_lines", "source_return_lines", "stack_aliases"}
                    )
                    or (
                        isinstance(child, ast.Name)
                        and child.id in {"source_lines", "source_return_lines", "stack_aliases"}
                    )
                ):
                    return (
                        ArchitectureViolation(
                            _relative(path, REPO_ROOT),
                            "postprocess-source-return-shape",
                            "postprocess must not attach COD/source annotations after semantic recovery",
                        ),
                    )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in banned_names:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "postprocess-source-return-shape",
                    "postprocess must not recover return shape or void-ness from COD/source return text",
                ),
            )
        if isinstance(node, ast.ImportFrom):
            imported = {alias.name for alias in node.names}
            if imported.intersection(banned_names):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "postprocess-source-return-shape",
                        "postprocess must not import source sidecar return typing as semantic evidence",
                    ),
                )
        if not isinstance(node, ast.Call):
            continue
        call_name = None
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name in banned_names:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "postprocess-source-return-shape",
                    "postprocess must not use source/COD return text to classify function returns",
                ),
            )
    return ()


def _check_postprocess_not_cod_stack_alias_backed(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    paths = (
        root / "decompiler_postprocess_calls.py",
        root / "decompiler_postprocess_stage.py",
        root / "postprocess" / "optimization" / "dce.py",
    )
    for path in paths:
        if not path.exists():
            continue
        tree = _parse_python(path)
        for node in _walk_ast(tree):
            uses_stack_aliases = (
                (isinstance(node, ast.Attribute) and node.attr == "stack_aliases")
                or (isinstance(node, ast.Constant) and node.value == "stack_aliases")
                or (isinstance(node, ast.Name) and node.id == "stack_aliases")
            )
            if uses_stack_aliases:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "postprocess-cod-stack-alias-evidence",
                        "postprocess/DCE must not use COD stack_aliases as semantic liveness or argument-name evidence",
                    )
                )
                break
    return tuple(violations)


def _check_validation_not_source_or_sample_backed(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    banned_names = {
        "_validate_source_backed_call_shape_8616",
        "_same_heap_sort_entry_addr_8616",
    }
    banned_strings = {
        "HeapSort PercolateDown argument regressed to constant",
        "HeapSort SwapBars argument order/class regressed",
    }
    for node in _walk_ast(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in banned_names:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "validation-source-sample-call-shape",
                    "validation must not enforce source-backed or sample-specific call-shape policy",
                ),
            )
        if isinstance(node, ast.Constant) and node.value in banned_strings:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "validation-source-sample-call-shape",
                    "validation must stay generic; sample-specific call-shape checks belong in focused regressions",
                ),
            )
    return ()


def _check_tail_validation_not_source_decl_backed(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    banned_names = {
        "_source_decl_from_cod_source_lines",
        "_parse_c_prototype_8616",
    }
    for node in _walk_ast(tree):
        if isinstance(node, ast.ImportFrom):
            imported = {alias.name for alias in node.names}
            if imported.intersection(banned_names):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "tail-validation-source-decl-return-evidence",
                        "tail validation must not recover return semantics from COD/source declarations",
                    ),
                )
        if not isinstance(node, ast.Call):
            continue
        call_name = None
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name in banned_names:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "tail-validation-source-decl-return-evidence",
                    "tail validation must compare recovered semantics, not source declaration text",
                ),
            )
    return ()


def _check_tail_validation_fingerprint_not_cod_backed(path: Path) -> tuple[ArchitectureViolation, ...]:
    if not path.exists():
        return ()
    tree = _parse_python(path)
    banned_names = {"_cod_metadata_for_function_8616"}
    for node in _walk_ast(tree):
        if isinstance(node, ast.ImportFrom):
            imported = {alias.name for alias in node.names}
            if imported.intersection(banned_names):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "tail-validation-cod-call-fingerprint",
                        "tail validation fingerprints must not synthesize calls from COD metadata",
                    ),
                )
        if isinstance(node, ast.Attribute) and node.attr == "call_names":
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "tail-validation-cod-call-fingerprint",
                    "tail validation fingerprints must not consume COD call-name order",
                ),
            )
        if not isinstance(node, ast.Call):
            continue
        call_name = None
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name in banned_names:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "tail-validation-cod-call-fingerprint",
                    "tail validation fingerprints must use recovered call identity only",
                ),
            )
    return ()


def _check_recompilable_source_evidence_inert(
    source_path: Path, bridge_path: Path
) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []

    if source_path.exists():
        tree = _parse_python(source_path)
        builder = _find_function(tree, "build_recompilable_source_evidence_text")
        if builder is not None:
            inert = False
            if len(builder.body) == 1:
                stmt = builder.body[0]
                inert = (
                    isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) and stmt.value.value is None
                )
            if not inert:
                violations.append(
                    ArchitectureViolation(
                        _relative(source_path, REPO_ROOT),
                        "recompilable-source-evidence-fallback",
                        "recompilable subset checks must not synthesize C from COD/source evidence",
                    )
                )

        loader = _find_function(tree, "load_or_build_recompilable_source_evidence")
        if loader is not None:
            for node in _walk_ast(loader):
                writes_file = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"write_text", "write_bytes"}
                )
                reads_shape_text = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "check_recompilable_c_text_shape"
                )
                if writes_file or reads_shape_text:
                    violations.append(
                        ArchitectureViolation(
                            _relative(source_path, REPO_ROOT),
                            "recompilable-source-evidence-fallback",
                            "recompilable subset checks must not load, validate, or persist source-derived C",
                        )
                    )
                    break

    if bridge_path.exists():
        tree = _parse_python(bridge_path)
        for node in _walk_ast(tree):
            imports_source_evidence = isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                "recompilable_source_evidence"
            )
            imports_storage_fallback = isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                "recompilable_storage_fallback"
            )
            if imports_source_evidence or imports_storage_fallback:
                violations.append(
                    ArchitectureViolation(
                        _relative(bridge_path, REPO_ROOT),
                        "recompilable-source-evidence-fallback",
                        "recompilable CLI bridge must not select source-evidence fallback text",
                    )
                )
                break
            if isinstance(node, ast.Constant) and node.value in {
                "shape_ok_evidence",
                "storage_object_shape_ok_evidence",
                "shape_ok_evidence_fallback",
                "storage_object_shape_ok_evidence_fallback",
                "storage_object_refusal_shape_ok_evidence_fallback",
            }:
                violations.append(
                    ArchitectureViolation(
                        _relative(bridge_path, REPO_ROOT),
                        "recompilable-source-evidence-fallback",
                        "recompilable CLI bridge must not select source-evidence fallback text",
                    )
                )
                break

    return tuple(violations)


def _function_returns_only_constant(function: ast.FunctionDef | ast.AsyncFunctionDef | None, value: object) -> bool:
    if function is None:
        return False
    body = _body_without_leading_docstring(function.body)
    if len(body) != 1:
        return False
    stmt = body[0]
    if not isinstance(stmt, ast.Return):
        return False
    if value == () and isinstance(stmt.value, ast.Tuple) and not stmt.value.elts:
        return True
    return isinstance(stmt.value, ast.Constant) and stmt.value.value is value


def _check_forced_corpus_templates_inert(cli_path: Path, entrypoint_path: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []

    if cli_path.exists():
        tree = _parse_python(cli_path)
        enabled = _find_function(tree, "_forced_corpus_templates_enabled")
        if not _function_returns_only_constant(enabled, False):
            violations.append(
                ArchitectureViolation(
                    _relative(cli_path, REPO_ROOT),
                    "forced-corpus-template-fallback",
                    "forced corpus template gate must be permanently false",
                )
            )

        template = _find_function(tree, "_forced_function_template")
        if not _function_returns_only_constant(template, None):
            violations.append(
                ArchitectureViolation(
                    _relative(cli_path, REPO_ROOT),
                    "forced-corpus-template-fallback",
                    "CLI must not substitute sample-specific C templates for decompiler output",
                )
            )

    if entrypoint_path.exists():
        tree = _parse_python(entrypoint_path)
        for node in _walk_ast(tree):
            default_enables_templates = (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setdefault"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "INERTIA_ENABLE_FORCED_CORPUS_TEMPLATES"
            )
            if default_enables_templates:
                violations.append(
                    ArchitectureViolation(
                        _relative(entrypoint_path, REPO_ROOT),
                        "forced-corpus-template-fallback",
                        "entrypoint must not enable forced corpus templates by default",
                    )
                )
                break

    return tuple(violations)


def _check_compatibility_shims(root: Path) -> tuple[ArchitectureViolation, ...]:
    violations: list[ArchitectureViolation] = []
    for filename, canonical_import in _COMPATIBILITY_SHIMS.items():
        path = root / filename
        if not path.exists():
            continue
        tree = _parse_python(path)
        docstring = ast.get_docstring(tree) or ""
        for marker in _COMPATIBILITY_SHIM_HEADER_MARKERS:
            if not _contains_marker(docstring, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "compat-shim-header",
                        f"compatibility shim docstring must contain {marker!r}",
                    )
                )
        module, _, imported_name = canonical_import.rpartition(".")
        imported_names = _imported_names_from_module(tree, module)
        canonical_star_imports = _imported_names_from_module(tree, canonical_import)
        if imported_name not in imported_names and "*" not in canonical_star_imports:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "compat-shim-import",
                    f"must import only canonical implementation {canonical_import!r}",
                )
            )
        for node in _walk_ast(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "compat-shim-behavior",
                        f"{node.__class__.__name__} {node.name!r} adds behavior to a compatibility shim",
                    )
                )
    return tuple(violations)


def _check_promoted_typed_file_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "promoted-typed-file-docstring",
                    "promoted typed file is missing",
                )
            )
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not doc.strip():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "promoted-typed-file-docstring",
                    "promoted typed files must keep module docstrings as part of the docs/types ratchet",
                )
            )
            continue
        missing_markers = tuple(marker for marker in ("Layer:", "Responsibility:") if marker not in doc)
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "promoted-typed-file-docstring",
                    "promoted typed file docstring must include ownership markers: "
                    + ", ".join(repr(marker) for marker in missing_markers),
                )
            )
    return tuple(violations)


def _module_has_future_annotations(tree: ast.Module) -> bool:
    """Return whether a module enables postponed annotation evaluation."""

    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _check_promoted_typed_future_annotations(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require promoted typed files to use postponed annotations consistently."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        if _module_has_future_annotations(_parse_python(path)):
            continue
        violations.append(
            ArchitectureViolation(
                _relative(path, repo_root),
                "promoted-typed-future-annotations",
                "promoted typed files must include 'from __future__ import annotations'",
            )
        )
    return tuple(violations)


def _check_promoted_typed_public_assign_annotations(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require public module constants in promoted typed files to be annotated."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        for node in _parse_python(path).body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name) or target.id.startswith("_") or target.id == "__all__":
                    continue
                violations.append(
                    ArchitectureViolation(
                        _relative(path, repo_root),
                        "promoted-typed-public-assignment-annotation",
                        f"promoted typed public assignment {target.id!r} must use an annotation",
                    )
                )
    return tuple(violations)


def _iter_public_contract_defs(tree: ast.Module) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, ...]:
    """Return public top-level and class-member definitions in a module."""

    def is_overload_stub(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any(_decorator_name(decorator) == "overload" for decorator in node.decorator_list)

    public_defs: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
            and not is_overload_stub(node)
        ) or (isinstance(node, ast.ClassDef) and not node.name.startswith("_")):
            public_defs.append(node)
        if isinstance(node, ast.ClassDef):
            public_defs.extend(
                stmt
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and not stmt.name.startswith("_")
                and not (isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and is_overload_stub(stmt))
            )
    return tuple(public_defs)


def _check_promoted_typed_public_def_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require public definitions in promoted typed files to explain their contract."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        for node in _iter_public_contract_defs(_parse_python(path)):
            if (ast.get_docstring(node) or "").strip():
                continue
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "promoted-typed-public-docstring",
                    f"promoted typed public definition {node.name!r} must keep a docstring",
                )
            )
    return tuple(violations)


def _function_missing_annotation_labels(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    """Return public-signature annotation labels missing from a function."""

    missing: list[str] = []
    positional = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    for arg in positional:
        if arg.arg not in {"self", "cls"} and arg.annotation is None:
            missing.append(arg.arg)  # noqa: PERF401
    if node.args.vararg is not None and node.args.vararg.annotation is None:
        missing.append(f"*{node.args.vararg.arg}")
    if node.args.kwarg is not None and node.args.kwarg.annotation is None:
        missing.append(f"**{node.args.kwarg.arg}")
    if node.returns is None:
        missing.append("return")
    return tuple(missing)


def _annotation_debt_slots(tree: ast.Module) -> tuple[str, ...]:
    """Return sorted qualified annotation gaps for one module."""

    slots: list[str] = []

    def _visit_statements(statements: list[ast.stmt], scope: tuple[str, ...]) -> None:
        for statement in statements:
            if isinstance(statement, ast.ClassDef):
                _visit_statements(statement.body, (*scope, statement.name))
                continue
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                qualified_name = ".".join((*scope, statement.name))
                slots.extend(f"{qualified_name}:{label}" for label in _function_missing_annotation_labels(statement))
                _visit_statements(statement.body, (*scope, statement.name))
                continue
            nested_statements = [child for child in ast.iter_child_nodes(statement) if isinstance(child, ast.stmt)]
            if nested_statements:
                _visit_statements(nested_statements, scope)

    _visit_statements(tree.body, ())
    return tuple(sorted(slots))


def _annotation_debt_fingerprint(slots: tuple[str, ...]) -> str:
    """Return a deterministic fingerprint for exact annotation debt slots."""

    return hashlib.sha256("\n".join(slots).encode("utf-8")).hexdigest()


def _check_decompiler_annotation_debt(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Reject new, moved, or stale private/nested annotation debt."""

    violations: list[ArchitectureViolation] = []
    actual_debt_files: set[str] = set()
    seen_files: set[str] = set()
    for relative_root in _DECOMPILER_ANNOTATION_ROOTS:
        source_root = repo_root / relative_root
        if not source_root.exists():
            continue
        for path in sorted(source_root.rglob("*.py")):
            relative_path = path.relative_to(repo_root).as_posix()
            seen_files.add(relative_path)
            slots = _annotation_debt_slots(_parse_python(path))
            if not slots:
                continue
            actual_debt_files.add(relative_path)
            expected = _DECOMPILER_ANNOTATION_DEBT_BASELINE.get(relative_path)
            if expected is None:
                violations.append(
                    ArchitectureViolation(
                        relative_path,
                        "decompiler-annotation-debt-new",
                        f"untracked annotation debt ({len(slots)} slots): {', '.join(slots[:3])}",
                    )
                )
                continue
            actual = (len(slots), _annotation_debt_fingerprint(slots))
            if actual != expected:
                violations.append(
                    ArchitectureViolation(
                        relative_path,
                        "decompiler-annotation-debt-changed",
                        f"annotation debt changed from {expected[0]} to {actual[0]} slots; remove debt and update the baseline",
                    )
                )

    for relative_path in sorted(_DECOMPILER_ANNOTATION_DEBT_BASELINE):
        if relative_path not in seen_files:
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "decompiler-annotation-debt-stale",
                    "annotation debt baseline references a missing decompiler module",
                )
            )
        elif relative_path not in actual_debt_files:
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "decompiler-annotation-debt-stale",
                    "annotation debt was removed; delete the stale baseline entry",
                )
            )
    return tuple(violations)


def _check_promoted_typed_public_function_annotations(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require public functions in promoted typed files to keep explicit signatures."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        for node in _iter_public_contract_defs(_parse_python(path)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            missing = _function_missing_annotation_labels(node)
            if not missing:
                continue
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "promoted-typed-public-annotations",
                    f"promoted typed public function {node.name!r} missing annotations: {', '.join(missing)}",
                )
            )
    return tuple(violations)


def _class_has_decorator(node: ast.ClassDef, decorator_name: str) -> bool:
    """Return whether a class has a decorator with the given simple name."""

    return any(_decorator_name(decorator) == decorator_name for decorator in node.decorator_list)


def _class_has_base(node: ast.ClassDef, base_name: str) -> bool:
    """Return whether a class inherits from a base with the given simple name."""

    return any(_call_name(base) == base_name for base in node.bases)


def _check_promoted_typed_dataclass_fields(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require public dataclass fields in promoted typed files to be annotated."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        for node in _walk_ast(_parse_python(path)):
            if not isinstance(node, ast.ClassDef) or not _class_has_decorator(node, "dataclass"):
                continue
            for stmt in node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        violations.append(  # noqa: PERF401
                            ArchitectureViolation(
                                _relative(path, repo_root),
                                "promoted-typed-dataclass-field-annotation",
                                f"promoted dataclass field {node.name}.{target.id} must use an annotation",
                            )
                        )
    return tuple(violations)


def _check_promoted_typed_enum_values(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require promoted status enums to use explicit string values."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        for node in _walk_ast(_parse_python(path)):
            if not isinstance(node, ast.ClassDef) or not (
                _class_has_base(node, "Enum") or _class_has_base(node, "StrEnum")
            ):
                continue
            for stmt in node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                for target in stmt.targets:
                    if not isinstance(target, ast.Name) or target.id.startswith("_"):
                        continue
                    if not (isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)):
                        violations.append(
                            ArchitectureViolation(
                                _relative(path, repo_root),
                                "promoted-typed-enum-string-value",
                                f"promoted enum member {node.name}.{target.id} must use an explicit string value",
                            )
                        )
    return tuple(violations)


def _literal_dunder_all_names(value: ast.AST) -> tuple[str, ...] | None:
    """Return literal __all__ names, or None when the assignment is computed."""

    if not isinstance(value, (ast.Tuple, ast.List)):
        return None
    names: list[str] = []
    for element in value.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            return None
        names.append(element.value)
    return tuple(names)


def _check_promoted_typed_literal_dunder_all(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require promoted typed files to expose static export lists."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        tree = _parse_python(path)
        for node in _walk_ast(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                continue
            targets, value = _assignment_targets_and_value(node)
            if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                continue
            if value is not None and _literal_dunder_all_names(value) is not None:
                continue
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "promoted-typed-file-literal-dunder-all",
                    "promoted typed files must assign __all__ from a literal tuple/list of string exports",
                )
            )
    return tuple(violations)


def _dynamic_attr_access_has_boundary_reason(lines: list[str], line_no: int) -> bool:
    """Return whether an attached comment explains a dynamic attribute boundary."""

    nearby_comments: list[str] = []
    for line in lines[max(0, line_no - 2) : line_no]:
        _, separator, comment = line.partition("#")
        if separator:
            nearby_comments.append(comment.strip().lower())
    reason = " ".join(nearby_comments)
    return "dynamic" in reason and "boundary" in reason and any(term in reason for term in _DYNAMIC_ATTR_BOUNDARY_TERMS)


def _dynamic_boundary_reason_text_is_valid(reason: str) -> bool:
    """Return whether text documents a supported dynamic ownership boundary."""

    normalized = reason.lower()
    return (
        "dynamic" in normalized
        and "boundary" in normalized
        and any(term in normalized for term in _DYNAMIC_ATTR_BOUNDARY_TERMS)
    )


def _dynamic_boundary_docstring_index(
    tree: ast.Module,
) -> tuple[bool, tuple[tuple[int, int, bool], ...]]:
    """Index module and nearest-definition dynamic-boundary documentation."""

    cached = _DYNAMIC_BOUNDARY_DOCSTRING_CACHE.get(tree)
    if cached is not None:
        return cached
    module_reason = _dynamic_boundary_reason_text_is_valid(ast.get_docstring(tree) or "")
    if module_reason:
        result: tuple[bool, tuple[tuple[int, int, bool], ...]] = (True, ())
        _DYNAMIC_BOUNDARY_DOCSTRING_CACHE[tree] = result
        return result
    definitions: list[tuple[int, int, bool]] = []
    for node in _walk_ast(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        end_lineno = node.end_lineno if node.end_lineno is not None else node.lineno
        definitions.append(
            (
                node.lineno,
                end_lineno,
                _dynamic_boundary_reason_text_is_valid(ast.get_docstring(node) or ""),
            )
        )
    result = module_reason, tuple(definitions)
    _DYNAMIC_BOUNDARY_DOCSTRING_CACHE[tree] = result
    return result


def _dynamic_attr_docstring_has_boundary_reason(tree: ast.Module, line_no: int) -> bool:
    """Return whether an enclosing docstring explains a dynamic attribute boundary."""

    module_reason, definitions = _dynamic_boundary_docstring_index(tree)
    if module_reason:
        return True
    owner_start = -1
    owner_reason = False
    for start, end, reason in definitions:
        if not (start <= line_no <= end):
            continue
        if start >= owner_start:
            owner_start = start
            owner_reason = reason
    return owner_reason


def _static_setattr_field(node: ast.Call) -> str | None:
    """Return the fixed field name from an unqualified or builtins setattr call."""

    if len(node.args) < 2 or not isinstance(node.args[1], ast.Constant) or not isinstance(node.args[1].value, str):
        return None
    if isinstance(node.func, ast.Name) and node.func.id == "setattr":
        return node.args[1].value
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "builtins"
        and node.func.attr == "setattr"
    ):
        return node.args[1].value
    return None


def _check_promoted_typed_files_avoid_dynamic_attr(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Reject avoidable dynamic attribute access in promoted typed gate files."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _PROMOTED_TYPED_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        text = _read_text_if_present(path)
        if text is None:
            continue
        lines = text.splitlines()
        tree = _parse_python(path)
        for node in _walk_ast(tree):
            if not isinstance(node, ast.Call):
                continue
            static_setattr_field = _static_setattr_field(node)
            if static_setattr_field is not None:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, repo_root),
                        "promoted-typed-file-static-setattr",
                        f"fixed field {static_setattr_field!r} must use dot assignment, not setattr() at line {node.lineno}",
                    )
                )
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {"getattr", "setattr"}:
                if _dynamic_attr_access_has_boundary_reason(
                    lines,
                    node.lineno,
                ) or _dynamic_attr_docstring_has_boundary_reason(tree, node.lineno):
                    continue
                violations.append(
                    ArchitectureViolation(
                        _relative(path, repo_root),
                        "promoted-typed-file-dynamic-attr",
                        "promoted typed quality files must use explicit contracts or document a dynamic boundary, "
                        f"not unqualified {node.func.id}() at line {node.lineno}",
                    )
                )
                continue
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "builtins"
                and node.func.attr in {"getattr", "setattr"}
            ):
                if _dynamic_attr_docstring_has_boundary_reason(tree, node.lineno):
                    continue
                violations.append(
                    ArchitectureViolation(
                        _relative(path, repo_root),
                        "promoted-typed-file-dynamic-attr",
                        "promoted typed quality files must document builtins dynamic attribute wrappers, "
                        f"not undocumented builtins.{node.func.attr}() at line {node.lineno}",
                    )
                )
    return tuple(violations)


def _check_gate_script_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _GATE_SCRIPT_FILES:
        path = repo_root / filename
        if not path.exists():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "gate-script-docstring",
                    "gate script is missing",
                )
            )
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not doc.strip():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "gate-script-docstring",
                    "gate scripts must keep module docstrings explaining their enforcement role",
                )
            )
            continue
        missing_markers = tuple(
            marker for marker in _GATE_SCRIPT_DOCSTRING_MARKERS.get(filename, ()) if marker not in doc
        )
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "gate-script-docstring",
                    f"gate script docstring must include: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_cli_boundary_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    cli_dir = repo_root / "inertia_decompiler"
    cli_paths = {repo_root / filename for filename in _CLI_BOUNDARY_FILES}
    if cli_dir.exists():
        cli_paths.update(cli_dir.glob("cli*.py"))
    for filename in _CLI_BOUNDARY_FILES:
        path = repo_root / filename
        if not path.exists():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "cli-boundary-docstring",
                    "CLI boundary file is missing",
                )
            )
    for path in sorted(cli_paths):
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        relative_path = _relative(path, repo_root)
        responsibility_marker = _CLI_BOUNDARY_RESPONSIBILITY_MARKERS.get(
            relative_path, _CLI_BOUNDARY_DEFAULT_RESPONSIBILITY_MARKER
        )
        expected_markers = (*_CLI_BOUNDARY_COMMON_HEADER_MARKERS, responsibility_marker)
        missing_markers = tuple(marker for marker in expected_markers if not _contains_marker(doc, marker))
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "cli-boundary-docstring",
                    f"CLI boundary module must declare exact ownership markers: {', '.join(repr(marker) for marker in missing_markers)}",
                )
            )
    return tuple(violations)


def _check_inertia_decompiler_module_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    if not (repo_root / "Makefile").exists():
        return ()
    package_dir = repo_root / "inertia_decompiler"
    if not package_dir.exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for path in sorted(package_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        relative_path = _relative(path, repo_root)
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not doc.strip():
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "inertia-module-docstring",
                    "inertia_decompiler modules must state their CLI/fallback/reporting contract",
                )
            )
            continue
        if "Responsibility:" not in doc and relative_path not in _LEGACY_INERTIA_RESPONSIBILITY_DEBT:
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "inertia-module-docstring",
                    "new inertia_decompiler modules must include a Responsibility: ownership marker; "
                    "legacy omissions belong in _LEGACY_INERTIA_RESPONSIBILITY_DEBT until fixed",
                )
            )
    return tuple(violations)


def _check_script_module_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    if not (repo_root / "Makefile").exists():
        return ()
    scripts_dir = repo_root / "scripts"
    if not scripts_dir.exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for path in sorted(scripts_dir.glob("*.py")):
        relative_path = _relative(path, repo_root)
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not doc.strip():
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "script-module-docstring",
                    "scripts must state their diagnostic, gate, fixture, or artifact contract",
                )
            )
            continue
        if "Responsibility:" not in doc and relative_path not in _LEGACY_SCRIPT_RESPONSIBILITY_DEBT:
            violations.append(
                ArchitectureViolation(
                    relative_path,
                    "script-module-docstring",
                    "new scripts must include a Responsibility: ownership marker; "
                    "legacy omissions belong in _LEGACY_SCRIPT_RESPONSIBILITY_DEBT until fixed",
                )
            )
    return tuple(violations)


def _check_legacy_responsibility_debt_is_current(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require responsibility-header debt allowlists to name only current debt."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for rule, debt_paths in (
        ("script-module-docstring", _LEGACY_SCRIPT_RESPONSIBILITY_DEBT),
        ("inertia-module-docstring", _LEGACY_INERTIA_RESPONSIBILITY_DEBT),
    ):
        for relative_path in sorted(debt_paths):
            path = repo_root / relative_path
            if not path.exists():
                violations.append(
                    ArchitectureViolation(
                        relative_path,
                        rule,
                        "legacy Responsibility: debt entry is stale because the file no longer exists",
                    )
                )
                continue
            doc = ast.get_docstring(_parse_python(path)) or ""
            if "Responsibility:" in doc:
                violations.append(
                    ArchitectureViolation(
                        relative_path,
                        rule,
                        "legacy Responsibility: debt entry must be removed after the module docstring is fixed",
                    )
                )
    return tuple(violations)


def _check_root_contract_docstrings(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _ROOT_CONTRACT_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        if not doc.strip():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "root-contract-docstring",
                    "root entrypoint/evidence files must state their architecture contract",
                )
            )
    return tuple(violations)


def _check_root_contract_layer_headers(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require root entrypoint/evidence contracts to declare architecture ownership."""

    if not (repo_root / "Makefile").exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for filename in _ROOT_CONTRACT_FILES:
        path = repo_root / filename
        if not path.exists():
            continue
        doc = ast.get_docstring(_parse_python(path)) or ""
        missing_markers = tuple(marker for marker in ("Layer:", "Responsibility:") if marker not in doc)
        if missing_markers:
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "root-contract-layer-header",
                    "root entrypoint/evidence files must include ownership markers: "
                    + ", ".join(repr(marker) for marker in missing_markers),
                )
            )
    return tuple(violations)


def _check_makefile_gate_targets(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    makefile_path = repo_root / "Makefile"
    makefile_text = _read_text_if_present(makefile_path)
    if makefile_text is None:
        return ()
    violations: list[ArchitectureViolation] = []
    for marker in _MAKEFILE_MARKERS:
        if not _contains_marker(makefile_text, marker):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-gate-marker",
                    f"missing required Makefile gate marker {marker!r}",
                )
            )
    for marker in _MAKEFILE_FORBIDDEN_MARKERS:
        if _contains_marker(makefile_text, marker):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-type-ratchet-legacy-debt",
                    f"obsolete type-ratchet legacy skip marker {marker!r} must not be present",
                )
            )
    typed_targets = frozenset(_makefile_variable_words(makefile_text, "QA_TYPED_FILES"))
    ruff_targets = frozenset(_makefile_variable_words(makefile_text, "QA_RUFF_TARGETS"))
    for filename in _PROMOTED_TYPED_FILES:
        if filename not in typed_targets:
            violations.append(
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-promoted-typed-file",
                    f"promoted typed file {filename!r} must be included in QA_TYPED_FILES",
                )
            )
        if filename not in ruff_targets:
            violations.append(
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-promoted-ruff-file",
                    f"promoted typed file {filename!r} must be included in QA_RUFF_TARGETS",
                )
            )
    for filename in _PYRIGHT_ONLY_TYPED_PROMOTION_FILES:
        if filename not in typed_targets:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-pyright-only-typed-file",
                    f"Pyright-only promoted file {filename!r} must be included in QA_TYPED_FILES",
                )
            )
    full_promotion_debt_files: frozenset[str] = (
        frozenset(_INERTIA_TYPED_PROMOTION_DEBT_FILES) | frozenset(_X86_16_TYPED_PROMOTION_DEBT_FILES)
    ) - frozenset(_PYRIGHT_ONLY_TYPED_PROMOTION_FILES)
    for filename in sorted(full_promotion_debt_files & typed_targets):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                _relative(makefile_path, repo_root),
                "makefile-full-promotion-debt-typed-target",
                f"full-promotion debt file {filename!r} must not be listed in QA_TYPED_FILES",
            )
        )
    for filename in sorted(full_promotion_debt_files & ruff_targets):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                _relative(makefile_path, repo_root),
                "makefile-full-promotion-debt-ruff-target",
                f"full-promotion debt file {filename!r} must not be listed in QA_RUFF_TARGETS",
            )
        )
    for marker in _FOCUSED_PYTEST_MARKERS:
        if not _contains_marker(makefile_text, marker):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-focused-contract-test",
                    f"focused fast contract test {marker!r} must be included in Makefile quality targets",
                )
            )
    pipeline_path = repo_root / "scripts" / "test_pipeline.py"
    if pipeline_path.exists():
        makefile_pytest_targets = frozenset(_makefile_variable_words(makefile_text, "QA_PYTEST_TARGETS"))
        for target in _focused_pytest_literals(_parse_python(pipeline_path)):
            if target not in makefile_pytest_targets:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(makefile_path, repo_root),
                        "makefile-pipeline-fast-target",
                        f"fast pipeline pytest target {target!r} must also be included in QA_PYTEST_TARGETS",
                    )
                )
    pytest_skip_calls = _fast_pytest_skip_calls(repo_root)
    for variable_name in ("QA_PYTEST_TARGETS", "QA_RUFF_TARGETS", "QA_TYPED_FILES"):
        targets = _makefile_variable_words(makefile_text, variable_name)
        for target in _duplicate_items(targets):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(makefile_path, repo_root),
                    "makefile-duplicate-qa-target",
                    f"{variable_name} lists {target!r} more than once",
                )
            )
        for target in targets:
            target_path = _makefile_target_path(target)
            if target_path and not (repo_root / target_path).exists():
                violations.append(
                    ArchitectureViolation(
                        _relative(makefile_path, repo_root),
                        "makefile-missing-qa-target",
                        f"{variable_name} target {target!r} does not exist",
                    )
                )
            elif variable_name == "QA_PYTEST_TARGETS" and "::" in target:
                node_exists, _skip_lines = _fast_pytest_target_contract(
                    repo_root,
                    target,
                    pytest_skip_calls,
                )
                if not node_exists:
                    violations.append(
                        ArchitectureViolation(
                            _relative(makefile_path, repo_root),
                            "makefile-missing-qa-node",
                            f"{variable_name} node {target!r} does not exist",
                        )
                    )
    return tuple(violations)


def _check_inertia_decompiler_typed_promotion_coverage(
    repo_root: Path = REPO_ROOT,
) -> tuple[ArchitectureViolation, ...]:
    """Require each inertia_decompiler module to be promoted or explicitly tracked as debt."""
    package_root = repo_root / "inertia_decompiler"
    if not package_root.exists():
        return ()
    promoted = frozenset(filename for filename in _PROMOTED_TYPED_FILES if filename.startswith("inertia_decompiler/"))
    debt: frozenset[str] = frozenset(_INERTIA_TYPED_PROMOTION_DEBT_FILES)
    pyright_only = frozenset(_PYRIGHT_ONLY_TYPED_PROMOTION_FILES)
    violations: list[ArchitectureViolation] = []

    for filename in sorted(debt & promoted):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                filename,
                "inertia-typed-promotion-debt-stale",
                "typed promotion debt entries must be removed once the module is promoted",
            )
        )

    for filename in sorted(pyright_only & promoted):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                filename,
                "inertia-pyright-only-promotion-stale",
                "Pyright-only promotion entries must be removed once the module is fully promoted",
            )
        )

    for filename in sorted(pyright_only - debt):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                filename,
                "inertia-pyright-only-promotion-untracked-debt",
                "Pyright-only promotion entries must remain explicit full-promotion debt until Ruff/docs/dynamic-attribute cleanup is complete",
            )
        )

    for filename in sorted(debt):
        if not (repo_root / filename).exists():
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    filename,
                    "inertia-typed-promotion-debt-stale",
                    "typed promotion debt entries must reference existing modules",
                )
            )

    for filename in sorted(pyright_only):
        if not (repo_root / filename).exists():
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    filename,
                    "inertia-pyright-only-promotion-stale",
                    "Pyright-only promotion entries must reference existing modules",
                )
            )

    covered = promoted | debt
    for path in sorted(package_root.glob("*.py")):
        filename = _relative(path, repo_root)
        if filename not in covered:
            violations.append(
                ArchitectureViolation(
                    filename,
                    "inertia-typed-promotion-coverage",
                    "inertia_decompiler modules must be in promoted typed/ruff gates or explicit promotion debt",
                )
            )
    return tuple(violations)


def _check_x86_16_typed_promotion_coverage(
    repo_root: Path = REPO_ROOT,
) -> tuple[ArchitectureViolation, ...]:
    """Require each X86_16 module to be promoted or explicitly tracked as debt."""
    package_root = repo_root / "angr_platforms" / "angr_platforms" / "X86_16"
    if not package_root.exists():
        return ()
    promoted = frozenset(
        filename for filename in _PROMOTED_TYPED_FILES if filename.startswith("angr_platforms/angr_platforms/X86_16/")
    )
    debt: frozenset[str] = frozenset(_X86_16_TYPED_PROMOTION_DEBT_FILES)
    violations: list[ArchitectureViolation] = []

    for filename in sorted(debt & promoted):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                filename,
                "x86-16-typed-promotion-debt-stale",
                "typed promotion debt entries must be removed once the module is promoted",
            )
        )

    for filename in sorted(debt):
        if not (repo_root / filename).exists():
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    filename,
                    "x86-16-typed-promotion-debt-stale",
                    "typed promotion debt entries must reference existing modules",
                )
            )

    covered = promoted | debt
    for path in sorted(package_root.rglob("*.py")):
        filename = _relative(path, repo_root)
        if filename not in covered:
            violations.append(
                ArchitectureViolation(
                    filename,
                    "x86-16-typed-promotion-coverage",
                    "X86_16 modules must be in promoted typed/ruff gates or explicit promotion debt",
                )
            )
    return tuple(violations)


def _duplicate_items(values: tuple[str, ...]) -> tuple[str, ...]:
    """Return repeated values while preserving first repeat order."""

    seen: set[str] = set()
    duplicates: list[str] = []
    duplicate_seen: set[str] = set()
    for value in values:
        if value in seen and value not in duplicate_seen:
            duplicates.append(value)
            duplicate_seen.add(value)
        seen.add(value)
    return tuple(duplicates)


def _makefile_target_path(target: str) -> str:
    """Return the filesystem path part from a Makefile lint or pytest target."""

    return target.split("::", 1)[0]


def _pipeline_tier_literals(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """Return literal PIPELINE_TIERS entries from the curated pipeline script."""

    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(node)
        if not any(isinstance(target, ast.Name) and target.id == "PIPELINE_TIERS" for target in targets):
            continue
        if not isinstance(value, ast.Dict):
            return {}
        tiers: dict[str, tuple[str, ...]] = {}
        for key_node, value_node in zip(value.keys, value.values, strict=True):
            if key_node is None:
                continue
            key = _string_constant(key_node)
            if key is None:
                continue
            tiers[key] = _ordered_tuple_string_constants(value_node)
        return tiers
    return {}


def _focused_pytest_literals(tree: ast.Module) -> tuple[str, ...]:
    """Return literal FOCUSED_PYTEST_TARGETS entries from the pipeline script."""

    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets, value = _assignment_targets_and_value(node)
        if any(isinstance(target, ast.Name) and target.id == "FOCUSED_PYTEST_TARGETS" for target in targets):
            return _ordered_tuple_string_constants(value)
    return ()


def _fast_pytest_skip_calls(repo_root: Path = REPO_ROOT) -> frozenset[str]:
    """Return the ownership-manifest source of truth for forbidden fast-test skips."""

    manifest_path = repo_root / "scripts" / "test_ownership_manifest.py"
    if not manifest_path.exists():
        return frozenset()
    calls = _module_frozenset_string_constant(_parse_python(manifest_path), "FAST_PYTEST_SKIP_CALLS")
    return frozenset() if calls is None else calls


def _fast_pytest_target_contract(
    repo_root: Path,
    target: str,
    skip_calls: frozenset[str],
) -> tuple[bool, tuple[int, ...]]:
    """Return node existence and skip/xfail lines for one fast target."""

    path_text, *selectors = target.split("::")
    target_path = repo_root / path_text
    if not target_path.exists():
        return False, ()
    index = load_pytest_source_index(target_path, skip_calls)
    selector = "::".join(selectors)
    return index.has_node(selector), index.skip_xfail_lines(selector)


def _check_test_pipeline_fast_targets(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    pipeline_path = repo_root / "scripts" / "test_pipeline.py"
    pipeline_text = _read_text_if_present(pipeline_path)
    if pipeline_text is None:
        return ()
    violations: list[ArchitectureViolation] = []
    pipeline_tree = _parse_python(pipeline_path)
    pipeline_tiers = _pipeline_tier_literals(pipeline_tree)
    skip_calls = _fast_pytest_skip_calls(repo_root)
    for tier_name, expected_lanes in _PIPELINE_TIER_CONTRACT.items():
        actual_lanes = pipeline_tiers.get(tier_name)
        if actual_lanes != expected_lanes:
            violations.append(
                ArchitectureViolation(
                    _relative(pipeline_path, repo_root),
                    "test-pipeline-tier-contract",
                    f"{tier_name!r} tier must be {expected_lanes!r}, got {actual_lanes!r}",
                )
            )
    for marker in _FOCUSED_PYTEST_MARKERS:
        if not _contains_marker(pipeline_text, marker):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(pipeline_path, repo_root),
                    "focused-pipeline-contract-test",
                    f"fast focused pytest lane must include {marker!r}",
                )
            )
    focused_targets = _focused_pytest_literals(pipeline_tree)
    for duplicate_target in _duplicate_items(focused_targets):
        violations.append(  # noqa: PERF401
            ArchitectureViolation(
                _relative(pipeline_path, repo_root),
                "focused-pipeline-duplicate-target",
                f"fast focused pytest lane must not duplicate target {duplicate_target!r}",
            )
        )
    for marker in _FOCUSED_PYTEST_FORBIDDEN_MARKERS:
        if marker in focused_targets:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(pipeline_path, repo_root),
                    "focused-pipeline-slow-target",
                    f"fast focused pytest lane must not include slow/corpus target {marker!r}",
                )
            )
    for target in focused_targets:
        path_text, *_selectors = target.split("::")
        target_path = repo_root / path_text
        if not target_path.exists():
            violations.append(
                ArchitectureViolation(
                    _relative(pipeline_path, repo_root),
                    "focused-pipeline-missing-target",
                    f"fast focused pytest lane references missing target {target!r}",
                )
            )
            continue
        target_exists, skip_xfail_lines = _fast_pytest_target_contract(repo_root, target, skip_calls)
        if not target_exists:
            violations.append(
                ArchitectureViolation(
                    _relative(pipeline_path, repo_root),
                    "focused-pipeline-missing-target",
                    f"fast focused pytest lane references missing pytest node {target!r}",
                )
            )
            continue
        for line_no in skip_xfail_lines:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(target_path, repo_root),
                    "focused-pipeline-skip-xfail",
                    f"fast focused pytest target {target!r} must not use skip/xfail at line {line_no}",
                )
            )
    typed_conditions = "angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py"
    jcc = "angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py"
    if (
        typed_conditions in focused_targets
        and jcc in focused_targets
        and focused_targets.index(typed_conditions) > focused_targets.index(jcc)
    ):
        violations.append(
            ArchitectureViolation(
                _relative(pipeline_path, repo_root),
                "focused-pipeline-jcc-order",
                "fast focused pytest lane must run typed-condition tests before JCC postprocess tests",
            )
        )
    return tuple(violations)


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _tuple_string_constants(node: ast.AST | None) -> frozenset[str]:
    if node is None:
        return frozenset()
    if isinstance(node, ast.Tuple):
        return frozenset(value for item in node.elts if (value := _string_constant(item)) is not None)
    value = _string_constant(node)
    if value is None:
        return frozenset()
    return frozenset({value})


def _ordered_tuple_string_constants(node: ast.AST | None) -> tuple[str, ...]:
    """Return literal tuple/list string contents while preserving source order."""

    if node is None:
        return ()
    if isinstance(node, ast.Tuple | ast.List):
        values: list[str] = []
        for item in node.elts:
            value = _string_constant(item)
            if value is not None:
                values.append(value)
        return tuple(values)
    value = _string_constant(node)
    return () if value is None else (value,)


def _architecture_required_source_path_reason(repo_root: Path, path_text: str) -> str | None:
    """Return why a mandatory ownership source path is stale or malformed."""

    if not path_text:
        return "required ownership source paths must be non-empty"
    if "\\" in path_text:
        return "required ownership source paths must use POSIX '/' separators"
    if Path(path_text).is_absolute():
        return "required ownership source paths must be repository-relative"
    if path_text.startswith("./") or path_text.endswith("/"):
        return "required ownership source paths must omit leading './' and trailing '/'"
    if any(part in {"", ".", ".."} for part in path_text.split("/")):
        return "required ownership source paths must not contain empty, '.', or '..' segments"
    if not (repo_root / path_text).exists():
        return f"required ownership source path does not exist: {path_text}"
    return None


def _ownership_manifest_rules(tree: ast.Module) -> dict[str, tuple[frozenset[str], bool, str]]:
    """Return ownership manifest rule paths and fallback metadata keyed by owner."""

    rules: dict[str, tuple[frozenset[str], bool, str]] = {}
    for node in _walk_ast(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "TestOwnershipRule":
            continue
        owner = _string_constant(_keyword_value(node, "owner") or ast.Constant(value=None))
        if owner is None:
            continue
        paths = _tuple_string_constants(_keyword_value(node, "paths"))
        fallback_node = _keyword_value(node, "fallback")
        fallback = isinstance(fallback_node, ast.Constant) and fallback_node.value is True
        reason = _string_constant(_keyword_value(node, "reason") or ast.Constant(value="")) or ""
        rules[owner] = (paths, fallback, reason)
    return rules


def _ownership_manifest_duplicate_owner_lines(tree: ast.Module) -> tuple[tuple[str, int], ...]:
    """Return duplicate ownership manifest owners with their duplicate call lines."""

    seen: set[str] = set()
    duplicates: list[tuple[str, int]] = []
    for node in _walk_ast(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "TestOwnershipRule":
            continue
        owner = _string_constant(_keyword_value(node, "owner") or ast.Constant(value=None))
        if owner is None:
            continue
        if owner in seen:
            duplicates.append((owner, node.lineno))
            continue
        seen.add(owner)
    return tuple(duplicates)


def _ownership_manifest_rule_tests(tree: ast.Module) -> dict[str, frozenset[str]]:
    """Return ownership manifest focused pytest targets keyed by owner."""

    tests_by_owner: dict[str, frozenset[str]] = {}
    for node in _walk_ast(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "TestOwnershipRule":
            continue
        owner = _string_constant(_keyword_value(node, "owner") or ast.Constant(value=None))
        if owner is None:
            continue
        tests_by_owner[owner] = _tuple_string_constants(_keyword_value(node, "tests"))
    return tests_by_owner


def _ownership_manifest_fast_test_targets(tree: ast.Module) -> frozenset[str]:
    """Return fast pytest targets selected by the changed-file ownership manifest."""

    targets: set[str] = set()
    for node in _walk_ast(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "TestOwnershipRule":
            continue
        tier = _string_constant(_keyword_value(node, "tier") or ast.Constant(value="fast")) or "fast"
        if tier != "fast":
            continue
        targets.update(_tuple_string_constants(_keyword_value(node, "tests")))
    return frozenset(targets)


def _check_ownership_manifest_contract(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    manifest_path = repo_root / "scripts" / "test_ownership_manifest.py"
    if not manifest_path.exists():
        return ()
    manifest_tree = _parse_python(manifest_path)
    rules = _ownership_manifest_rules(manifest_tree)
    tests_by_owner = _ownership_manifest_rule_tests(manifest_tree)
    skip_calls = _fast_pytest_skip_calls(repo_root)
    violations: list[ArchitectureViolation] = []
    for owner, line_no in _ownership_manifest_duplicate_owner_lines(manifest_tree):
        violations.append(
            ArchitectureViolation(
                _relative(manifest_path, repo_root),
                "ownership-manifest-duplicate-owner",
                f"TestOwnershipRule owner {owner!r} is duplicated at line {line_no}; duplicate owners hide coverage",
            )
        )
    if not skip_calls:
        violations.append(
            ArchitectureViolation(
                _relative(manifest_path, repo_root),
                "ownership-manifest-fast-skip-policy",
                "scripts/test_ownership_manifest.py must define literal FAST_PYTEST_SKIP_CALLS",
            )
        )
    for owner, required_path in _OWNERSHIP_MANIFEST_FALLBACK_RULES.items():
        paths, fallback, reason = rules.get(owner, (frozenset(), False, ""))
        if required_path not in paths or not fallback:
            violations.append(
                ArchitectureViolation(
                    _relative(manifest_path, repo_root),
                    "ownership-manifest-layer-fallback",
                    f"{owner!r} must cover {required_path!r} with fallback=True",
                )
            )
        elif not reason.strip():
            violations.append(
                ArchitectureViolation(
                    _relative(manifest_path, repo_root),
                    "ownership-manifest-fallback-reason",
                    f"{owner!r} must explain the fast architectural coverage for its fallback rule",
                )
            )
    for owner, required_paths in _OWNERSHIP_MANIFEST_REQUIRED_RULES.items():
        paths, _fallback, _reason = rules.get(owner, (frozenset(), False, ""))
        for required_path in required_paths:
            if required_path not in paths:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(manifest_path, repo_root),
                        "ownership-manifest-required-rule",
                        f"{owner!r} must cover {required_path!r}",
                    )
                )
    for owner, required_tests in _OWNERSHIP_MANIFEST_REQUIRED_TESTS.items():
        tests = tests_by_owner.get(owner, frozenset())
        for required_test in required_tests:
            if required_test not in tests:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(manifest_path, repo_root),
                        "ownership-manifest-required-test",
                        f"{owner!r} must run focused target {required_test!r}",
                    )
                )
    for target in sorted(_ownership_manifest_fast_test_targets(manifest_tree)):
        target_path = repo_root / target.split("::", 1)[0]
        _target_exists, skip_xfail_lines = _fast_pytest_target_contract(repo_root, target, skip_calls)
        for line_no in skip_xfail_lines:
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(target_path, repo_root),
                    "ownership-manifest-fast-skip-xfail",
                    f"fast ownership pytest target {target!r} must not use skip/xfail at line {line_no}",
                )
            )
    return tuple(violations)


def _module_calls_function(tree: ast.Module, function_name: str) -> bool:
    """Return whether a module contains a call to the named helper."""

    return any(isinstance(node, ast.Call) and _call_name(node.func) == function_name for node in _walk_ast(tree))


def _function_calls_function(function: ast.FunctionDef | ast.AsyncFunctionDef | None, function_name: str) -> bool:
    """Return whether a function body contains a call to the named helper."""

    if function is None:
        return False
    return any(isinstance(node, ast.Call) and _call_name(node.func) == function_name for node in _walk_ast(function))


def _stmt_calls_function(stmt: ast.stmt, function_name: str) -> bool:
    """Return whether one statement contains a call to the named helper."""

    return any(isinstance(node, ast.Call) and _call_name(node.func) == function_name for node in _walk_ast(stmt))


def _first_non_definition_statement(function: ast.FunctionDef | ast.AsyncFunctionDef | None) -> ast.stmt | None:
    """Return the first executable statement after local helper definitions."""

    if function is None:
        return None
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    for stmt in body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        return stmt
    return None


def _first_protected_runtime_import_line(tree: ast.Module) -> int | None:
    """Return the first decompiler/angr import that must be after runtime guard."""

    protected_prefixes = ("angr", "angr_platforms", "inertia_decompiler")
    allowed_modules = {
        "inertia_decompiler.architecture_runtime_guard",
    }
    protected_lines: list[int] = []
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.name in allowed_modules:
                    continue
                if alias.name.startswith(protected_prefixes):
                    protected_lines.append(stmt.lineno)
        elif isinstance(stmt, ast.ImportFrom):
            module = stmt.module or ""
            if module in allowed_modules or module == "architecture_runtime_guard":
                continue
            if module.startswith(protected_prefixes) or (stmt.level > 0 and module != "architecture_runtime_guard"):
                protected_lines.append(stmt.lineno)
    return min(protected_lines) if protected_lines else None


def _first_module_call_line(tree: ast.Module, function_name: str) -> int | None:
    """Return the first module-level executable call line for a named helper."""

    lines: list[int] = []
    for stmt in tree.body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            if _call_name(stmt.value.func) == function_name:
                lines.append(stmt.lineno)
        elif isinstance(stmt, ast.Try):
            for try_stmt in stmt.body:
                if isinstance(try_stmt, ast.Expr) and isinstance(try_stmt.value, ast.Call):  # noqa: SIM102
                    if _call_name(try_stmt.value.func) == function_name:
                        lines.append(try_stmt.lineno)
    return min(lines) if lines else None


def _handler_terminates_startup(handler: ast.ExceptHandler) -> bool:
    """Return whether an exception handler re-raises or exits startup."""

    for stmt in handler.body:
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call_name = _call_name(stmt.value.func)
            if call_name in {"sys.exit", "exit", "quit"}:
                return True
        if isinstance(stmt, ast.If) and any(isinstance(child, ast.Raise) for child in _walk_ast(stmt)):
            return True
    return False


def _swallowed_module_guard_try_lines(tree: ast.Module, function_name: str) -> tuple[int, ...]:
    """Return module-level try lines that catch a guard failure and continue startup."""

    lines: list[int] = []
    for stmt in tree.body:
        if not isinstance(stmt, ast.Try):
            continue
        if not any(_stmt_calls_function(try_stmt, function_name) for try_stmt in stmt.body):
            continue
        if any(not _handler_terminates_startup(handler) for handler in stmt.handlers):
            lines.append(stmt.lineno)
    return tuple(lines)


def _check_runtime_architecture_guard_entrypoints(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require runtime architecture checks on every public decompiler entrypoint."""

    violations: list[ArchitectureViolation] = []
    for relative_path in ("decompile.py", "inertia_decompiler/cli.py"):
        path = repo_root / relative_path
        if not path.exists():
            continue
        tree = _parse_python(path)
        guard_line = _first_module_call_line(tree, "assert_decompiler_architecture_clean")
        if guard_line is None:
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "runtime-architecture-guard-entrypoint",
                    "decompiler entrypoints must call assert_decompiler_architecture_clean() before startup",
                )
            )
            continue
        first_protected_import = _first_protected_runtime_import_line(tree)
        if first_protected_import is not None and first_protected_import < guard_line:
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "runtime-architecture-guard-order",
                    "decompiler entrypoints must call assert_decompiler_architecture_clean() before angr/decompiler imports",
                )
            )
        for line_no in _swallowed_module_guard_try_lines(tree, "assert_decompiler_architecture_clean"):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "runtime-architecture-guard-swallowed",
                    f"decompiler entrypoints must not catch and continue after architecture guard failures at line {line_no}",
                )
            )
    cli_core_path = repo_root / "inertia_decompiler" / "cli_core.py"
    if cli_core_path.exists():
        tree = _parse_python(cli_core_path)
        main_function = _find_function(tree, "main")
        if not _function_calls_function(main_function, "_ensure_runtime_architecture_guard_8616"):
            violations.append(
                ArchitectureViolation(
                    _relative(cli_core_path, repo_root),
                    "runtime-architecture-guard-entrypoint",
                    "cli_core.main() must call _ensure_runtime_architecture_guard_8616() before parsing/running work",
                )
            )
        impl_function = None
        if main_function is not None:
            impl_function = next(
                (stmt for stmt in main_function.body if isinstance(stmt, ast.FunctionDef) and stmt.name == "_impl"),
                None,
            )
        first_stmt = _first_non_definition_statement(impl_function)
        if first_stmt is None or not _stmt_calls_function(first_stmt, "_ensure_runtime_architecture_guard_8616"):
            violations.append(
                ArchitectureViolation(
                    _relative(cli_core_path, repo_root),
                    "runtime-architecture-guard-order",
                    "cli_core.main() must run _ensure_runtime_architecture_guard_8616() before parsing/running work",
                )
            )
    cod_dir_path = repo_root / "scripts" / "decompile_cod_dir.py"
    if cod_dir_path.exists():
        tree = _parse_python(cod_dir_path)
        main_function = _find_function(tree, "main")
        if not _function_calls_function(main_function, "_run_runtime_architecture_guard"):
            violations.append(
                ArchitectureViolation(
                    _relative(cod_dir_path, repo_root),
                    "runtime-architecture-guard-entrypoint",
                    "decompile_cod_dir.main() must call _run_runtime_architecture_guard() before batch work",
                )
            )
        first_stmt = _first_non_definition_statement(main_function)
        if first_stmt is None or not _stmt_calls_function(first_stmt, "_run_runtime_architecture_guard"):
            violations.append(
                ArchitectureViolation(
                    _relative(cod_dir_path, repo_root),
                    "runtime-architecture-guard-order",
                    "decompile_cod_dir.main() must run _run_runtime_architecture_guard() before batch work",
                )
            )
    return tuple(violations)


def _check_architecture_table_unique_keys(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require architecture marker tables to avoid duplicate literal entries."""

    architecture_path = repo_root / "scripts" / "check_decompiler_architecture.py"
    if not architecture_path.exists():
        return ()
    tree = _parse_python(architecture_path)
    violations: list[ArchitectureViolation] = []
    skip_calls = _fast_pytest_skip_calls(repo_root)
    for table_name, key, line_no in _dict_literal_duplicate_string_keys(
        tree,
        table_names=_ARCHITECTURE_UNIQUE_KEY_TABLES,
    ):
        violations.append(
            ArchitectureViolation(
                _relative(architecture_path, repo_root),
                "architecture-table-duplicate-key",
                f"{table_name} duplicates key {key!r} at line {line_no}; duplicate keys silently disable earlier rules",
            )
        )
    for table_name, value, line_no in _module_string_set_duplicate_values(
        tree,
        table_names=_ARCHITECTURE_UNIQUE_STRING_SET_TABLES,
    ):
        violations.append(
            ArchitectureViolation(
                _relative(architecture_path, repo_root),
                "architecture-table-duplicate-value",
                f"{table_name} duplicates value {value!r} at line {line_no}; duplicate frozenset entries hide debt-list churn",
            )
        )
    required_rule_entries = tuple(
        _dict_literal_tuple_values(
            tree,
            table_names=frozenset({"_OWNERSHIP_MANIFEST_REQUIRED_RULES"}),
        )
    )
    required_rule_owners = {
        key
        for table_name, key, _values, _line_no in required_rule_entries
        if table_name == "_OWNERSHIP_MANIFEST_REQUIRED_RULES"
    }
    for table_name, owner, required_paths, line_no in required_rule_entries:
        if table_name != "_OWNERSHIP_MANIFEST_REQUIRED_RULES":
            continue
        for required_path in required_paths:
            path_reason = _architecture_required_source_path_reason(repo_root, required_path)
            if path_reason is not None:
                violations.append(
                    ArchitectureViolation(
                        _relative(architecture_path, repo_root),
                        "architecture-required-rule-source",
                        f"_OWNERSHIP_MANIFEST_REQUIRED_RULES owner {owner!r} at line {line_no}: {path_reason}",
                    )
                )
    for _table_name, owner, required_tests, line_no in _dict_literal_tuple_values(
        tree,
        table_names=frozenset({"_OWNERSHIP_MANIFEST_REQUIRED_TESTS"}),
    ):
        if owner not in required_rule_owners:
            violations.append(
                ArchitectureViolation(
                    _relative(architecture_path, repo_root),
                    "architecture-required-test-owner",
                    f"_OWNERSHIP_MANIFEST_REQUIRED_TESTS owner {owner!r} at line {line_no} must also be in _OWNERSHIP_MANIFEST_REQUIRED_RULES",
                )
            )
        for required_test in required_tests:
            path_text, *_selectors = required_test.split("::")
            if path_text in _FOCUSED_PYTEST_FORBIDDEN_MARKERS:
                violations.append(
                    ArchitectureViolation(
                        _relative(architecture_path, repo_root),
                        "architecture-required-test-fast-target",
                        f"_OWNERSHIP_MANIFEST_REQUIRED_TESTS owner {owner!r} must not require slow/corpus target {required_test!r}",
                    )
                )
            target_path = repo_root / path_text
            if not target_path.exists():
                violations.append(
                    ArchitectureViolation(
                        _relative(architecture_path, repo_root),
                        "architecture-required-test-target",
                        f"_OWNERSHIP_MANIFEST_REQUIRED_TESTS owner {owner!r} references missing focused target {required_test!r}",
                    )
                )
                continue
            target_exists, skip_xfail_lines = _fast_pytest_target_contract(repo_root, required_test, skip_calls)
            if not target_exists:
                violations.append(
                    ArchitectureViolation(
                        _relative(architecture_path, repo_root),
                        "architecture-required-test-target",
                        f"_OWNERSHIP_MANIFEST_REQUIRED_TESTS owner {owner!r} references missing pytest node {required_test!r}",
                    )
                )
                continue
            for skip_line in skip_xfail_lines:
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(target_path, repo_root),
                        "architecture-required-test-skip-xfail",
                        f"_OWNERSHIP_MANIFEST_REQUIRED_TESTS target {required_test!r} must not use skip/xfail at line {skip_line}",
                    )
                )
    return tuple(violations)


def _check_architecture_header_marker_contracts(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require ownership marker tables to carry layer, responsibility, and boundary guidance."""

    architecture_path = repo_root / "scripts" / "check_decompiler_architecture.py"
    if not architecture_path.exists():
        return ()
    tree = _parse_python(architecture_path)
    violations: list[ArchitectureViolation] = []
    for table_name, key, markers, line_no in _dict_literal_tuple_values(
        tree,
        table_names=_OWNERSHIP_HEADER_MARKER_TABLES,
    ):
        if (
            len(markers) >= 3
            and markers[0].startswith("Layer:")
            and markers[1].strip()
            and markers[2].strip()
            and not markers[1].startswith("Layer:")
            and not markers[2].startswith("Layer:")
        ):
            continue
        violations.append(
            ArchitectureViolation(
                _relative(architecture_path, repo_root),
                "architecture-header-marker-contract",
                f"{table_name}[{key!r}] at line {line_no} must start with Layer and include responsibility and forbidden-boundary markers",
            )
        )
    return tuple(violations)


def _check_docstring_marker_contracts(repo_root: Path = REPO_ROOT) -> tuple[ArchitectureViolation, ...]:
    """Require docstring marker tables to keep layer and responsibility guidance."""

    architecture_path = repo_root / "scripts" / "check_decompiler_architecture.py"
    if not architecture_path.exists():
        return ()
    tree = _parse_python(architecture_path)
    violations: list[ArchitectureViolation] = []
    for table_name, key, markers, line_no in _dict_literal_tuple_values(
        tree,
        table_names=_DOCSTRING_HEADER_MARKER_TABLES,
    ):
        if any(marker.startswith("Layer:") for marker in markers) and any(
            marker.startswith("Responsibility:") for marker in markers
        ):
            continue
        violations.append(
            ArchitectureViolation(
                _relative(architecture_path, repo_root),
                "architecture-docstring-marker-contract",
                f"{table_name}[{key!r}] at line {line_no} must include Layer and Responsibility markers",
            )
        )
    for table_name, key, marker, line_no in _dict_literal_string_values(
        tree,
        table_names=_DOCSTRING_RESPONSIBILITY_MARKER_TABLES,
    ):
        if marker.startswith("Responsibility:"):
            continue
        violations.append(
            ArchitectureViolation(
                _relative(architecture_path, repo_root),
                "architecture-docstring-marker-contract",
                f"{table_name}[{key!r}] at line {line_no} must start with Responsibility:",
            )
        )
    return tuple(violations)


def _check_dynamic_attr_boundary_terms_match_changed_file_ratchet(
    repo_root: Path = REPO_ROOT,
) -> tuple[ArchitectureViolation, ...]:
    """Require architecture and changed-file ratchets to share dynamic-boundary terms."""

    architecture_path = repo_root / "scripts" / "check_decompiler_architecture.py"
    changed_ratchet_path = repo_root / "scripts" / "check_changed_non_test_types.py"
    if not architecture_path.exists() or not changed_ratchet_path.exists():
        return ()
    architecture_terms = _module_frozenset_string_constant(
        _parse_python(architecture_path), "_DYNAMIC_ATTR_BOUNDARY_TERMS"
    )
    changed_ratchet_terms = _module_frozenset_string_constant(
        _parse_python(changed_ratchet_path),
        "_DYNAMIC_ATTR_BOUNDARY_TERMS",
    )
    if architecture_terms == changed_ratchet_terms and architecture_terms is not None:
        return ()
    return (
        ArchitectureViolation(
            _relative(architecture_path, repo_root),
            "dynamic-attr-boundary-term-drift",
            "_DYNAMIC_ATTR_BOUNDARY_TERMS must match scripts/check_changed_non_test_types.py",
        ),
    )


def _check_project_awareness_docs(
    repo_root: Path = REPO_ROOT,
    agents_path: Path | None = None,
    project_map_path: Path | None = None,
    decompiler_map_path: Path | None = None,
    agent_rules_path: Path | None = None,
    understand_config_path: Path | None = None,
) -> tuple[ArchitectureViolation, ...]:
    agents_path = agents_path or repo_root / "AGENTS.md"
    project_map_path = project_map_path or repo_root / "reference" / "project-map.md"
    decompiler_map_path = decompiler_map_path or repo_root / "reference" / "decompiler-map.md"
    agent_rules_path = agent_rules_path or repo_root / "reference" / "agent-rules.md"
    understand_config_path = understand_config_path or repo_root / ".understand-anything" / "config.json"

    violations: list[ArchitectureViolation] = []
    agents_text = _read_text_if_present(agents_path)
    if agents_text is None:
        violations.append(
            ArchitectureViolation(
                _relative(agents_path, repo_root),
                "agent-doc-missing",
                "AGENTS.md must exist and point agents at the project map",
            )
        )
    else:
        line_count = len(agents_text.splitlines())
        if line_count > _AGENTS_MAX_LINES:
            violations.append(
                ArchitectureViolation(
                    _relative(agents_path, repo_root),
                    "agent-doc-too-large",
                    f"AGENTS.md has {line_count} lines; keep it at {_AGENTS_MAX_LINES} or fewer and move details to reference/",
                )
            )
        for marker in _AGENT_DOC_MARKERS:
            if not _contains_marker(agents_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(agents_path, repo_root),
                        "agent-doc-marker",
                        f"missing required startup reference {marker!r}",
                    )
                )
        for marker in _AGENT_DOC_FORBIDDEN_MARKERS:
            if _contains_marker(agents_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(agents_path, repo_root),
                        "agent-doc-duplicate-rulebook",
                        f"AGENTS.md must stay concise and avoid duplicate rule sections such as {marker!r}",
                    )
                )

    project_map_text = _read_text_if_present(project_map_path)
    if project_map_text is None:
        violations.append(
            ArchitectureViolation(
                _relative(project_map_path, repo_root),
                "project-map-missing",
                "reference/project-map.md must summarize repo modules, checks, and agent startup rules",
            )
        )
    else:
        line_count = len(project_map_text.splitlines())
        if line_count > _PROJECT_MAP_MAX_LINES:
            violations.append(
                ArchitectureViolation(
                    _relative(project_map_path, repo_root),
                    "project-map-too-large",
                    f"reference/project-map.md has {line_count} lines; keep it navigational and move details to narrower reference files",
                )
            )
        for marker in _PROJECT_MAP_MARKERS:
            if not _contains_marker(project_map_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(project_map_path, repo_root),
                        "project-map-marker",
                        f"missing required project map marker {marker!r}",
                    )
                )
        for marker in _REFERENCE_MAP_FORBIDDEN_RULEBOOK_MARKERS:
            if _contains_marker(project_map_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(project_map_path, repo_root),
                        "project-map-duplicate-rulebook",
                        f"reference/project-map.md must stay navigational and not restate AGENTS.md section {marker!r}",
                    )
                )

    decompiler_map_text = _read_text_if_present(decompiler_map_path)
    if decompiler_map_text is None:
        violations.append(
            ArchitectureViolation(
                _relative(decompiler_map_path, repo_root),
                "decompiler-map-marker",
                "reference/decompiler-map.md must summarize layer order and fast/default/expanded decompiler gates",
            )
        )
    else:
        line_count = len(decompiler_map_text.splitlines())
        if line_count > _DECOMPILER_MAP_MAX_LINES:
            violations.append(
                ArchitectureViolation(
                    _relative(decompiler_map_path, repo_root),
                    "decompiler-map-too-large",
                    f"reference/decompiler-map.md has {line_count} lines; keep it as a layer/gate map and move details to narrower reference files",
                )
            )
        for marker in _DECOMPILER_MAP_MARKERS:
            if not _contains_marker(decompiler_map_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(decompiler_map_path, repo_root),
                        "decompiler-map-marker",
                        f"missing required decompiler map marker {marker!r}",
                    )
                )
        for marker in _DECOMPILER_MAP_FORBIDDEN_MARKERS:
            if _contains_marker(decompiler_map_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(decompiler_map_path, repo_root),
                        "decompiler-map-duplicate-rulebook",
                        f"reference/decompiler-map.md must stay navigational and not restate AGENTS.md section {marker!r}",
                    )
                )

    agent_rules_text = _read_text_if_present(agent_rules_path)
    if agent_rules_text is None:
        violations.append(
            ArchitectureViolation(
                _relative(agent_rules_path, repo_root),
                "agent-rules-canonical-contract",
                "reference/agent-rules.md must exist and defer architecture rules to AGENTS.md",
            )
        )
    else:
        line_count = len(agent_rules_text.splitlines())
        if line_count > _AGENT_RULES_MAX_LINES:
            violations.append(
                ArchitectureViolation(
                    _relative(agent_rules_path, repo_root),
                    "agent-rules-too-large",
                    f"reference/agent-rules.md has {line_count} lines; keep it supplemental and move detailed plans to narrower reference files",
                )
            )
        for marker in _AGENT_RULES_MARKERS:
            if not _contains_marker(agent_rules_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(agent_rules_path, repo_root),
                        "agent-rules-canonical-contract",
                        f"missing required canonical-contract marker {marker!r}",
                    )
                )
        for marker in _AGENT_RULES_FORBIDDEN_MARKERS:
            if _contains_marker(agent_rules_text, marker):
                violations.append(  # noqa: PERF401
                    ArchitectureViolation(
                        _relative(agent_rules_path, repo_root),
                        "agent-rules-duplicate-rulebook",
                        f"reference/agent-rules.md must not restate canonical AGENTS.md section {marker!r}",
                    )
                )

    for relative_path in _ACTIVE_REFERENCE_PATHS:
        path = repo_root / relative_path
        if not path.exists():
            violations.append(
                ArchitectureViolation(
                    _relative(path, repo_root),
                    "active-reference-missing",
                    f"active agent/decompiler reference path must exist: {relative_path}",
                )
            )

    config_text = _read_text_if_present(understand_config_path)
    if config_text is None:
        violations.append(
            ArchitectureViolation(
                _relative(understand_config_path, repo_root),
                "understand-auto-update",
                "Understand-Anything config must exist with autoUpdate disabled",
            )
        )
    else:
        try:
            config = json.loads(config_text)
        except json.JSONDecodeError as exc:
            violations.append(
                ArchitectureViolation(
                    _relative(understand_config_path, repo_root),
                    "understand-auto-update",
                    f"config is not valid JSON: {exc.msg}",
                )
            )
        else:
            if config.get("autoUpdate") is not False:
                violations.append(
                    ArchitectureViolation(
                        _relative(understand_config_path, repo_root),
                        "understand-auto-update",
                        "autoUpdate must be false so agent runs do not mutate the graph unexpectedly",
                    )
                )

    return tuple(violations)


def _check_status_reporting_not_source_backed(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Reject stale source-backed acceptance wording in status reporting."""

    text = _read_text_if_present(path)
    if text is None or "source-backed quality guard rejected" not in text:
        return ()
    return (
        ArchitectureViolation(
            _relative(path, REPO_ROOT),
            "status-reporting-source-backed-quality",
            "status reporting must use final generated-C quality wording, not obsolete source-backed acceptance gates",
        ),
    )


def _function_arg_annotation(function: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> ast.AST | None:
    for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
        if arg.arg == name:
            return arg.annotation
    return None


def _class_field_annotation(class_node: ast.ClassDef, name: str) -> ast.AST | None:
    for stmt in class_node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == name:
            return stmt.annotation
    return None


def _check_sortdemo_status_reporting_typed_state(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require typed internal status state in the SORTDEMO reporting harness."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    violations: list[ArchitectureViolation] = []
    required_enums = ("TerminalStatus", "FailureStatus", "ValidationStatus", "AttemptStatus")
    for enum_name in required_enums:
        class_node = _find_class(tree, enum_name)
        if class_node is None or not any(
            _decorator_name(base) in {"Enum", "StrEnum"} for base in class_node.bases
        ):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "sortdemo-status-typed-state",
                    f"SORTDEMO status reporting must define {enum_name} enum for internal verdict state",
                )
            )
    function_status = _find_class(tree, "FunctionStatus")
    if function_status is None:
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "sortdemo-status-typed-state",
                "SORTDEMO status reporting must keep FunctionStatus as the typed internal record",
            )
        )
    else:
        required_fields = {
            "failure_status": "FailureStatus",
            "attempt": "AttemptStatus",
            "validation": "ValidationStatus",
        }
        for field_name, type_name in required_fields.items():
            if type_name not in _annotation_type_names(_class_field_annotation(function_status, field_name)):
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "sortdemo-status-typed-state",
                        f"FunctionStatus.{field_name} must use {type_name}, not raw strings",
                    )
                )
        terminal_status = _find_function(ast.Module(body=function_status.body, type_ignores=[]), "terminal_status")
        if terminal_status is None or "TerminalStatus" not in _annotation_type_names(terminal_status.returns):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "sortdemo-status-typed-state",
                    "FunctionStatus.terminal_status() must return TerminalStatus, not str",
                )
            )
    triage = _find_function(tree, "_build_triage")
    if triage is None or "FunctionStatus" not in _annotation_type_names(_function_arg_annotation(triage, "records")):
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "sortdemo-status-typed-state",
                "_build_triage() must consume typed FunctionStatus records before JSON serialization",
            )
        )
    return tuple(violations)


def _check_decompilation_quality_not_source_backed_named(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Reject obsolete source-backed naming for final generated-C quality gates."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    if _find_function(tree, "assess_source_backed_c_text") is None:
        return ()
    return (
        ArchitectureViolation(
            _relative(path, REPO_ROOT),
            "decompilation-quality-source-backed-name",
            "final generated-C quality gates must not be named as source-backed acceptance gates",
        ),
    )


def _check_grouped_graph_ir_address_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit IRAddress fields in grouped graph typed-IR scans."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    scanner = _find_function(tree, "_scan_typed_ir_block_8616")
    if scanner is None:
        return ()
    fields = {"space", "status", "segment_origin"}
    for node in _walk_ast(scanner):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in fields:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "grouped-graph-iraddress-dot-access",
                    f"typed-IR grouped graph scans must use IRAddress.{field_name}, not getattr()",
                ),
            )
    return ()


def _check_type_equivalence_typed_ir_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit typed-IR dataclass fields in type-equivalence scans."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    banned_fields_by_target = {
        "artifact": {"blocks"},
        "block": {"instrs"},
        "instr": {"args", "dst"},
        "atom": {"args", "base", "op", "segment_origin", "status"},
        "phi": {"incoming", "target"},
        "target": {"space"},
        "incoming": {"value"},
    }
    for function_name in ("_typed_ir_summary_from_codegen", "_typed_ir_equivalence_from_codegen"):
        function = _find_function(tree, function_name)
        if function is None:
            continue
        for node in _walk_ast(function):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
            ):
                continue
            target = node.args[0]
            target_name = target.id if isinstance(target, ast.Name) else None
            if target_name is None and isinstance(target, ast.Attribute):
                target_name = target.attr
            field_name = _string_constant(node.args[1])
            if field_name in banned_fields_by_target.get(target_name or "", set()):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "type-equivalence-typed-ir-dot-access",
                        f"type-equivalence typed-IR scans must use direct {target_name}.{field_name} fields, not getattr()",
                    ),
                )
    return ()


def _check_type_array_matching_typed_ir_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit IRAddress fields in typed array candidate scans."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    banned_fields_by_target = {
        "artifact": {"blocks", "records"},
        "function_ssa": {"phi_nodes"},
        "phi": {"target"},
        "target": {"name"},
        "block": {"instrs"},
        "instr": {"args"},
        "atom": {"base", "space", "status", "segment_origin", "size"},
        "record": {"source", "destination"},
    }
    for function_name in ("_typed_ir_array_candidates", "_typed_string_array_candidates"):
        scanner = _find_function(tree, function_name)
        if scanner is None:
            continue
        for node in _walk_ast(scanner):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
            ):
                continue
            target = node.args[0]
            target_name = target.id if isinstance(target, ast.Name) else None
            if target_name is None and isinstance(target, ast.Attribute):
                target_name = target.attr
            field_name = _string_constant(node.args[1])
            if field_name in banned_fields_by_target.get(target_name or "", set()):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "type-array-matching-iraddress-dot-access",
                        f"typed array candidate scans must use direct {target_name}.{field_name} fields, not getattr()",
                    ),
                )
    return ()


def _check_type_array_matching_induction_summary_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit InductionSummary fields in typed array induction scans."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for function_name in ("_has_induction_evidence_for_key_8616", "_profile_induction_match_8616"):
        scanner = _find_function(tree, function_name)
        if scanner is None:
            continue
        for node in _walk_ast(scanner):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in {"summary", "best_summary"}
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in {"index_key", "count", "stride", "width", "offset", "bound_candidate"}:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "type-array-induction-summary-dot-access",
                        f"typed array induction scans must narrow InductionSummary and use direct fields, not getattr({node.args[0].id}, {field_name!r})",
                    ),
                )
    return ()


def _check_type_structure_merging_typed_ir_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit owned IR/SSA fields in typed structure candidate scans."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    scanner = _find_function(tree, "_typed_ir_struct_candidates")
    if scanner is None:
        return ()
    banned_fields_by_target = {
        "phi": {"target"},
        "target": {"name"},
        "block": {"instrs"},
        "instr": {"args"},
        "atom": {"base", "space", "offset", "size"},
    }
    for node in _walk_ast(scanner):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
        ):
            continue
        target = node.args[0]
        target_name = target.id if isinstance(target, ast.Name) else None
        if target_name is None and isinstance(target, ast.Attribute):
            target_name = target.attr
        field_name = _string_constant(node.args[1])
        if field_name in banned_fields_by_target.get(target_name or "", set()):
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "type-structure-merging-typed-ir-dot-access",
                    f"typed structure candidate scans must use direct {target_name}.{field_name} fields, not getattr()",
                ),
            )
    return ()


def _check_structuring_alias_failure_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit AliasFailure/IRAddress fields in structuring alias gate."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    guard = _find_function(tree, "_assert_alias_complete_8616")
    if guard is None:
        return ()
    banned = {"address": {"status"}, "fact": {"address", "reason", "space"}}
    for node in _walk_ast(guard):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
        ):
            continue
        target_name = node.args[0].id
        field_name = _string_constant(node.args[1])
        if field_name in banned.get(target_name, set()):
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "structuring-alias-failure-dot-access",
                    f"structuring alias gate must use {target_name}.{field_name}, not getattr()",
                ),
            )
    return ()


def _check_stack_lowering_binding_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit owned fact/binding fields in fact-based stack lowering."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for function_name in (
        "build_stack_variable_bindings_from_alias_facts_8616",
        "lower_stack_accesses_from_alias_facts_8616",
    ):
        lowering = _find_function(tree, function_name)
        if lowering is None:
            continue
        owned_fields = {"binding": {"bp_offset", "size", "var_name"}, "fact": {"identity"}}
        for node in _walk_ast(lowering):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
            ):
                continue
            target_name = node.args[0].id
            field_name = _string_constant(node.args[1])
            if field_name in owned_fields.get(target_name, set()):
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "stack-lowering-binding-dot-access",
                        f"fact-based stack lowering must use {target_name}.{field_name}, not getattr()",
                    ),
                )
    return ()


def _check_fact_transfer_alias_fact_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit AliasStorageFacts fields in fact-transfer diagnostics."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for function_name in (
        "collect_semantic_alias_facts_from_project_8616",
        "transfer_semantic_alias_facts_to_codegen_8616",
    ):
        transfer = _find_function(tree, function_name)
        if transfer is None:
            continue
        for node in _walk_ast(transfer):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "fact"
                and _string_constant(node.args[1]) == "identity"
            ):
                continue
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "fact-transfer-alias-fact-dot-access",
                    "fact transfer must narrow AliasStorageFacts and use fact.identity, not getattr()",
                ),
            )
    return ()


def _check_real_mode_alias_fact_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require real-mode lowering to consume typed alias fact identities."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for function_name in (
        "_has_bp_stack_alias_evidence_8616",
        "_known_bp_stack_offsets_8616",
        "_has_stack_alias_fact_for_displacement_8616",
    ):
        helper = _find_function(tree, function_name)
        if helper is None:
            continue
        for node in _walk_ast(helper):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in {"fact", "slot"}
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in {"identity", "base", "offset", "width"}:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "real-mode-alias-fact-dot-access",
                        f"real-mode lowering must narrow typed alias facts and use direct {node.args[0].id}.{field_name}",
                    ),
                )
    return ()


def _check_real_mode_stack_probe_fact_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require real-mode lowering to consume typed stack-probe facts."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for function_name in (
        "_build_vvar_carrier_delta_map_8616",
        "_stack_pointer_carrier_offset_8616",
        "_ss_probe_enabled_8616",
    ):
        helper = _find_function(tree, function_name)
        if helper is None:
            continue
        for node in _walk_ast(helper):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "fact"
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in {"segment_space", "width"}:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "real-mode-stack-probe-fact-dot-access",
                        f"real-mode lowering must narrow TypedStackProbeReturnFact8616 and use direct fact.{field_name}",
                    ),
                )
    return ()


def _check_stack_probe_return_summary_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require stack-probe fact builders to consume typed callsite summaries."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    helper = _find_function(tree, "build_typed_stack_probe_return_facts_8616")
    if helper is None:
        return ()
    for node in _walk_ast(helper):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "summary"
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in {
            "stack_probe_helper",
            "helper_return_state",
            "helper_return_address_kind",
            "helper_return_space",
            "helper_return_width",
        }:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "stack-probe-return-summary-dot-access",
                    f"stack-probe return facts must narrow CallsiteSummary8616 and use direct summary.{field_name}",
                ),
            )
    return ()


def _check_stack_lowering_result_typed_status(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require StackLoweringStatus enum values for stack lowering results."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    lowering = _find_function(tree, "lower_stack_accesses_from_alias_facts_8616")
    if lowering is None:
        return ()
    for node in _walk_ast(lowering):
        if not (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "StackLoweringResult"
        ):
            continue
        for keyword in node.keywords:
            if keyword.arg != "status":
                continue
            status_value = _string_constant(keyword.value)
            if status_value is not None:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "stack-lowering-result-typed-status",
                        "StackLoweringResult.status must use StackLoweringStatus enum values, not raw strings",
                    ),
                )
    return ()


def _check_named_narrowed_fields_use_dot(
    path: Path,
    *,
    narrowed_fields: dict[str, set[str]],
    rule: str,
    detail_prefix: str,
) -> tuple[ArchitectureViolation, ...]:
    """Reject fixed getattr calls on named values narrowed by the owning module."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for target_name, field_name in _fixed_name_getattr_calls(tree):
        if field_name not in narrowed_fields.get(target_name, set()):
            continue
        return (
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                rule,
                f"{detail_prefix} must use {target_name}.{field_name} after type narrowing",
            ),
        )
    return ()


def _qualified_ast_name(node: ast.AST) -> str | None:
    """Return the dotted source name for a simple name or attribute expression."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _qualified_ast_name(node.value)
        return f"{owner}.{node.attr}" if owner is not None else None
    return None


def _isinstance_type_names(node: ast.AST) -> tuple[str, ...]:
    """Return all simple class names represented by an isinstance type operand."""

    if isinstance(node, ast.Tuple):
        names = tuple(_qualified_ast_name(item) for item in node.elts)
        return tuple(name for name in names if name is not None) if all(name is not None for name in names) else ()
    name = _qualified_ast_name(node)
    return (name,) if name is not None else ()


def _common_narrowed_fields(type_names: tuple[str, ...], class_fields: dict[str, set[str]]) -> set[str]:
    """Return fields owned by every class in one isinstance narrowing."""

    field_sets = tuple(class_fields.get(type_name) for type_name in type_names)
    if not field_sets or any(fields is None for fields in field_sets):
        return set()
    return set.intersection(*(fields for fields in field_sets if fields is not None))


def _positive_isinstance_narrowings(test: ast.AST) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Collect type narrowings guaranteed by a positive ``if`` condition."""

    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return tuple(narrowing for condition in test.values for narrowing in _positive_isinstance_narrowings(condition))
    if not (
        isinstance(test, ast.Call)
        and _qualified_ast_name(test.func) == "isinstance"
        and len(test.args) >= 2
        and isinstance(test.args[0], ast.Name)
    ):
        return ()
    type_names = _isinstance_type_names(test.args[1])
    return ((test.args[0].id, type_names),) if type_names else ()


def _check_isinstance_narrowed_fields_use_dot(
    path: Path,
    *,
    class_fields: dict[str, set[str]],
    rule: str,
    detail_prefix: str,
) -> tuple[ArchitectureViolation, ...]:
    """Reject fixed getattr calls made after a positive owned-class narrowing."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    for branch in (node for node in _walk_ast(tree) if isinstance(node, ast.If)):
        for target_name, type_names in _positive_isinstance_narrowings(branch.test):
            owned_fields = _common_narrowed_fields(type_names, class_fields)
            if not owned_fields:
                continue
            for statement in branch.body:
                for call_target_name, field_name in _fixed_name_getattr_calls(statement):
                    if call_target_name != target_name:
                        continue
                    if field_name not in owned_fields:
                        continue
                    return (
                        ArchitectureViolation(
                            _relative(path, REPO_ROOT),
                            rule,
                            f"{detail_prefix} must use {target_name}.{field_name} after {' | '.join(type_names)} narrowing",
                        ),
                    )
    return ()


def _negative_isinstance_narrowing(
    test: ast.AST, class_fields: dict[str, set[str]]
) -> tuple[str, tuple[str, ...]] | None:
    """Return the owned-class narrowing established after a negative guard."""

    if not (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Call)
        and _qualified_ast_name(test.operand.func) == "isinstance"
        and len(test.operand.args) >= 2
        and isinstance(test.operand.args[0], ast.Name)
    ):
        return None
    type_names = _isinstance_type_names(test.operand.args[1])
    if not _common_narrowed_fields(type_names, class_fields):
        return None
    return test.operand.args[0].id, type_names


def _statement_body_terminates(body: list[ast.stmt]) -> bool:
    """Return whether a simple guard body exits its current statement list."""

    return bool(body) and isinstance(body[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break))


def _assigned_ast_names(statement: ast.stmt) -> frozenset[str]:
    """Collect names directly rebound by a statement for narrowing invalidation."""

    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return frozenset()
    cached = _ASSIGNED_AST_NAMES_CACHE.get(statement)
    if cached is not None:
        return cached
    names: set[str] = set()
    for node in _walk_ast(statement):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        for target in targets:
            names.update(child.id for child in _walk_ast(target) if isinstance(child, ast.Name))
    result = frozenset(names)
    _ASSIGNED_AST_NAMES_CACHE[statement] = result
    return result


def _check_terminating_guard_narrowed_fields_use_dot(
    path: Path,
    *,
    class_fields: dict[str, set[str]],
    rule: str,
    detail_prefix: str,
) -> tuple[ArchitectureViolation, ...]:
    """Reject fixed getattr reads proven by an earlier terminating type guard."""

    if not path.exists():
        return ()
    tree = _parse_python(path)

    def _find_getattr(node: ast.AST, narrowed: dict[str, tuple[str, ...]]) -> tuple[str, str, str] | None:
        if not narrowed:
            return None
        for target_name, field_name in _fixed_name_getattr_calls(node):
            type_names = narrowed.get(target_name, ())
            if field_name in _common_narrowed_fields(type_names, class_fields):
                return target_name, " | ".join(type_names), field_name
        return None

    def _scan_statements(
        statements: list[ast.stmt], inherited: dict[str, tuple[str, ...]]
    ) -> tuple[str, str, str] | None:
        narrowed = dict(inherited)
        for statement in statements:
            found: tuple[str, str, str] | None = None
            if isinstance(statement, ast.If):
                found = _find_getattr(statement.test, narrowed)
                found = found or _scan_statements(statement.body, narrowed)
                found = found or _scan_statements(statement.orelse, narrowed)
                guard = _negative_isinstance_narrowing(statement.test, class_fields)
                if guard is not None and not statement.orelse and _statement_body_terminates(statement.body):
                    narrowed[guard[0]] = guard[1]
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                found = _find_getattr(statement.iter, narrowed)
                found = found or _scan_statements(statement.body, narrowed)
                found = found or _scan_statements(statement.orelse, narrowed)
                guard = None
            elif isinstance(statement, ast.While):
                found = _find_getattr(statement.test, narrowed)
                found = found or _scan_statements(statement.body, narrowed)
                found = found or _scan_statements(statement.orelse, narrowed)
                guard = None
            elif isinstance(statement, ast.Try):
                found = _scan_statements(statement.body, narrowed)
                for handler in statement.handlers:
                    found = found or _scan_statements(handler.body, narrowed)
                found = found or _scan_statements(statement.orelse, narrowed)
                found = found or _scan_statements(statement.finalbody, narrowed)
                guard = None
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    found = found or _find_getattr(item.context_expr, narrowed)
                found = found or _scan_statements(statement.body, narrowed)
                guard = None
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found = _scan_statements(statement.body, {})
                guard = None
            else:
                found = _find_getattr(statement, narrowed)
                guard = None
            if found is not None:
                return found
            if narrowed:
                for name in _assigned_ast_names(statement):
                    if guard is None or guard[0] != name:
                        narrowed.pop(name, None)
        return None

    found = _scan_statements(tree.body, {})
    if found is None:
        return ()
    target_name, type_name, field_name = found
    return (
        ArchitectureViolation(
            _relative(path, REPO_ROOT),
            rule,
            f"{detail_prefix} must use {target_name}.{field_name} after {type_name} guard",
        ),
    )


def _check_positive_and_guard_narrowed_fields_use_dot(
    path: Path,
    *,
    class_fields: dict[str, set[str]],
    rule: str,
    detail_prefix: str,
) -> tuple[ArchitectureViolation, ...]:
    """Check direct-field use after positive narrowing and terminating guards."""

    positive_violations = _check_isinstance_narrowed_fields_use_dot(
        path,
        class_fields=class_fields,
        rule=rule,
        detail_prefix=detail_prefix,
    )
    if positive_violations:
        return positive_violations
    return _check_terminating_guard_narrowed_fields_use_dot(
        path,
        class_fields=class_fields,
        rule=rule,
        detail_prefix=detail_prefix,
    )


def _check_stack_prototype_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after stack-prototype third-party values are narrowed."""

    return _check_named_narrowed_fields_use_dot(
        path,
        narrowed_fields={
            "cvar": {"name", "unified_variable", "variable", "variable_type"},
            "current_proto": {"args", "returnty", "variadic"},
            "return_type": {"label"},
            "typed_cfunc": {"arg_list", "functy", "prototype"},
            "typed_func": {"prototype"},
            "unified_variable": {"name"},
            "variable": {"name", "offset", "size"},
        },
        rule="stack-prototype-narrowed-field-dot-access",
        detail_prefix="stack prototype materialization",
    )


def _check_stack_c_ast_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after stack C-AST matcher values are narrowed."""

    return _check_named_narrowed_fields_use_dot(
        path,
        narrowed_fields={
            "cvar": {"variable"},
            "lhs": {"variable"},
            "node": {"name", "variable"},
            "operand": {"variable"},
            "stmt": {"lhs", "rhs"},
            "variable": {"name", "offset"},
        },
        rule="stack-c-ast-narrowed-field-dot-access",
        detail_prefix="stack C-AST matching",
    )


def _check_calling_convention_owned_seed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct access to owned call-target seed evidence."""

    return _check_named_narrowed_fields_use_dot(
        path,
        narrowed_fields={"seed": {"callsite_addr", "target_addr"}},
        rule="calling-convention-owned-seed-dot-access",
        detail_prefix="calling-convention compatibility",
    )


_C_AST_UTILS_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CBinaryOp": {"lhs", "op", "rhs"},
    "CDirtyExpression": {"dirty"},
    "CFunctionCall": {"args", "callee_func", "callee_target"},
    "CStatements": {"statements"},
    "CVariable": {"variable"},
    "SimMemoryVariable": {"addr", "size"},
    "SimRegisterVariable": {"reg", "size"},
    "SimStackVariable": {"base", "offset", "region", "size"},
}


_CLI_DEAD_LOCAL_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "structured_c.CAssignment": {"lhs", "rhs"},
    "structured_c.CFunctionCall": {"args", "callee_func", "callee_target"},
    "structured_c.CReturn": {"retval"},
    "structured_c.CVariable": {"unified_variable", "variable"},
}


def _check_cli_dead_local_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after dead-local pruning narrows stable C-AST nodes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_CLI_DEAD_LOCAL_NARROWED_CLASS_FIELDS,
        rule="cli-dead-local-narrowed-field-dot-access",
        detail_prefix="CLI dead-local pruning",
    )


def _check_lifter_operand_size_uses_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct size access on the established capstone operand contract."""

    return _check_named_narrowed_fields_use_dot(
        path,
        narrowed_fields={"operand": {"size"}},
        rule="lifter-operand-size-dot-access",
        detail_prefix="X86-16 lifter operand",
    )


def _check_c_ast_utils_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields on stable C-AST and SimVariable contracts."""

    named_violations = _check_named_narrowed_fields_use_dot(
        path,
        narrowed_fields={
            "lhs": {"callee_func", "callee_target"},
            "lvar": {"addr", "base", "offset", "reg", "region", "size"},
            "node": {"dirty"},
            "rhs": {"callee_func", "callee_target"},
            "rhs_call": {"args"},
            "rvar": {"addr", "base", "offset", "reg", "region", "size"},
        },
        rule="c-ast-utils-narrowed-field-dot-access",
        detail_prefix="C AST utility",
    )
    if named_violations:
        return named_violations
    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_C_AST_UTILS_NARROWED_CLASS_FIELDS,
        rule="c-ast-utils-narrowed-field-dot-access",
        detail_prefix="C AST utility",
    )


_STRUCTURING_CODEGEN_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "structured_c.CIfElse": {"condition_and_nodes", "else_node"},
    "structured_c.CStatements": {"statements"},
}


def _check_structuring_codegen_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after structuring codegen narrows stable C-AST nodes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_STRUCTURING_CODEGEN_NARROWED_CLASS_FIELDS,
        rule="structuring-codegen-narrowed-field-dot-access",
        detail_prefix="structuring codegen",
    )


_POSTPROCESS_SIMPLIFY_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs"},
    "CBinaryOp": {"lhs", "op", "rhs", "tags", "type"},
    "CDirtyExpression": {"dirty"},
    "CFunctionCall": {"args", "callee_func", "callee_target"},
    "CITE": {"iffalse", "iftrue", "tags", "type"},
    "CTypeCast": {"expr", "tags", "type"},
    "CUnaryOp": {"op", "operand", "tags", "type"},
    "CVariable": {"name", "tags", "type", "variable", "variable_type"},
}


def _check_postprocess_simplify_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields for owned domains and narrowed simplifier C-AST values."""

    named_violations = _check_named_narrowed_fields_use_dot(
        path,
        narrowed_fields={
            "candidate": {"rhs"},
            "expr": {"lhs", "op", "operand", "rhs"},
            "high_domain": {"space", "stack_slot", "width"},
            "high_expr": {"variable", "variable_type"},
            "high_slot": {"base", "offset", "region"},
            "lhs": {"operand", "tags"},
            "low_expr": {"variable", "variable_type"},
            "next_stmt": {"lhs", "rhs"},
            "node": {"name", "operand", "tags", "variable"},
            "operand": {"tags", "variable"},
            "source_expr": {"lhs", "rhs", "tags"},
            "stmt": {"lhs", "rhs"},
            "target": {"variable"},
            "target_domain": {"space", "stack_slot", "width"},
            "variable": {"addr", "name", "offset", "reg", "size"},
            "word_domain": {"space", "stack_slot", "width"},
            "word_slot": {"base", "offset", "region"},
        },
        rule="postprocess-simplify-narrowed-field-dot-access",
        detail_prefix="postprocess simplification",
    )
    if named_violations:
        return named_violations
    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_POSTPROCESS_SIMPLIFY_NARROWED_CLASS_FIELDS,
        rule="postprocess-simplify-narrowed-field-dot-access",
        detail_prefix="postprocess simplification",
    )


_POSTPROCESS_CALLS_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CBinaryOp": {"lhs", "op", "rhs"},
    "CFunctionCall": {"args", "callee_func", "callee_target"},
    "CIndexedVariable": {"index", "variable"},
    "SimMemoryVariable": {"addr", "size"},
    "SimRegisterVariable": {"reg", "size"},
    "SimStackVariable": {"base", "name", "offset", "size"},
    "structured_c.CAssignment": {"lhs", "rhs"},
    "structured_c.CBinaryOp": {"lhs", "op", "rhs"},
    "structured_c.CConstant": {"value"},
    "structured_c.CFunctionCall": {"args", "callee_func", "callee_target"},
    "structured_c.CIfElse": {"condition_and_nodes", "else_node"},
    "structured_c.CIndexedVariable": {"index", "variable"},
    "structured_c.CReturn": {"retval"},
    "structured_c.CVariable": {"name", "variable", "variable_type"},
}


_REAL_MODE_LINEAR_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "SimMemoryVariable": {"addr", "size"},
    "SimRegisterVariable": {"name", "reg", "size"},
    "SimStackVariable": {"base", "name", "offset", "size"},
    "SimTypeChar": {"signed"},
    "SimTypeInt": {"signed"},
    "SimTypeLong": {"signed"},
    "SimTypeShort": {"signed"},
    "SimVariable": {"name"},
    "structured_c.CAssignment": {"lhs", "rhs", "tags"},
    "structured_c.CBinaryOp": {"codegen", "lhs", "op", "rhs"},
    "structured_c.CConstant": {"value"},
    "structured_c.CFunctionCall": {"args"},
    "structured_c.CIndexedVariable": {"index", "variable"},
    "structured_c.CReturn": {"retval"},
    "structured_c.CTypeCast": {"expr"},
    "structured_c.CUnaryOp": {"codegen", "op", "operand"},
    "structured_c.CVariable": {"name", "variable", "variable_type"},
}


_POSTPROCESS_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"codegen", "lhs", "rhs"},
    "CFunctionCall": {"args"},
    "CIndexedVariable": {"index", "variable"},
    "CLabel": {"name"},
    "CReturn": {"codegen", "retval"},
    "CStatements": {"statements"},
    "CVariable": {"name", "unified_variable", "variable", "variable_type"},
    "SimMemoryVariable": {"addr", "name", "size"},
    "SimRegisterVariable": {"reg", "size"},
    "SimStackVariable": {"offset", "size"},
    "SimTypeFunction": {"arg_names", "args"},
}


_CLI_C_AST_REWRITES_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "SimMemoryVariable": {"addr", "name", "size"},
    "SimRegisterVariable": {"name", "reg", "size"},
    "SimStackVariable": {"base", "name", "offset", "region", "size"},
    "structured_c.CAssignment": {"lhs", "rhs"},
    "structured_c.CBinaryOp": {"codegen", "tags", "type"},
    "structured_c.CFunctionCall": {"args", "callee_func", "callee_target"},
    "structured_c.CTypeCast": {"codegen", "expr", "type"},
    "structured_c.CUnaryOp": {"codegen", "operand", "tags", "type"},
    "structured_c.CVariable": {"name", "unified_variable", "variable", "variable_type"},
}


_POSTPROCESS_JCC_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs", "tags"},
    "CBinaryOp": {"common_type", "lhs", "op", "rhs"},
    "CConstant": {"_type", "value"},
    "CFunctionCall": {"callee_target"},
    "CITE": {"cond", "iffalse", "iftrue"},
    "CIfElse": {"condition_and_nodes", "else_node"},
    "CReturn": {"retval"},
    "CStatements": {"statements"},
    "CTypeCast": {"dst_type", "expr", "src_type"},
    "CUnaryOp": {"operand"},
    "CVariable": {"name", "unified_variable", "variable", "variable_type"},
    "SimRegisterVariable": {"reg", "size"},
    "SimStackVariable": {"name", "offset"},
}


_POSTPROCESS_STAGE_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs"},
    "CBinaryOp": {"lhs", "op", "rhs", "tags"},
    "CConstant": {"reference_values", "tags", "value"},
    "CForLoop": {"condition"},
    "CFunctionCall": {"callee_func", "callee_target"},
    "CIfBreak": {"condition"},
    "CIfElse": {"condition_and_nodes", "else_node"},
    "CStatements": {"statements"},
    "CTypeCast": {"dst_type", "expr", "src_type", "tags"},
    "CUnaryOp": {"op", "operand", "tags"},
    "CVariable": {"codegen", "name", "tags", "unified_variable", "variable", "variable_type", "vvar_id"},
    "SimStackVariable": {"name", "offset", "size"},
    "SimTypeFunction": {"arg_names", "args"},
}


_TAIL_VALIDATION_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs"},
    "CDoWhileLoop": {"body", "condition"},
    "CForLoop": {"body", "condition", "initializer", "iterator"},
    "CFunctionCall": {"args"},
    "CGoto": {"target", "target_idx"},
    "CIfBreak": {"condition"},
    "CIfElse": {"codegen", "condition_and_nodes", "else_node"},
    "CReturn": {"retval"},
    "CStatements": {"statements"},
    "CSwitchCase": {"cases", "default", "switch"},
    "CWhileLoop": {"body", "condition"},
}


_LOOP_BODY_REPAIR_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs"},
    "CBinaryOp": {"op"},
    "CDoWhileLoop": {"body"},
    "CForLoop": {"body"},
    "CIfBreak": {"condition"},
    "CIfElse": {"condition_and_nodes", "else_node"},
    "CStatements": {"statements"},
    "CSwitchCase": {"default"},
    "CVariable": {"variable"},
    "CWhileLoop": {"body"},
    "SimRegisterVariable": {"name", "reg", "size"},
    "SimStackVariable": {"base", "name", "offset", "size"},
}


_STACK_LOWERING_IMPL_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "SimStackVariable": {"base", "name", "offset", "size"},
    "structured_c.CAssignment": {"lhs", "rhs"},
    "structured_c.CBinaryOp": {"codegen"},
    "structured_c.CIndexedVariable": {"index", "type", "variable"},
    "structured_c.CUnaryOp": {"operand", "type"},
    "structured_c.CVariable": {"name", "variable", "variable_type"},
}


_RETURN_CHAINS_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs"},
    "CConstant": {"value"},
    "CExpressionStatement": {"expr"},
    "CFunctionCall": {"tags"},
    "CIfElse": {"condition_and_nodes", "else_node"},
    "CReturn": {"retval"},
    "CStatements": {"statements"},
    "CVariable": {"name", "variable"},
}


_RETURN_COMPAT_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CVariable": {"name", "unified_variable", "variable"},
    "SimStackVariable": {"offset"},
    "SimTypeLong": {"signed"},
    "ailment.Expr.BinaryOp": {"op", "operands"},
    "ailment.Expr.Const": {"value"},
    "ailment.Expr.Load": {"addr", "bits", "tags"},
    "ailment.Expr.Register": {"bits", "reg_offset"},
    "ailment.Expr.Tmp": {"tmp_idx"},
    "ailment.Stmt.Assignment": {"dst", "src"},
    "unary_op_type": {"operand"},
}


_SEGMENTED_GLOBAL_LOADS_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CBinaryOp": {"codegen"},
    "CDirtyExpression": {"dirty", "idx"},
    "CFunctionCall": {"args", "callee_func", "callee_target"},
    "SimStackVariable": {"base", "offset", "size"},
}


_STRUCTURING_STAGE_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CBinaryOp": {"lhs", "rhs", "tags"},
    "CIfElse": {"else_node"},
    "CStatements": {"statements"},
    "CTypeCast": {"expr"},
    "CUnaryOp": {"operand", "tags"},
}


_CLI_DECOMPILATION_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "SimRegisterVariable": {"reg"},
    "SimTypeShort": {"signed"},
    "structured_c.CFunctionCall": {"callee_func", "callee_target"},
    "structured_c.CUnaryOp": {"operand"},
    "structured_c.CVariable": {"name", "variable", "vvar_id"},
}


_POSTPROCESS_OPTIMIZATION_NARROWED_CLASS_FIELDS: dict[str, set[str]] = {
    "CAssignment": {"lhs", "rhs"},
    "CBinaryOp": {"lhs", "op", "rhs"},
    "CVariable": {"name", "variable"},
    "SimStackVariable": {"base", "offset"},
}


def _check_postprocess_optimization_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after postprocess optimization narrows stable classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_POSTPROCESS_OPTIMIZATION_NARROWED_CLASS_FIELDS,
        rule="postprocess-optimization-narrowed-field-dot-access",
        detail_prefix="postprocess optimization",
    )


def _check_cli_decompilation_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after CLI decompilation narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_CLI_DECOMPILATION_NARROWED_CLASS_FIELDS,
        rule="cli-decompilation-narrowed-field-dot-access",
        detail_prefix="CLI decompilation",
    )


def _check_structuring_stage_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after the structuring stage narrows stable C-AST classes."""

    return _check_isinstance_narrowed_fields_use_dot(
        path,
        class_fields=_STRUCTURING_STAGE_NARROWED_CLASS_FIELDS,
        rule="structuring-stage-narrowed-field-dot-access",
        detail_prefix="structuring stage",
    )


def _check_segmented_global_loads_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after segmented-global lowering narrows angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_SEGMENTED_GLOBAL_LOADS_NARROWED_CLASS_FIELDS,
        rule="segmented-global-loads-narrowed-field-dot-access",
        detail_prefix="segmented-global lowering",
    )


def _check_return_compat_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after return compatibility narrows stable AIL classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_RETURN_COMPAT_NARROWED_CLASS_FIELDS,
        rule="return-compat-narrowed-field-dot-access",
        detail_prefix="return compatibility",
    )


def _check_return_chains_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after return-chain structuring narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_RETURN_CHAINS_NARROWED_CLASS_FIELDS,
        rule="return-chains-narrowed-field-dot-access",
        detail_prefix="return-chain structuring",
    )


def _check_stack_lowering_impl_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after stack lowering narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_STACK_LOWERING_IMPL_NARROWED_CLASS_FIELDS,
        rule="stack-lowering-impl-narrowed-field-dot-access",
        detail_prefix="stack lowering implementation",
    )


def _check_loop_body_repair_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after loop-body repair narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_LOOP_BODY_REPAIR_NARROWED_CLASS_FIELDS,
        rule="loop-body-repair-narrowed-field-dot-access",
        detail_prefix="loop-body repair",
    )


def _check_tail_validation_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after tail validation narrows stable C-AST classes."""

    return _check_isinstance_narrowed_fields_use_dot(
        path,
        class_fields=_TAIL_VALIDATION_NARROWED_CLASS_FIELDS,
        rule="tail-validation-narrowed-field-dot-access",
        detail_prefix="tail validation",
    )


def _check_postprocess_stage_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after the postprocess stage narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_POSTPROCESS_STAGE_NARROWED_CLASS_FIELDS,
        rule="postprocess-stage-narrowed-field-dot-access",
        detail_prefix="postprocess stage",
    )


def _check_postprocess_jcc_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after JCC cleanup narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_POSTPROCESS_JCC_NARROWED_CLASS_FIELDS,
        rule="postprocess-jcc-narrowed-field-dot-access",
        detail_prefix="JCC postprocess cleanup",
    )


def _check_cli_c_ast_rewrites_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after CLI C-AST cleanup narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_CLI_C_AST_REWRITES_NARROWED_CLASS_FIELDS,
        rule="cli-c-ast-rewrites-narrowed-field-dot-access",
        detail_prefix="CLI C-AST cleanup",
    )


def _check_postprocess_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after postprocess cleanup narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_POSTPROCESS_NARROWED_CLASS_FIELDS,
        rule="postprocess-narrowed-field-dot-access",
        detail_prefix="postprocess cleanup",
    )


def _check_real_mode_linear_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after real-mode lowering narrows stable angr classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_REAL_MODE_LINEAR_NARROWED_CLASS_FIELDS,
        rule="real-mode-linear-narrowed-field-dot-access",
        detail_prefix="real-mode linear lowering",
    )


def _check_postprocess_calls_narrowed_fields_use_dot(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require direct fields after call cleanup narrows owned angr node classes."""

    return _check_positive_and_guard_narrowed_fields_use_dot(
        path,
        class_fields=_POSTPROCESS_CALLS_NARROWED_CLASS_FIELDS,
        rule="postprocess-calls-narrowed-field-dot-access",
        detail_prefix="postprocess call cleanup",
    )


def _check_stack_lowering_impl_binding_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit StackVariableBinding fields in stack lowering consumers."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    owned_fields = {"bp_offset", "offset", "size"}
    for node in _walk_ast(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "binding"
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in owned_fields:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "stack-lowering-impl-binding-dot-access",
                    f"stack lowering consumers must use typed StackVariableBinding fields, not getattr(binding, {field_name!r})",
                ),
            )
    return ()


def _check_stack_lowering_impl_alias_fact_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require explicit AliasStorageFacts fields in stack lowering consumers."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    helper = _find_function(tree, "_typed_alias_fact_bp_offsets_8616")
    if helper is None:
        return ()
    for node in _walk_ast(helper):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in {"fact", "slot"}
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in {"identity", "base", "offset", "width"}:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "stack-lowering-impl-alias-fact-dot-access",
                    f"stack lowering alias consumers must narrow AliasStorageFacts and use direct {node.args[0].id}.{field_name}",
                ),
            )
    return ()


def _check_tail_validation_binding_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require tail validation fingerprints to consume typed stack bindings."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    mapper = _find_function(tree, "_materialized_local_map_8616")
    if mapper is None:
        return ()
    for node in _walk_ast(mapper):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "binding"
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in {"bp_offset", "size", "var_name"}:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "tail-validation-binding-dot-access",
                    f"tail validation fingerprints must use typed StackVariableBinding fields, not getattr(binding, {field_name!r})",
                ),
            )
    return ()


def _check_tail_validation_callsite_summary_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require live tail-validation summaries to use typed callsite fields."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    helper_names = {
        "_summary_is_stack_probe_helper_8616",
        "_call_summary_target_addr_8616",
        "_call_summary_callsite_addr_8616",
        "_prunable_live_out_segment_write_ids_8616",
    }
    fields = {
        "stack_probe_helper",
        "target_addr",
        "callsite_addr",
        "arg_count",
        "push_arg_sources",
    }
    for helper_name in helper_names:
        helper = _find_function(tree, helper_name)
        if helper is None:
            continue
        for node in _walk_ast(helper):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "summary"
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in fields:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "tail-validation-callsite-summary-dot-access",
                        f"tail validation must narrow CallsiteSummary8616 and use summary.{field_name}",
                    ),
                )
    return ()


def _check_call_recovery_summary_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require recovered-call queues to consume typed callsite summaries."""
    if not path.exists():
        return ()
    tree = _parse_python(path)
    helper_names = {
        "_recover_missing_direct_calls_from_evidence_8616",
        "_insert_missing_calls_8616",
        "_summary_looks_loop_carried_arg_8616",
    }
    for helper_name in helper_names:
        helper = _find_function(tree, helper_name)
        if helper is None:
            continue
        for node in _walk_ast(helper):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in {"summary", "summary_obj"}
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in {"arg_sources", "push_arg_sources"}:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "call-recovery-summary-dot-access",
                        (f"call recovery must narrow CallsiteSummary8616 and use summary.{field_name}, not getattr"),
                    ),
                )
    return ()


def _check_ss_bp_substitution_binding_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require SS:BP C-text substitution to consume typed stack bindings."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    substitution = _find_function(tree, "substitute_ss_bp_dereferences_with_variables")
    if substitution is None:
        return ()
    violations: list[ArchitectureViolation] = []
    for arg in substitution.args.args:
        if arg.arg == "bindings" and "StackVariableBinding" not in _annotation_type_names(arg.annotation):
            violations.append(  # noqa: PERF401
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "ss-bp-substitution-typed-bindings",
                    "SS:BP substitution must type bindings as StackVariableBinding, not generic object records",
                )
            )
    for node in _walk_ast(substitution):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in {"binding", "b"}
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in {"bp_offset", "var_name", "offset", "name", "size"}:
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "ss-bp-substitution-binding-dot-access",
                    f"SS:BP substitution must use typed StackVariableBinding fields, not getattr({node.args[0].id}, {field_name!r})",
                )
            )
    return tuple(violations)


def _check_callsite_materialization_stats_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require callsite materialization completeness checks to use typed stats fields."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    checker = _find_function(tree, "_callsite_materialization_complete_8616")
    if checker is None:
        return ()
    owned_fields = {
        "call_target_fact_count",
        "call_target_materialized_count",
        "call_arg_fact_count",
        "call_arg_materialized_count",
    }
    for node in _walk_ast(checker):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "stats"
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in owned_fields:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "callsite-materialization-stats-dot-access",
                    f"callsite materialization completeness must use stats.{field_name}, not getattr(stats, ...)",
                ),
            )
    return ()


def _check_callsite_stack_summary_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require callsite stack metadata pruning to consume typed callsite summaries."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    checker = _find_function(tree, "prune_materialized_callsite_segment_metadata_8616")
    if checker is None:
        return ()
    for node in _walk_ast(checker):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in {"summary", "item"}
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in {"stack_probe_helper", "helper_return_state", "helper_return_space"}:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "callsite-stack-summary-dot-access",
                    f"callsite stack metadata pruning must narrow CallsiteSummary8616 and use direct {node.args[0].id}.{field_name}",
                ),
            )
    return ()


def _check_postprocess_calls_summary_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require postprocess call matching helpers to use typed callsite summaries."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    helper_names = {"_call_node_matches_summary_8616", "_call_node_can_take_summary_8616"}
    fields = {"stack_probe_helper", "target_addr", "arg_count", "stack_cleanup"}
    for helper_name in helper_names:
        helper = _find_function(tree, helper_name)
        if helper is None:
            continue
        for node in _walk_ast(helper):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "summary"
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in fields:
                return (
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "postprocess-calls-summary-dot-access",
                        f"postprocess call matching must narrow CallsiteSummary8616 and use summary.{field_name}",
                    ),
                )
    return ()


def _check_postprocess_stack_identity_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require postprocess stack-prune helpers to use typed stack identities."""

    if not path.exists():
        return ()
    helper = _find_function(_parse_python(path), "_prune_return_address_stack_arguments_8616")
    if helper is None:
        return ()
    for node in _walk_ast(helper):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "identity"
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name in {"base", "offset"}:
            return (
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "postprocess-stack-identity-dot-access",
                    f"return-address pruning must narrow _StackSlotIdentity and use identity.{field_name}",
                ),
            )
    return ()


def _check_structuring_diagnostics_stats_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require structuring diagnostics to use typed stats fields after narrowing."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    owned_fields = {
        "iterations",
        "regions_reduced",
        "cycles_resolved",
        "max_iterations_reached",
        "had_unstructured_gotos",
    }
    violations: list[ArchitectureViolation] = []
    for function_name in (
        "build_failure_reason_from_stats",
        "suggest_recovery_hints",
        "apply_x86_16_structuring_diagnostics",
    ):
        function = _find_function(tree, function_name)
        if function is None:
            continue
        for node in _walk_ast(function):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in {"stats", "structuring_stats"}
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name in owned_fields:
                violations.append(
                    ArchitectureViolation(
                        _relative(path, REPO_ROOT),
                        "structuring-diagnostics-stats-dot-access",
                        f"structuring diagnostics must use typed {node.args[0].id}.{field_name}, not getattr()",
                    )
                )
    return tuple(violations)


def _check_return_chain_codegen_metadata_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require return-chain structuring to use typed Inertia codegen contract fields."""

    if not path.exists():
        return ()
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(_parse_python(path)):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "codegen"
        ):
            continue
        field_name = _string_constant(node.args[1])
        if field_name == "cfunc" or (field_name is not None and field_name.startswith("_inertia_")):
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "return-chain-codegen-metadata-dot-access",
                    f"return-chain structuring must use typed codegen.{field_name}, not getattr(codegen, ...)",
                )
            )
    return tuple(violations)


def _check_segmented_global_materializer_codegen_dot_access(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require segmented-global materializer entrypoints to use typed codegen.cfunc access."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    materializers = (
        "materialize_named_segmented_global_loads_8616",
        "materialize_direct_global_symbol_stores_from_evidence_8616",
        "materialize_indexed_segmented_global_loads_from_evidence_8616",
        "materialize_compare_register_global_carriers_from_evidence_8616",
    )
    violations: list[ArchitectureViolation] = []
    for function_name in materializers:
        function = _find_function(tree, function_name)
        if function is None:
            continue
        for node in _walk_ast(function):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "codegen"
                and _string_constant(node.args[1]) == "cfunc"
            ):
                continue
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "segmented-global-materializer-codegen-dot-access",
                    f"{function_name} must use typed codegen.cfunc, not getattr(codegen, ...)",
                )
            )
    return tuple(violations)


def _check_segmented_global_codegen_boundary_helpers(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Require segmented-global codegen dynamic attrs to stay behind named boundary helpers."""

    if not path.exists():
        return ()
    tree = _parse_python(path)
    allowed_helpers = {"_codegen_cfunc_optional_8616", "_codegen_project_optional_8616"}
    violations: list[ArchitectureViolation] = []
    for function in (node for node in _walk_ast(tree) if isinstance(node, ast.FunctionDef)):
        if function.name in allowed_helpers:
            continue
        for node in _walk_ast(function):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "codegen"
            ):
                continue
            field_name = _string_constant(node.args[1])
            if field_name not in {"cfunc", "project"}:
                continue
            violations.append(
                ArchitectureViolation(
                    _relative(path, REPO_ROOT),
                    "segmented-global-codegen-boundary-helper",
                    f"{function.name} must use _codegen_{field_name}_optional_8616(), not getattr(codegen, ...)",
                )
            )
    return tuple(violations)


_FORBIDDEN_GLOBAL_EVIDENCE_CACHE_NAMES = frozenset(
    {
        "_accesses_by_block",
        "_accesses_by_function",
        "clear_accesses_for_block",
        "clear_accesses_for_function",
        "get_accesses_for_block",
        "get_accesses_for_function",
        "migrate_block_accesses_to_function",
        "record_access_by_block",
        "set_current_function_addr",
    }
)


def _check_semantic_evidence_context_ownership(path: Path) -> tuple[ArchitectureViolation, ...]:
    """Reject process-global address-keyed semantic evidence ownership."""
    if not path.is_file():
        return ()
    tree = _parse_python(path)
    if tree is None:
        return ()
    violations: list[ArchitectureViolation] = []
    for node in _walk_ast(tree):
        name: str | None = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            name = node.id
        if name not in _FORBIDDEN_GLOBAL_EVIDENCE_CACHE_NAMES:
            continue
        violations.append(
            ArchitectureViolation(
                _relative(path, REPO_ROOT),
                "semantic-evidence-context-ownership",
                f"{name} reintroduces address-keyed global evidence; use an explicit collection context",
            )
        )
    return tuple(violations)


def check_decompiler_architecture(
    root: Path = X86_16_ROOT,
    cli_path: Path = CLI_DECOMPILATION,
    repo_root: Path = REPO_ROOT,
) -> tuple[ArchitectureViolation, ...]:
    """Return static architecture violations for the decompiler workspace."""

    violations: list[ArchitectureViolation] = []
    violations.extend(_check_postprocess_headers(root))
    violations.extend(_check_postprocess_imports(root))
    violations.extend(_check_postprocess_source_text_recovery(root))
    violations.extend(_check_semantic_layers_do_not_import_postprocess(root))
    violations.extend(_check_compatibility_shims(root))
    violations.extend(_check_cli_imports(cli_path))
    violations.extend(_check_cli_c_text_cleanup(repo_root / "inertia_decompiler" / "c_text_cleanup.py"))
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_fallback_decompilation.py")
    )
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_decompilation.py")
    )
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py")
    )
    violations.extend(
        _check_cli_source_header_recovery_inactive(repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py")
    )
    violations.extend(_check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_core.py"))
    violations.extend(_check_cli_acceptance_not_source_evidence_gated(repo_root / "inertia_decompiler" / "cli_core.py"))
    violations.extend(_check_cli_not_source_backed_quality_gated(repo_root / "inertia_decompiler" / "cli_core.py"))
    violations.extend(
        _check_cli_not_source_backed_quality_gated(repo_root / "inertia_decompiler" / "cli_decompilation.py")
    )
    violations.extend(
        _check_forced_corpus_templates_inert(
            repo_root / "inertia_decompiler" / "cli_decompilation.py",
            repo_root / "decompile.py",
        )
    )
    violations.extend(
        _check_cli_ast_cod_callee_names_inert(
            repo_root / "inertia_decompiler" / "cli_c_ast_rewrites.py",
            repo_root / "inertia_decompiler" / "cli_decompilation.py",
        )
    )
    violations.extend(
        _check_cli_cod_call_names_not_semantic(
            repo_root / "inertia_decompiler" / "cli_decompilation.py",
            repo_root / "inertia_decompiler" / "cli_helper_modeling.py",
            repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py",
        )
    )
    violations.extend(
        _check_cli_cod_stack_alias_rewrites_inert(
            repo_root / "inertia_decompiler" / "cli_c_ast_rewrites.py",
            repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py",
        )
    )
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_function_discovery.py")
    )
    violations.extend(_check_cod_source_rewrites_are_inert(root / "cod_source_rewrites.py"))
    violations.extend(_check_source_annotations_do_not_materialize_types(root / "annotations.py"))
    violations.extend(_check_runtime_architecture_guard_entrypoints(repo_root))
    violations.extend(_check_architecture_table_unique_keys(repo_root))
    violations.extend(_check_architecture_header_marker_contracts(repo_root))
    violations.extend(_check_docstring_marker_contracts(repo_root))
    violations.extend(_check_dynamic_attr_boundary_terms_match_changed_file_ratchet(repo_root))
    violations.extend(_check_semantic_layer_ownership_headers(root))
    violations.extend(_check_validation_ownership_headers(root))
    violations.extend(_check_recompilable_ownership_headers(root))
    violations.extend(_check_root_structuring_ownership_headers(root))
    violations.extend(_check_optional_evidence_ownership_headers(root))
    violations.extend(_check_recovery_reporting_ownership_headers(root))
    violations.extend(_check_frontend_runtime_ownership_headers(root))
    violations.extend(_check_recovery_metadata_ownership_headers(root))
    violations.extend(_check_helper_boundary_ownership_headers(root))
    violations.extend(_check_root_module_docstrings(root))
    violations.extend(_check_x86_16_module_layer_headers(root))
    violations.extend(_check_pipeline_lane_contracts_use_dot_access(root))
    violations.extend(_check_postprocess_stage_runs_pipeline_contract_gate(root))
    violations.extend(_check_identical_assignment_arm_structuring_ownership(root))
    violations.extend(_check_terminal_call_result_structuring_ownership(root))
    violations.extend(_check_shared_body_wide_condition_ownership(root))
    violations.extend(_check_condition_lane_counters_use_dot_access(root))
    violations.extend(_check_condition_origin_tags_use_dot_access(root))
    violations.extend(_check_pipeline_invariants_alias_contracts_use_dot_access(root))
    violations.extend(_check_owned_contracts_use_dot_access(root))
    violations.extend(_check_lowering_not_cod_name_backed(root))
    violations.extend(_check_lowering_ownership_headers(root))
    violations.extend(_check_semantic_layers_not_cod_raw_text_backed(root))
    violations.extend(_check_postprocess_calls_source_evidence_is_inert(root / "decompiler_postprocess_calls.py"))
    violations.extend(_check_postprocess_return_shape_not_source_backed(root / "decompiler_postprocess.py"))
    violations.extend(_check_postprocess_not_cod_stack_alias_backed(root))
    violations.extend(_check_validation_not_source_or_sample_backed(root / "validation_semantics.py"))
    violations.extend(_check_tail_validation_not_source_decl_backed(root / "tail_validation.py"))
    violations.extend(_check_tail_validation_fingerprint_not_cod_backed(root / "tail_validation_fingerprint.py"))
    violations.extend(
        _check_recompilable_source_evidence_inert(
            root / "recompilable_source_evidence.py",
            root / "recompilable_cli_bridge.py",
        )
    )
    violations.extend(_check_project_awareness_docs(repo_root))
    violations.extend(
        _check_status_reporting_not_source_backed(repo_root / "scripts" / "sortdemo_decompiler_status.py")
    )
    violations.extend(
        _check_sortdemo_status_reporting_typed_state(repo_root / "scripts" / "sortdemo_decompiler_status.py")
    )
    violations.extend(
        _check_decompilation_quality_not_source_backed_named(
            repo_root / "inertia_decompiler" / "decompilation_quality.py"
        )
    )
    violations.extend(_check_promoted_typed_file_docstrings(repo_root))
    violations.extend(_check_promoted_typed_future_annotations(repo_root))
    violations.extend(_check_promoted_typed_public_assign_annotations(repo_root))
    violations.extend(_check_promoted_typed_public_def_docstrings(repo_root))
    violations.extend(_check_promoted_typed_public_function_annotations(repo_root))
    violations.extend(_check_decompiler_annotation_debt(repo_root))
    violations.extend(_check_promoted_typed_dataclass_fields(repo_root))
    violations.extend(_check_promoted_typed_enum_values(repo_root))
    violations.extend(_check_promoted_typed_literal_dunder_all(repo_root))
    violations.extend(_check_promoted_typed_files_avoid_dynamic_attr(repo_root))
    violations.extend(_check_inertia_decompiler_typed_promotion_coverage(repo_root))
    violations.extend(_check_x86_16_typed_promotion_coverage(repo_root))
    violations.extend(_check_gate_script_docstrings(repo_root))
    violations.extend(_check_cli_boundary_docstrings(repo_root))
    violations.extend(_check_inertia_decompiler_module_docstrings(repo_root))
    violations.extend(_check_script_module_docstrings(repo_root))
    violations.extend(_check_legacy_responsibility_debt_is_current(repo_root))
    violations.extend(
        _check_cli_decompilation_narrowed_fields_use_dot(repo_root / "inertia_decompiler" / "cli_decompilation.py")
    )
    violations.extend(
        _check_cli_c_ast_rewrites_narrowed_fields_use_dot(repo_root / "inertia_decompiler" / "cli_c_ast_rewrites.py")
    )
    violations.extend(
        _check_cli_dead_local_narrowed_fields_use_dot(repo_root / "inertia_decompiler" / "cli_dead_local_prune.py")
    )
    violations.extend(
        _check_python_module_layer_headers(
            repo_root / "inertia_decompiler",
            rule="inertia-module-layer-header",
            expected_layer="Layer: CLI/fallback/reporting",
        )
    )
    violations.extend(
        _check_python_module_layer_headers(
            repo_root / "scripts",
            rule="script-module-layer-header",
            expected_layer="Layer: Tooling/gates",
        )
    )
    violations.extend(_check_root_contract_docstrings(repo_root))
    violations.extend(_check_root_contract_layer_headers(repo_root))
    violations.extend(_check_grouped_graph_ir_address_dot_access(root / "structuring_grouped_graph_builder.py"))
    violations.extend(_check_type_equivalence_typed_ir_dot_access(root / "type_equivalence_classes.py"))
    violations.extend(_check_type_array_matching_typed_ir_dot_access(root / "type_array_matching.py"))
    violations.extend(_check_type_array_matching_induction_summary_dot_access(root / "type_array_matching.py"))
    violations.extend(_check_type_structure_merging_typed_ir_dot_access(root / "type_structure_merging.py"))
    violations.extend(_check_structuring_alias_failure_dot_access(root / "decompiler_structuring_stage.py"))
    violations.extend(_check_structuring_stage_narrowed_fields_use_dot(root / "decompiler_structuring_stage.py"))
    violations.extend(_check_loop_body_repair_narrowed_fields_use_dot(root / "structuring" / "loop_body_repair.py"))
    violations.extend(_check_fact_transfer_alias_fact_dot_access(root / "lowering" / "fact_transfer.py"))
    violations.extend(_check_semantic_evidence_context_ownership(root / "semantics" / "evidence_cache.py"))
    stack_lowering_from_facts = root / "lowering" / "stack_lowering_from_facts.py"
    violations.extend(_check_stack_lowering_binding_dot_access(stack_lowering_from_facts))
    violations.extend(_check_stack_lowering_result_typed_status(stack_lowering_from_facts))
    violations.extend(
        _check_stack_prototype_narrowed_fields_use_dot(root / "lowering" / "stack_prototype_materialization.py")
    )
    violations.extend(_check_stack_c_ast_narrowed_fields_use_dot(root / "lowering" / "stack_c_ast_matching.py"))
    violations.extend(_check_calling_convention_owned_seed_fields_use_dot(root / "calling_convention_compat.py"))
    violations.extend(_check_c_ast_utils_narrowed_fields_use_dot(root / "c_ast_utils.py"))
    violations.extend(_check_lifter_operand_size_uses_dot(root / "lift_86_16.py"))
    violations.extend(_check_structuring_codegen_narrowed_fields_use_dot(root / "structuring_codegen.py"))
    violations.extend(_check_postprocess_simplify_narrowed_fields_use_dot(root / "decompiler_postprocess_simplify.py"))
    violations.extend(_check_postprocess_calls_narrowed_fields_use_dot(root / "decompiler_postprocess_calls.py"))
    violations.extend(_check_postprocess_jcc_narrowed_fields_use_dot(root / "decompiler_postprocess_jcc.py"))
    violations.extend(_check_postprocess_stage_narrowed_fields_use_dot(root / "decompiler_postprocess_stage.py"))
    violations.extend(_check_return_compat_narrowed_fields_use_dot(root / "decompiler_return_compat.py"))
    violations.extend(_check_stack_lowering_impl_narrowed_fields_use_dot(root / "lowering" / "stack_lowering_impl.py"))
    violations.extend(_check_stack_lowering_impl_binding_dot_access(root / "lowering" / "stack_lowering_impl.py"))
    violations.extend(_check_stack_lowering_impl_alias_fact_dot_access(root / "lowering" / "stack_lowering_impl.py"))
    violations.extend(_check_stack_lowering_impl_binding_dot_access(root / "lowering" / "real_mode_linear.py"))
    violations.extend(_check_real_mode_alias_fact_dot_access(root / "lowering" / "real_mode_linear.py"))
    violations.extend(_check_real_mode_stack_probe_fact_dot_access(root / "lowering" / "real_mode_linear.py"))
    violations.extend(_check_real_mode_linear_narrowed_fields_use_dot(root / "lowering" / "real_mode_linear.py"))
    violations.extend(_check_stack_probe_return_summary_dot_access(root / "lowering" / "stack_probe_return_facts.py"))
    violations.extend(_check_tail_validation_binding_dot_access(root / "tail_validation_fingerprint.py"))
    violations.extend(_check_tail_validation_callsite_summary_dot_access(root / "tail_validation.py"))
    violations.extend(_check_call_recovery_summary_dot_access(root / "decompiler_postprocess_calls.py"))
    violations.extend(_check_tail_validation_narrowed_fields_use_dot(root / "tail_validation.py"))
    violations.extend(_check_ss_bp_substitution_binding_dot_access(root / "lowering" / "ss_bp_substitution.py"))
    violations.extend(_check_callsite_materialization_stats_dot_access(root / "callsite_stack_metadata.py"))
    violations.extend(_check_callsite_stack_summary_dot_access(root / "callsite_stack_metadata.py"))
    violations.extend(_check_postprocess_calls_summary_dot_access(root / "decompiler_postprocess_calls.py"))
    violations.extend(_check_postprocess_narrowed_fields_use_dot(root / "decompiler_postprocess.py"))
    violations.extend(_check_postprocess_stack_identity_dot_access(root / "decompiler_postprocess.py"))
    violations.extend(_check_structuring_diagnostics_stats_dot_access(root / "structuring_diagnostics.py"))
    for optimization_name in ("copy_prop.py", "dead_setup.py", "trivial_copy.py"):
        violations.extend(
            _check_postprocess_optimization_narrowed_fields_use_dot(
                root / "postprocess" / "optimization" / optimization_name
            )
        )
    violations.extend(_check_return_chains_narrowed_fields_use_dot(root / "structuring" / "return_chains.py"))
    violations.extend(_check_return_chain_codegen_metadata_dot_access(root / "structuring" / "return_chains.py"))
    violations.extend(
        _check_segmented_global_materializer_codegen_dot_access(root / "lowering" / "segmented_global_loads.py")
    )
    violations.extend(
        _check_segmented_global_loads_narrowed_fields_use_dot(root / "lowering" / "segmented_global_loads.py")
    )
    violations.extend(_check_segmented_global_codegen_boundary_helpers(root / "lowering" / "segmented_global_loads.py"))
    violations.extend(_check_makefile_gate_targets(repo_root))
    violations.extend(_check_test_pipeline_fast_targets(repo_root))
    violations.extend(_check_ownership_manifest_contract(repo_root))
    return tuple(violations)


def check_decompiler_startup_architecture(
    root: Path = X86_16_ROOT,
    cli_path: Path = CLI_DECOMPILATION,
    repo_root: Path = REPO_ROOT,
    *,
    prechecked_import_violations: tuple[ArchitectureViolation, ...] | None = None,
) -> tuple[ArchitectureViolation, ...]:
    """Return runtime startup violations that must stop decompiler execution.

    This deliberately excludes slower docs/types/Makefile ratchets. Those are
    mandatory in `make architecture-check` and the focused linters run by
    `make check-files`; this path fails fast on wrong-layer imports and semantic
    recovery leaks before decompilation starts.
    """

    violations = list(prechecked_import_violations or ())
    if prechecked_import_violations is None:
        violations.extend(_check_postprocess_imports(root))
    violations.extend(_check_postprocess_source_text_recovery(root))
    if prechecked_import_violations is None:
        violations.extend(_check_semantic_layers_do_not_import_postprocess(root))
    violations.extend(_check_identical_assignment_arm_structuring_ownership(root))
    violations.extend(_check_terminal_call_result_structuring_ownership(root))
    violations.extend(_check_shared_body_wide_condition_ownership(root))
    violations.extend(_check_compatibility_shims(root))
    violations.extend(_check_architecture_table_unique_keys(repo_root))
    violations.extend(_check_architecture_header_marker_contracts(repo_root))
    if prechecked_import_violations is None:
        violations.extend(_check_cli_imports(cli_path))
    violations.extend(_check_cli_c_text_cleanup(repo_root / "inertia_decompiler" / "c_text_cleanup.py"))
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_fallback_decompilation.py")
    )
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_decompilation.py")
    )
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py")
    )
    violations.extend(
        _check_cli_source_header_recovery_inactive(repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py")
    )
    violations.extend(_check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_core.py"))
    violations.extend(_check_cli_acceptance_not_source_evidence_gated(repo_root / "inertia_decompiler" / "cli_core.py"))
    violations.extend(_check_cli_not_source_backed_quality_gated(repo_root / "inertia_decompiler" / "cli_core.py"))
    violations.extend(
        _check_cli_not_source_backed_quality_gated(repo_root / "inertia_decompiler" / "cli_decompilation.py")
    )
    violations.extend(
        _check_forced_corpus_templates_inert(
            repo_root / "inertia_decompiler" / "cli_decompilation.py",
            repo_root / "decompile.py",
        )
    )
    violations.extend(
        _check_cli_ast_cod_callee_names_inert(
            repo_root / "inertia_decompiler" / "cli_c_ast_rewrites.py",
            repo_root / "inertia_decompiler" / "cli_decompilation.py",
        )
    )
    violations.extend(
        _check_cli_cod_call_names_not_semantic(
            repo_root / "inertia_decompiler" / "cli_decompilation.py",
            repo_root / "inertia_decompiler" / "cli_helper_modeling.py",
            repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py",
        )
    )
    violations.extend(
        _check_cli_cod_stack_alias_rewrites_inert(
            repo_root / "inertia_decompiler" / "cli_c_ast_rewrites.py",
            repo_root / "inertia_decompiler" / "cli_c_text_postprocess.py",
        )
    )
    violations.extend(
        _check_cli_fallback_source_body_recovery(repo_root / "inertia_decompiler" / "cli_function_discovery.py")
    )
    violations.extend(_check_cod_source_rewrites_are_inert(root / "cod_source_rewrites.py"))
    violations.extend(_check_source_annotations_do_not_materialize_types(root / "annotations.py"))
    violations.extend(_check_lowering_not_cod_name_backed(root))
    violations.extend(_check_semantic_layers_not_cod_raw_text_backed(root))
    violations.extend(_check_postprocess_calls_source_evidence_is_inert(root / "decompiler_postprocess_calls.py"))
    violations.extend(_check_postprocess_return_shape_not_source_backed(root / "decompiler_postprocess.py"))
    violations.extend(_check_postprocess_not_cod_stack_alias_backed(root))
    violations.extend(_check_validation_not_source_or_sample_backed(root / "validation_semantics.py"))
    violations.extend(_check_tail_validation_not_source_decl_backed(root / "tail_validation.py"))
    violations.extend(_check_tail_validation_fingerprint_not_cod_backed(root / "tail_validation_fingerprint.py"))
    violations.extend(
        _check_recompilable_source_evidence_inert(
            root / "recompilable_source_evidence.py",
            root / "recompilable_cli_bridge.py",
        )
    )
    violations.extend(
        _check_decompilation_quality_not_source_backed_named(
            repo_root / "inertia_decompiler" / "decompilation_quality.py"
        )
    )
    return tuple(violations)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check static decompiler architecture guardrails.")
    parser.add_argument("--x86-16-root", type=Path, default=X86_16_ROOT)
    parser.add_argument("--cli", type=Path, default=CLI_DECOMPILATION)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--startup-only",
        action="store_true",
        help="run the startup-critical architecture subset for focused development",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the architecture checker command."""

    args = _parse_args(argv)
    if args.startup_only:
        uses_default_tree = (
            args.x86_16_root.resolve() == X86_16_ROOT.resolve()
            and args.cli.resolve() == CLI_DECOMPILATION.resolve()
            and args.repo_root.resolve() == REPO_ROOT.resolve()
        )
        if uses_default_tree and __package__:
            from inertia_decompiler.architecture_runtime_guard import (
                DecompilerArchitectureGuardError,
                cached_decompiler_startup_architecture_violations,
            )

            try:
                violations = cached_decompiler_startup_architecture_violations()
            except DecompilerArchitectureGuardError as exc:
                print(str(exc), file=sys.stderr)
                return 1
        else:
            violations = check_decompiler_startup_architecture(
                args.x86_16_root,
                args.cli,
                args.repo_root,
            )
    else:
        violations = check_decompiler_architecture(args.x86_16_root, args.cli, args.repo_root)
    if violations:
        for violation in violations:
            print(violation.format(), file=sys.stderr)
        return 1
    scope = "startup" if args.startup_only else "full"
    print(f"decompiler {scope} architecture checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
