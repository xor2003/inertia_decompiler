1. Split `/home/xor/vextest/decompile.py` into SRP modules under a real package boundary, starting with:
   `cache.py`, `sidecar_metadata.py`, `project_loading.py`, `function_recovery.py`, `fallback_rendering.py`, and `postprocess_text.py`.
   Done when `decompile.py` becomes an orchestration entrypoint instead of a kitchen-sink implementation file.
2. Cap repo-owned Python modules at roughly 300-500 lines unless a file is data-driven or generated.
   Done when every hand-maintained Python file in the root repo is either within that size band or has an explicit generated/vendor exception.
3. Remove ladder effect from control flow in the decompiler pipeline.
   Replace long `if`/`elif` recovery and rewrite ladders with dispatch tables, stage registries, or small strategy helpers.
   Done when stage selection and fallback selection read as ordered policy tables instead of long imperative ladders.
4. Extract sidecar evidence handling from `/home/xor/vextest/decompile.py`.
   Move `.cod`, `.lst`, `.map`, CodeView, FLAIR, and peer-binary metadata loading/merging into a dedicated module with deterministic source precedence.
   Done when sidecar parsing and reconciliation no longer live beside CFG/decompilation code.
5. Extract executable loading and format detection from `/home/xor/vextest/decompile.py`.
   Keep MZ/NE/packed-EXE routing in one place with small backend-specific helpers.
   Done when binary-format selection and angr project creation live outside the CLI and recovery code.
6. Extract function discovery and seed ranking from `/home/xor/vextest/decompile.py`.
   Keep entry fallback, quick seed scans, peer-catalog seeding, and candidate ranking in one module with focused tests.
   Done when recovery heuristics are testable without importing the whole CLI.
7. Extract late fallback rendering from `/home/xor/vextest/decompile.py`.
   Keep lift-break probing, non-optimized fallback C, asm-range formatting, and timeout/error reporting together.
   Done when failure reporting is isolated from normal successful decompilation flow.
8. Extract text-level cleanup passes from `/home/xor/vextest/decompile.py`.
   Group pure string rewrites into a dedicated postprocess module with a stable ordered pass list.
   Done when text cleanup no longer shares a file with CFG recovery, loading, and CLI policy.
9. Declutter the repo root.
   Move ad-hoc outputs and scratch artifacts under dedicated directories such as `/home/xor/vextest/reports`, `/home/xor/vextest/scratch`, or cache directories, and stop generating new noise in root.
   Done when routine runs no longer leave `.dec`, cache, IDE, or temp artifacts in the top-level tree.
10. Add root-level ignore rules for disposable state.
   At minimum cover `__pycache__`, `.inertia_*_cache`, IDE folders, and other generated local state that should never be reviewed as product changes.
   Done when `git status` highlights code and corpus work instead of local tool residue.
11. Commit refactor work intentionally in both git repos.
   Use small commits with messages that match the extracted responsibility boundaries instead of one monolithic “cleanup” snapshot.
   Done when root repo and nested `/home/xor/vextest/angr_platforms` each have coherent refactor commits.
