# Structuring

The existing condition, loop, branch and return structuring modules live here.
Their algorithms and interfaces are unchanged. Private tests move into
`tests/structuring/`; shared decompiler tests remain with their integration
cohort. Historical `X86_16/structuring/` imports alias these owners.

Root stage orchestration still lives in the historical platform package until
its file move. Semantic recovery stays in its existing layer.
