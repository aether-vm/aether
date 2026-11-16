# Aether Thin SDKs (`Python` & `TypeScript`)

Thin gRPC clients generated directly from `../../proto/aether/v1/`.

- **`python/`**: Primary SDK for RL training loops, MCTS sampling, and SWE-bench evaluation pipelines.
- **`typescript/`**: Primary SDK for Node.js CI orchestration and `aether-mcp`.

> **Design Rule**: Keep SDKs strictly thin over gRPC (no `napi-rs` native binary matrix prior to `v1.0`) and lockstep-versioned with `agentd`.
