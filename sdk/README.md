# Forkloom Thin SDKs (`Python` & `TypeScript`)

Thin gRPC clients generated directly from `../proto/forkloom/v1/runtime.proto`.

- **`python/` (`forkloom-vm`, `0.1.1a0`)**: Primary SDK for RL training loops, MCTS sampling, and SWE-bench evaluation pipelines.
- **`typescript/` (`@forkloom-vm/sdk`, `0.1.1-alpha.0`)**: Primary SDK for Node.js CI orchestration and `forkloom-mcp`.

> **Design Rules**:
> - Strictly **thin over gRPC** (no `napi-rs` or `PyO3` native binary matrix prior to `v1.0`).
> - Default transport is **Unix Domain Socket** (`unix:///run/forkloom/agentd.sock` or `$FORKLOOM_SOCKET`), matching `agentd`'s `0600` UDS-only security boundary.
> - Mandatory `SystemService.NegotiateVersion` handshake verifying `api_major == 1` before issuing stateful RPCs.
> - Structured gRPC error metadata (`x-forkloom-error-bin` / `x-forkloom-error-code`) decoded into typed exceptions (`WorldLostError`, `OutcomeUnknownError`, `FencedOutError`, `IdempotencyConflictError`, `DiskNotCleanError`, `UnsafePatchError`, etc.).


---

## Quickstarts

- Python: [`python/README.md`](python/README.md)
- TypeScript: [`typescript/README.md`](typescript/README.md)
