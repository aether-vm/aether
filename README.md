# Aether (`agentd`)

> **Stateful Sandbox & VM Forking Runtime on Linux + KVM**  
> Bring `checkpoint()`, `restore()`, and live memory+disk `fork(N)` to AI RL/eval environments, isolated full-stack CI testing, and autonomous agents—with host-side zero-trust credential mediation.

---

## Repository Layout (Core Monorepo)

To eliminate cross-repository contract drift prior to `v1.0`, the Rust runtime crates, guest init agent, guest kernel build configs, gRPC contracts, and thin Python/TypeScript SDKs evolve atomically in this repository:

```text
aether/
├── AGENTS.md                  # Engineering guardrails & 5-agent team charter
├── Cargo.toml                 # Rust workspace manifest (Linux kernel/runtime crates)
├── proto/aether/v1/           # Single source of truth for gRPC service contracts
├── crates/
│   ├── aos-types/             # Core primitives (WorldId, FrameId, Persisted/Ephemeral, Untrusted)
│   ├── aos-store/             # TreeStore (Btrfs subvols) & BlockStore (CoW disk images)
│   ├── aos-meta/              # redb single-commit-point state machine & epoch recovery
│   ├── aos-sandbox/           # NamespaceDriver (cold fork) & FirecrackerDriver (hot fork)
│   ├── aos-gw/                # Isolated zero-trust egress & credential injection gateway
│   ├── aos-guest/             # Static musl PID-1 guest agent (cgroup freeze, vsock reseed)
│   ├── agentd/                # Host control daemon (gRPC over Unix Domain Socket)
│   └── aos-cli/               # Command-line interface (`aos`)
├── guest-image/               # Guest Linux kernel (.config >= 5.18), Inspector initramfs & GPLv2 compliance scripts
├── sdk/
│   ├── python/                # Thin Python gRPC client (RL / SWE-bench primary SDK)
│   └── typescript/            # Thin TypeScript gRPC client
├── benchmarks/                # Phase 0 falsification & reproducible latency/density benchmarks
└── docs/
    ├── PRODUCT_POSITIONING.md # System layer positioning, 5 core capabilities & 6 industry use cases
    ├── ARCHITECTURE_V2.md     # Full v2.1 architecture, crash recovery & threat model spec
    └── PHASE0_FALSIFICATION.md# Phase 0 kernel falsification suite & pivot gates
```

## Documentation Quick Links

1. **[Product Positioning & Use Cases](./docs/PRODUCT_POSITIONING.md)** — What `Aether` is, how it differs from plain containers/sandboxes, and where it creates commercial value.
2. **[Architecture Specification v2.1](./docs/ARCHITECTURE_V2.md)** — Dual storage model, atomic `redb` commit invariants, Firecracker hot-fork reseed protocol, and `aos-gw` security design.
3. **[Phase 0 Falsification Suite](./docs/PHASE0_FALSIFICATION.md)** — Hardware/WSL2 constraints and the 8 mandatory kernel experiments before Phase 1 coding.

## Contribution & License

Licensed under **Apache-2.0**. All commits require `Signed-off-by` (Developer Certificate of Origin, DCO). Note that Linux kernel binaries built via `guest-image/` remain governed by **GPL-2.0-only** with accompanying source build scripts.
