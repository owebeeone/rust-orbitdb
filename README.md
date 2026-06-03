# rust-orbitdb

A Rust-first, OrbitDB-compatible oplog, sync, simulator, document, and binding
workspace.

Semantic crates are I/O-free and sans-io: pure data structures, state machines,
traits, fixtures, and deterministic simulators. Real I/O lives only in explicit
adapter/host layers (feature-gated libp2p adapter, Node.js runner, Python
binding boundary, downstream hosts). libp2p is adapter-only and never a
dependency of the core, store, sync, substrate, document, simulator, fixtures,
or testkit crates.

This repository is built under plan **GLP-0003** (roll-build checkpoints tagged
`glp-0003/<phase>-<checkpoint>`). The authoritative plan lives in the parent
`glial-dev` repo at `plan-docs/plans/GLP-0003-rust-orbitdb/`.

Status: bootstrap (`P00b`). Workspace skeleton, CI, and crate layout land in
`P00c` onward.
