# Changelog

## Unreleased

- Native bootstrap launchers and a rebuild command producing a usable local compiler.
- Editable source builds without Node, Rust/C development tools, or manual hash arguments.

Initial compiler alpha, version **0.1.0-alpha.1**:

- Self-hosted Kelft compiler with source checking, diagnostics, and native object emission.
- Core language support for typed values, modules, aggregates, generics, and ownership-aware mutation.
- Intent declarations, constraints, and verification contracts.
- Native build and brokered execution commands with explicit capability and resource limits.
- Rust/C platform hosts, pinned build inputs, authenticated bootstrap seeds, and offline source-build tooling.
- Native package definitions for Linux, Windows, and macOS on x86-64 and ARM64.

Package definitions do not establish platform qualification. Published release
notes will identify available assets, supported baselines, and signing status.
