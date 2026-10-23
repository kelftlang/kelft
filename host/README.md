# Native host components

`driver/` contains the Rust coordinator and platform boundaries. `native/`
contains the C supervisor, runtime/tool pins, resource contracts, and supporting
native inputs. Their relative layout is part of the build contract. `scripts/`
contains native build and packaging helpers.

Use the [build entrypoint](../docs/build.md) to authenticate a Kelft seed,
prepare pinned dependencies, and rebuild the compiler and hosts offline. The
[architecture guide](../docs/architecture.md) describes installed responsibilities;
[licensing](../docs/licensing.md) covers dependency and redistribution obligations.
