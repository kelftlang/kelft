# Building Kelft

The normal developer workflow uses the native seed checked into this repository.
It requires no Node, Cargo, Rust/C compiler, private credentials, or manual hash
arguments. The seed supplies the prepared native linker/runtime inputs where
redistribution permits. Consult the [seed index](../bootstrap/seeds.json) for
actual platform readiness and remaining platform requirements.

The Windows seed supplies LLVM and its native import libraries. Its boundary
uses the named Windows System32 modules and reports their actual identities.
Linux requires the recorded Ubuntu 24.04 platform inputs, bubblewrap and a
system policy that permits its user namespace. A changed Linux boundary input
can fail closed. macOS supplies its prepared LLVM linker and first-party
libSystem import declarations; ordinary rebuilding requires no Apple SDK.
The seed index identifies verified platform configurations.

## Bootstrap and rebuild

From the repository root, run:

```text
sh bootstrap.sh rebuild
```

On Windows use `bootstrap.cmd rebuild`. The launcher selects your native
platform. You can also invoke a prepared seed's bin/kelft directly.

The command defaults to the current source directory and build/local beneath it.
Use `rebuild --source DIRECTORY --out DIRECTORY` to choose another source tree
or output. Relative output paths resolve beneath the selected source directory.
Builds use the current selfhost/ and stdlib/ files, including local edits and new
modules. Compilation is offline; no tools are discovered through PATH.

```text
build/local/bin/kelft check examples/hello.kelft
build/local/bin/kelft run examples/hello.kelft --project-root .
build/local/bin/kelft test --project-root .
build/local/bin/kelft test --corpus --project-root .
```

Use kelft.exe on Windows. The rebuilt directory contains its own compiler,
rebuilt Kelft test and rebuild policies, coordinator, boundary, and native
runtime inputs. Test discovery therefore uses the edited compiler's parser.
Source edits do not require
publication inventory updates. An existing local rebuild can be replaced safely;
an unrelated output directory is preserved. Failed rebuilds leave the previous
installation usable. Each successful build writes rebuild.json with its actual
source inventory, compiler/object identities, and sizes. Local builds remain
unqualified and are identified as local rebuilds by version and doctor.

The host loads the compiler from its installation without a fixed compiler hash
rejecting changes. It checks the native image and protocol, snapshots inputs for
execution, and retains capability restrictions, resource limits, and descendant
cleanup. Runtime files are staged outside the project automatically, so tests
can run even when the seed or output installation is inside the checkout.

## Seed trust and verification

The rebuilt installation records its version in its own `release.json`. A valid
source `release.json` takes precedence when rebuilding; otherwise the existing
installation identity is inherited. `kelft version` and `kelft doctor --json`
read installation metadata, never a file in the current project. Metadata must
be a regular file of at most 64 KiB with supported language versions and a
canonical compiler version. Missing installation metadata permits the legacy
embedded identity; malformed metadata is an error. Ordinary rebuilds remain
unqualified local builds regardless of their version.

A seed is an initial binary trust input. Its inventories and corresponding
sources permit inspection; they do not eliminate that assumption. Git-tracked
payloads and any split parts are identified in the bootstrap inventories. See
[bootstrap packages](../bootstrap/README.md) and [release verification](../RELEASES.md).

Developer source changes are expected. Maintainers can explicitly verify an
unchanged distribution with `node scripts/check.mjs --verify-inventory`.
That release check is separate from compiling and testing edited source.

## Rebuilding host components

Rebuilding the Rust/C hosts themselves is an advanced maintainer operation.
It needs Node 24, Rust 1.99.0, prepared locked Cargo dependencies, and the native
platform SDK and build tools. Preparation may fetch pinned dependencies;
compilation and packaging use offline commands.

The scripts under scripts/ provide seed verification, dependency preparation,
full host rebuilding, smoke/language checks, and packaging. The full build
entrypoint is `node scripts/build.mjs --seed SEED_DIRECTORY --manifest SEED_DIRECTORY/seed.json --sha256 REVIEWED_SHA256 --sources SEED_SOURCE_ARCHIVE --out build/full`.
An installed build compiles the testing and rebuild policies before rebuilding
the host components. macOS additionally requires its explicit toolchain
configuration via --toolchain. Linux requires its documented namespace tools and
pinned Rust SDK; Windows requires the recorded native linker/SDK and compatible
system libraries. These maintainer prerequisites are not part of ordinary
compiler-core rebuilding.

See [rebuilding native hosts](host-build.md) for corresponding sources and
modifying or relinking Linux runtime libraries.
