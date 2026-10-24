# Rebuilding native hosts

The [normal source workflow](build.md) rebuilds Kelft sources with the native
seed. The Rust coordinator and platform boundaries can also be rebuilt from
their corresponding sources. This advanced workflow requires development tools
and does not confer release qualification on its output.

The `release-metadata/1` coordinator feature separates installed version
metadata from host executable identity. The public `refresh-seeds` workflow
updates changed coordinators and policies, checks metadata and staging, and
opens a PR for review. It retains existing compiler qualification and unchanged
boundaries and platform inputs. Compatible hosts can be reused for later
version-only changes. See the [release workflow](release-workflow.md).

## Sources and tools

Each seed identifies its corresponding compiler and host source archive.
Use that archive for the recorded binary, or the current `host/` sources when
developing a changed host. Retain its licenses, Cargo.lock and notices.
Dependency source archives and their authenticated inventories accompany the
bootstrap inputs. Rust 1.99.0 sources are identified by commit
`b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`; the LLVM revision used by the native
linker is `1b9c0d5ff9bbe7634aead059efe6b11a7eeba145`.
Their exact public source locations are recorded in the
[tool source inventory](../bootstrap/sources/dependencies/tool-sources.json).

Prepare Node 24, native Rust 1.99.0 and the locked Cargo dependency cache before
building. Linux host builds also need a native C compiler, static C runtime
development files and bubblewrap. Windows host builds need Visual Studio Build
Tools and the Windows SDK under their applicable terms. macOS host builds need
Xcode command-line tools and an installed Apple SDK. These SDKs are build
prerequisites; Microsoft and Apple SDK files are not included in the seeds.
Use a native filesystem for host build outputs so their recorded permissions
are meaningful. The full host builder authenticates and materializes split seed
inputs automatically; ordinary compiler rebuilding uses the native launcher.

The full host build entrypoint and seed-authentication arguments are described
in [building](build.md). Run preparation while networking is available; the
compiler and Cargo builds use the prepared inputs offline. A native Linux Rust
SDK can be supplied through `KELFT_NATIVE_RUST_SDK`: its JSON records the absolute
SDK root, Rust compiler and Cargo SHA-256 values, and the library inventory.
The builder verifies those inputs before and after building. The pinned public
Rust container is the other Linux host-build route.

## Modifying or relinking Linux runtime libraries

GNU source descriptors identify the exact upstream archives and Ubuntu patches.
Extract a source package with `dpkg-source -x PACKAGE.dsc`; use its included
build instructions to build a modified library in a separate development SDK.
Keep that SDK outside the compiler source project. GNU licenses, vendor notices
and the GCC runtime exception remain applicable to their respective components.

The C boundary and Rust coordinator are statically linked. Relinking them
requires rebuilding both hosts with the modified C runtime. Their complete
first-party sources and build scripts are included; no published binary hash
prevents rebuilding your own hosts. In a working copy:

1. Configure a native C compiler wrapper to use your SDK, including its headers,
   startup objects and libraries. GCC's `--sysroot`, `-B` and library-search
   options must select the intended SDK rather than the system's default libc.
2. Change the explicit C compiler path in
   `host/scripts/stage-native-installed.mjs` to that wrapper. The builder records
   the selected compiler, tools, startup objects and static runtime identities.
3. Set Cargo's native target linker to the same wrapper using
   `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` or
   `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER`, as appropriate. The explicit
   native Rust SDK build route preserves that setting.
4. Run the full host build. It builds the boundary first and embeds its new
   authenticated identity in the coordinator. Retain the new source and SDK
   observations, then run the normal compiler and boundary tests.

This is also the source route for debugging modifications to LGPL-covered
runtime code. The [LGPL](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)
and retained vendor notices describe the applicable rights and obligations.
Use the resulting installation as a local build; its changed identities do not
inherit a published package's qualification or signatures.

Controlled source examples and relink observations accompany the source tree
under `release-evidence/`. The Linux proofs replace `strlen.o` in a copy of the
exact vendor `libc.a` with an object built from the supplied LGPL source example,
then select that archive using `-B` and `-L` in the compiler wrapper. A forced
reference to the example's marker retains the modified object in both hosts.
The wrapper selects the modified SDK for static host links; Cargo's dynamically
linked build scripts use their ordinary toolchain. Restore recorded runtime
modes before generating the boundary's file inventory and retain a complete
`runtime-modes.json` in the rebuilt installation. The original seeds and vendor
archives remain unchanged by this process.
