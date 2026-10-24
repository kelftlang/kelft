# Compiler licensing and distribution

Copyright (c) 2026 Kelft contributors. Preserve existing individual notices and
third-party terms. The [licensing inventory](../licensing.json) identifies the
public tree's classifications and dependency inventories.

First-party compiler, standard library, native host and tooling software uses
**MIT OR Apache-2.0**, at the recipient's option. See [MIT](../LICENSE-MIT) and
[Apache 2.0](../LICENSE-APACHE). First-party documentation prose uses
[CC-BY-4.0](../LICENSES/CC-BY-4.0.txt); designated copyable examples
use [MIT-0](../LICENSES/MIT-0.txt). See the root [LICENSE](../LICENSE).

Application authors choose their own application license. Substantial Kelft
runtime or template code incorporated into an output retains its applicable
license and notice obligations. No LLVM exception is added. New contributions
use the applicable license and [DCO](../DCO) sign-off, with no assignment or CLA.
The name and approved Brandmark follow [TRADEMARKS.md](../TRADEMARKS.md) and
applicable asset provenance.

Inspect [Cargo.lock](../host/driver/Cargo.lock) and the
[native tool pins](../host/native/artifact-tools.lock.json) for exact native
build inputs. Third-party libraries, Rust runtime components, platform linkers,
SDKs and system libraries retain their own terms. Collected notices and hashes
do not establish permission to redistribute an SDK or replace required source
availability or other dependency obligations.

Binary distributions must include notices and satisfy the terms of the exact
linked and bundled dependencies. Where redistribution is unavailable, the
platform inputs must be supplied explicitly under their own terms. Package
reports record unresolved redistribution requirements; a successful local
package build alone does not authorize redistribution. Default native packages
exclude optional engines and services. Seed packages retain their own sources,
provenance, and dependency obligations.

Bootstrap packages have their own inventories and corresponding source archives.
First-party source grants do not license bundled SDKs, system libraries, or other
third-party inputs. Preserve collected notices and satisfy corresponding-source
requirements for the exact payload. The seed index records outstanding
redistribution and platform-qualification requirements.

Windows and macOS linker inputs use LLVM's own license and exception; that
exception does not change the license of Kelft's first-party software. GNU
linker/runtime inputs retain their GPL, LGPL and applicable exception terms.
The bootstrap source directories include corresponding GNU and locked Cargo
sources; each seed's notices identify its included dependencies. Rust runtime
components retain their upstream notices. Microsoft and Apple SDK files are
excluded from the native seed packages.
