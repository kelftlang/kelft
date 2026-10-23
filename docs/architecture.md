# Compiler and host architecture

The frontend, analysis, lowering, native object emission, compiler-facing link
protocols, and shared toolchain decisions are implemented in Kelft. Native object
emission writes object bytes directly, without invoking a C compiler.

The installed `bin/kelft` entry is a Rust coordinator. Windows and macOS use
Rust platform boundaries. Linux uses a C supervisor and measured namespace tools,
including Bubblewrap. These components authenticate inputs, broker filesystem
and process access, enforce resource limits, isolate compiler/linker/program
roles, and clean up descendants. Kelft's process and filesystem libraries use
these brokers.

Native linking uses prepared LLVM LLD on Windows and macOS, and GNU ld on Linux.
Windows import definitions and macOS libSystem declarations are first-party
inputs; Microsoft and Apple SDK files are excluded. Packages carry required
permitted runtime inputs and document operating-system prerequisites. Optional JavaScript/Wasm
execution engines, network services, and cross-target packs are separate from
the default native package. Capability output describes the actual installation
and does not establish platform certification.

The compiler preserves bounded traversal, consuming writers, early temporary
release, and explicit heap, stack, and deadline limits. Source builds consume
the checked-in Kelft runtime descriptions directly. Runtime ABIs and platform
boundaries remain distinct from portable language semantics; see the
[bundled specifications](../spec/README.md).
