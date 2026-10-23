# Kelft compiler

Kelft compiles typed programs to native code. Its self-hosted compiler is written
in Kelft and includes source checking, deterministic object emission, and
capability-controlled execution. Core describes executable programs; Intent
describes outcomes, constraints, and verification contracts.

The compiler version is **0.1.0-alpha.1**, an experimental alpha. Compiler, Core,
Intent, and specification versions identify separate contracts. See the
[changelog](CHANGELOG.md) and [release information](RELEASES.md).

## Install

Published packages are listed in [GitHub Releases](https://github.com/kelftlang/kelft/releases).
Choose your OS and architecture, authenticate its provenance, verify the
checksums, and extract it into a user-owned directory. Package definitions cover
Linux, Windows, and macOS on x86-64 and ARM64; availability and qualified OS
versions depend on the release. See [installation](docs/install.md).

Installed native compilation needs no Node or Rust/C development tools. The
distribution includes Rust/C host components and prepared native linker/runtime
inputs. [Architecture](docs/architecture.md) describes the platform dependencies.

## Compile and run

From a project directory, use the extracted compiler's `bin/kelft` executable
(`bin/kelft.exe` on Windows). For the included example:

```text
kelft version
kelft check examples/hello.kelft --json
kelft build examples/hello.kelft -o hello
kelft run examples/hello.kelft --project-root .
```

Use the executable's full path, or add its `bin` directory to your PATH. On
Windows choose `hello.exe` as the build output. The output directory must exist.
Building produces an executable; `kelft run` compiles and executes through the
platform boundary. See the [installation guide](docs/install.md) for runtime
requirements and command exit codes.

## Build from source

Run `sh bootstrap.sh rebuild` from a clone, or `bootstrap.cmd rebuild` on
Windows. The Git-tracked native seed rebuilds the current Kelft compiler sources
offline into `build/local`; no Node or Rust/C development tools are needed.
Use `build/local/bin/kelft` to check, build, run, and test your changes.
See the [build guide](docs/build.md) and [platform readiness](bootstrap/README.md).
The seed index identifies verified workflows and their operating-system prerequisites.

## Documentation and contributions

- [Public specification](https://www.kelft.com) and [bundled specifications](spec/README.md).
- [Contribution guide](CONTRIBUTING.md): issues and pull requests are welcome.
- [Security policy](SECURITY.md).

Software is MIT OR Apache-2.0; documentation prose is CC-BY-4.0; designated
examples are MIT-0. Dependencies retain their own terms. See [licensing](docs/licensing.md).
