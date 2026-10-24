# Installing a native alpha

Obtain available packages from [GitHub Releases](https://github.com/kelftlang/kelft/releases).
The instructions below describe the alpha package format; available targets and
qualified OS baselines are identified by each published release.

Select `kelft-v0.1.0-alpha.2-OS-ARCH`: `OS` is `linux`, `windows`, or `macos`;
`ARCH` is `x86_64` or `arm64`. Windows uses ZIP; other hosts use tar.gz.
Verify the package's GitHub artifact attestation against this repository and
its exact release-producing workflow, then compare its SHA-256 with the
attested checksum inventory. A checksum downloaded beside an untrusted binary
alone does not authenticate its origin.

Extract into a user-owned directory. No installer modifies PATH or elevates
privileges. Invoke `bin/kelft` directly (`bin/kelft.exe` on Windows).

```text
kelft version
kelft doctor --json
kelft capabilities --json
kelft check main.kelft --json
kelft build main.kelft -o hello
kelft run main.kelft --project-root .
```

The invocation directory is the default project root. `--project-root` restricts
source access; it does not rebase relative paths. The output directory must
already exist. An invalid public invocation exits 64; compilation failures exit
1. Native `run` returns the executed program's status through its existing
boundary contract. No network fetch or tool discovery occurs during a build.

Use `kelft run` for the supported execution path. Windows/macOS builds use the
brokered native runtime; directly launching a built image without its required
boundary is not a supported alpha execution path.

The baselines in `release.json` identify qualification targets. Consult the exact
release notes for tested hosts. Windows x64 preparation has been checked on
Windows 11 and Windows Server 2025 with their measured System32 inputs.
Linux requires bubblewrap, the recorded platform inputs and permission to use
unprivileged user namespaces; changed boundary inputs can fail closed.
macOS images use ad-hoc signatures. Trusted Apple notarization and trusted Windows executable
signing are deferred for the initial alpha; see [release information](../RELEASES.md).

Node and Rust/C development tools are unnecessary for installed
native compilation or compiler-core rebuilding. See the [build instructions](build.md)
for the native seed workflow and the separate advanced host build prerequisites.
Optional engines and services are not included.
