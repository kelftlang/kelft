# Kelft native compiler

Extract the package into a directory you own. Invoke `bin/kelft` directly, or
`bin/kelft.exe` on Windows. Adding `bin` to PATH is optional.

```text
kelft version
kelft doctor --json
kelft check main.kelft
kelft build main.kelft -o hello
kelft run main.kelft --project-root .
```

On Windows, use `hello.exe` as the build output. Run commands from your project
directory. The output directory must exist. Use `kelft run` to execute through
the supported native boundary.

Compilation uses the included native linker/runtime inputs and requires no
Node, Cargo, Rust compiler or C development tools. Linux also requires the
recorded Ubuntu 24.04 boundary inputs, bubblewrap and a policy permitting its
user namespace. Consult the release notes for exact tested OS configurations.

This is an experimental alpha. Trusted Windows signing and Apple notarization
are deferred; macOS images use ad-hoc signatures. Verify downloaded artifact
provenance and checksums before use.

Compiler sources and contribution instructions are at
[the Kelft repository](https://github.com/kelftlang/kelft).
The [public specification](https://www.kelft.com) describes the language.
First-party and dependency license texts accompany the package under
`licenses/kelft` and `licenses/dependencies`. Dependencies retain their own terms.
