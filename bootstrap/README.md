# Bootstrap packages

These Git-tracked files provide native Kelft seeds. The bootstrap launcher
selects the matching host; no registry, Node, or Rust compiler
is involved in developer rebuilding. Linkers and runtime inputs remain platform
dependencies, even when supplied with a seed.

Run from the repository root:

```text
sh bootstrap.sh rebuild
```

On Windows use `bootstrap.cmd rebuild`. The result is `build/local/bin/kelft`
(`kelft.exe` on Windows). Use that executable to check, build, run, and test Kelft
projects. See [building](../docs/build.md).

Each seed inventory records file hashes, original artifact identities,
corresponding sources, and preparation status. A seed is an initial binary trust
input. Checksums detect changed bytes; they do not remove that trust assumption.
Large payloads can be stored as bounded parts and reconstructed automatically
outside the checkout. Git LFS is not required.

Only a host with a `READY` marker supports the new native rebuild workflow.
The [seed index](seeds.json) lists actual preparation status and outstanding
platform requirements. Historical compiler artifacts do not qualify a changed
host or a newly rebuilt compiler. SDK redistribution review and exact-platform
release qualification remain prerequisites for publication.

## Platform inputs

| Platform | Prepared inputs and operating-system requirements |
| --- | --- |
| Windows | LLVM LLD and first-party Windows import definitions supply linking. Microsoft SDK libraries and private Visual C++ runtime DLLs are excluded. The operating system supplies the named System32 modules; their measured identities are reported. |
| Linux | GNU `ld.bfd`, its supporting libraries and glibc supply linking. Exact vendor notices and corresponding source archives accompany these inputs. The recorded Ubuntu 24.04 boundary inputs, bubblewrap and a policy permitting its user namespace are operating-system prerequisites. Changed boundary inputs can fail closed. |
| macOS | LLVM LLD, its required LLVM library and first-party libSystem import declarations supply linking. Ordinary rebuilding requires no Apple SDK, Xcode or signing tools. Built images carry ad-hoc signatures; Apple notarization is a separate release step. |

An inventory or an earlier successful test does not approve redistribution.
Unavailable platform inputs must be prepared explicitly under their applicable
terms; ordinary rebuilding does not discover an unrecorded system linker.
