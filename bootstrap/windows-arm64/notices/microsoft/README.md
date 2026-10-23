# Microsoft runtime components

The Windows Rust host executables use static Microsoft C runtime linkage.
Microsoft components retain their own license terms. The seed packages exclude
Microsoft SDK import libraries, Microsoft build tools and private Visual C++
runtime DLLs. Kelft compiler-core and application linking uses the included LLVM
linker and first-party import definitions.

Microsoft's [licensing guidance](https://www.microsoft.com/licensing/guidance/Visual-Studio)
distinguishes library code linked into an application from distributing library
files themselves. Distribution of Microsoft runtime code remains subject to the
applicable [Visual Studio license terms](https://visualstudio.microsoft.com/license-terms/)
and distributable-code lists for
[Visual Studio 2022](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution)
and [Visual Studio 2026](https://learn.microsoft.com/en-us/visualstudio/releases/2026/redistribution).

Rebuilding the Rust hosts requires appropriately licensed Visual Studio Build
Tools and Windows SDK inputs. Ordinary Kelft source rebuilding and application
compilation reuse the seed hosts and do not require those development tools.
