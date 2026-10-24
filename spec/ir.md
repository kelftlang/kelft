# Core IR 0.1

Pipeline: UTF-8 source -> tokens -> AST -> bound/typed representation -> concrete
generic instances -> validated structured Core -> backend lowering -> artifacts.

Core represents language-owned values, copy/update operations, calls, control flow,
and symbolic host operations. Types and symbols are resolved. Source spans survive.
Generic templates and unresolved names are forbidden in emitted Core. Validation
runs before every backend. Persisted Core has a schema version and stable ordering.

No JS object behavior, Wasm instructions, C types, pointer widths, registers,
calling conventions, allocator headers, or platform-specific layouts belong here.
Backends consume Core, never parser AST. Runtime profiles and capability policies
are explicit backend inputs. Unsupported targets fail, with no fallback to JS.
