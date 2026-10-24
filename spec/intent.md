# Intent IR 0.1

Versioned JSON carries intent, constraints, context, permissions, assumptions,
verification targets, changes, resolution, and provenance. It is a semantic contract,
not executable prompt text. Goals, examples, hard constraints, preferences,
delegated freedoms, and unresolved decisions remain distinct.

Proposals name an exact base snapshot and candidate hash. Mandatory obligations
must pass before acceptance; unresolved questions return needs-human. Model-provided
evidence cannot mint authority. Hard constraints must link compiler checks, runtime
restrictions, or mandatory registered verifiers. Unknown predicates remain explicit
unverified obligations. Source authoring and runtime permissions are separate.

Subsequent acceptance requires `--proposal` and `--base` matching the parent
event's Intent hash. Every earlier hard constraint must occur in `preserve`,
and its mandatory verification targets must remain identical. A trusted caller
may explicitly authorize named exceptions with `--allow-change ID`; that list
is not read from model-produced JSON.

Assumptions are proposed/confirmed/rejected/stale and have dependency hashes.
Changing a dependency marks them stale and invalidates associated evidence.
Ledger events append parent event, old/new semantic hashes, actor, change, and rationale.
Hash snapshots, ledger events, and evidence separately; exclude volatile presentation
metadata from semantic hashes. Evidence binds the exact candidate and intent hash.
Evidence also includes `policyHash`, `fixtureHash` (the canonical map of referenced
fixture filenames to raw-byte hashes), recomputed `dependencyHashes`, and
`compilerHash`. The trusted driver supplies the actual artifact via
`--compiler-file`. Low-level calls without that option record an explicitly empty
compiler identity. Verification recomputes declared file dependencies under the
project root; missing dependencies invalidate associated assumptions.

The first runtime permits bounded filesystem operations. Other capability kinds
are denied until implemented. Canonical path checks must include symlink resolution.
The capability adapter protects generated programs, not the external authoring agent.
