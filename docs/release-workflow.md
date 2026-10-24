# Preparing an alpha release

The **Native compiler release** workflow has five manual operations:

| Operation | Result |
| --- | --- |
| `refresh-seeds` | Refresh changed native components and open a seed-only PR against the dispatch branch, `dev` or `main`. |
| `verify` | Assemble selected native distributions and check extracted installations, retaining reports without creating a release. |
| `prepare` | Verify all six distributions, attest assets, create the version tag and a draft prerelease, and verify downloaded draft bytes. |
| `resume-draft` | Authenticate a previous prepare run and finish its draft using the original signed assets, without rebuilding or repackaging. |
| `publish` | Revalidate a specified draft and publish those same assets without rebuilding. |

Native jobs have maximum concurrency two. Release engineering uses pinned tools;
installed compilation and native Kelft rebuilding run offline without Node or
Rust/C development tools. Refreshing a coordinator requires those development
tools on its CI runner. Dependency preparation may use the network; compilation
uses locked, prepared dependencies offline.

## Configure GitHub once

In **Settings → Actions → General → Workflow permissions**, enable **Allow
GitHub Actions to create and approve pull requests**. The workflow creates PRs
but never approves or merges them. It uses the built-in `GITHUB_TOKEN`; no
additional credential is required. When a bot PR displays **Approve workflows
to run**, click it to start its `source` check. See GitHub's
[workflow triggering guidance](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).

Before merging into `main`, enable the prepared
[main ruleset](../.github/main.ruleset.json) in **Settings → Rules → Rulesets**.
Use **New ruleset → Import a ruleset**, or configure a branch ruleset with:

- Enforcement **Active**, target `main`, and no bypass actors.
- **Require a pull request before merging**, with required approvals **0** and
  resolved review conversations required.
- **Require status checks to pass**, selecting `source` from GitHub Actions,
  with branches required to be up to date.
- **Restrict deletions** and **Block force pushes**.

Do not require signed commits across existing history. Release preparation
separately verifies the selected source commit. The automation has no bypass;
you review and merge its PRs through GitHub. The JSON file is a configuration
template and does not activate a rule by being committed.

Configure required reviewers for `compiler-release-draft` and
`compiler-release-publish`, restricting both environments to `main`. If the same
person starts and approves a run, leave **Prevent self-review** unchecked.

## Refresh native seeds through a PR

After pushing reviewed tooling to `dev`, open **Actions → Native compiler
release → Run workflow**. Choose branch `dev`, operation `refresh-seeds`, and
target `all`. Leave `candidate_sha` empty: refresh always uses the triggering
commit. A dispatch from `dev` opens a PR into `dev`; one from `main` opens a PR
into `main`. Other branches and forks cannot run the write operation.

If GitHub's form still displays the workflow inputs from the older `main`
version, dispatch the existing workflow against `dev` using the GitHub CLI:

```sh
gh workflow run release.yml --repo kelftlang/kelft --ref dev -f operation=refresh-seeds -f target=all
```

The native jobs authenticate checked-in seeds and retained public compiler
evidence. They retain unchanged compiler images, testing policies, boundaries,
and linker/runtime inputs. Changed rebuild policies are compiled twice and
compared; coordinators are rebuilt only when their inputs or embedded policy
change. Focused checks exercise version metadata, staging in spaced/Unicode
paths, policy decisions, rejected metadata, empty runtime PATH, and Hello World.
These jobs do not repeat compiler S1/S2/S3 generations or unchanged language suites.

Native jobs have read-only repository permissions. A separate PR job authenticates
the artifacts' producing repository, workflow, dispatch branch, commit, ZIP
digest, and members before using the delta. Only that job receives repository
and PR write permissions. It creates an `automation/refresh-seeds/…` branch
through GitHub's bot-authenticated commit API, without overriding author,
committer, or signature fields. It verifies the returned signature, full tree,
paths, and executable modes before opening a PR. See GitHub's
[bot signature guidance](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).

The PR contains seed payloads, corresponding sources, inventories, provenance,
notices where required, and derived review bindings. Dependency decisions carry
forward only when dependency, license, and notice bytes remain unchanged.
Changed obligations stop with a review requirement. Unrelated destination edits
are preserved; relevant source or seed drift stops PR creation. No-op refreshes
create no commit. Identical reruns reuse the existing PR without force pushes.

Review the component hashes, retained identities, artifact identities, producer
commit, and checks in the PR description. Approve its workflow checks if GitHub
requests it, then merge manually. Seed-only PR checks validate inventories and
skip optional native compiler rebuilds. On failure, rerun failed jobs rather
than restarting successful targets; the PR job accepts authenticated successful
artifacts from earlier attempts of the same run.

## Retained compiler qualification

Initial compiler evidence is adopted from public run `40059868983`, candidate
`64b4da174db450ff96a9ce7a04555d3514758fe9`. Its S1 is the authenticated
checked-in seed; S2 is S1's rebuild; S3 is S2's rebuild from a separate identical
source copy. S2/S3 compiler objects, executable images, and policies were
compared. Original reports and producer identities remain unchanged.

Adoption checks the actual compiler import closure and selected execution
inputs, rather than equating whole repository snapshots. Compiler-core,
rebuild-policy, testing-policy, and host inputs have separate identities.
Documentation and version edits reuse the compiler and unchanged language
evidence. Changed fixtures rerun affected language checks without rebuilding
the compiler. A changed compiler, testing policy, boundary, linker, or runtime
that cannot use the retained proof stops with a specific diagnostic; it never
silently launches replacement six-host compiler generations.

The first refresh authenticates and imports the retained reports into the seed
materials. Later packaging can use those checked-in materials without private
access. Missing or expired initial artifacts are a concrete recovery requirement;
an artifact name alone is never enough to execute downloaded files.

## Prepare a draft

Merge the seed PR into `dev`, then merge the reviewed `dev` → `main` PR through
GitHub. Select that resulting `main` commit. Dispatch `prepare` from `main`,
target `all`, with the exact candidate SHA. No private qualification cycle or
separate host-readiness proof is required. Keep `main` unchanged until preparation
finishes. Before creating an absent tag, ordinary preparation confirms that
`main` still identifies the triggering candidate; drift stops tag creation.
An initial tag lookup returning 404 is expected for a new version.

`release.json` is the compiler version authority. The changelog must contain
exactly one nonempty matching tag section, such as `## v0.1.0-alpha.2`. Archive
names, release titles, and tags derive from it; no publication date is invented.
Preparation verifies the source commit's GitHub web-flow signature against
GitHub's published signing keys. An existing tag must identify that exact commit.

Each native runner assembles a distribution using the retained compiler and
compatible refreshed components, compares two independently written package
archives, and runs current extracted-package controls. These are repeated
packaging checks, not new S2/S3 compiler generations. Metadata, installation
documents, checksums, inventories, and provenance describe the new candidate.
Executable bytes are never normalized. The complete outgoing inventory and
candidate commit remain release audit inputs, separate from reuse identities.

The manifest calculates `releaseEligible` from source/export validation,
dependency review, all six qualification reports, reproducibility, and package
integrity. Missing checks produce explicit reasons. Seeds and ordinary local
rebuilds remain unqualified. Attestation, downloaded-draft verification, and
protected manual approval are additional mandatory publication gates.

After packaging and OIDC attestation, the protected draft job verifies local
assets and signatures, creates a missing version tag, and reads it back before
creating the draft. The lightweight tag points to the verified source commit;
the tag itself does not claim a signature. Matching concurrent tag creation is
accepted; tags are never moved or replaced.

Existing matching drafts and uploaded assets can be reused; missing assets can
be uploaded. Altered, unexpected, published, or immutable releases are rejected.
Every release update includes `tag_name` and validates response/readback identity.
Complete draft assets are downloaded and authenticated against checksums and
attestations. Alpha.1's tag, draft, assets, and historical evidence are preserved.

## Recover an interrupted draft

If a draft job repeatedly fails, preserve its signed-assets artifact. After reviewing and merging any tooling correction, dispatch **resume-draft** from **main**, target **all**, with the original **source_run_id** and **candidate_sha**. Approve **compiler-release-draft** when prompted. A rerun of the old workflow uses its old code; the recovery operation uses the reviewed tooling on current main.

Recovery requires a completed prepare run from this repository's main release workflow with successful preflight, assembly and attestation jobs. It authenticates the unique unexpired signed-assets ZIP, verifies the manifest's original-candidate attestation before reading its inventory, and verifies every asset. It preserves the original candidate, version, signatures and bytes. The recovery workflow must be a verified descendant of the candidate; its identity is recorded separately in the draft-recovery-evidence artifact. Ordinary prepare still requires its workflow commit to equal its candidate.

Recovery performs no native builds, packaging or new attestations, and never publishes. Creating a tag at an older candidate can be denied by GitHub even with Contents write permission. For a fresh preparation, dispatch `prepare` from the final merged `main` commit with target `all` and that exact candidate; leave recovery and release-ID inputs empty. Existing conflicting tags or drafts must be resolved by review, never overwritten. Preserve the earlier run artifacts and attestations; fresh assets receive attestations for the new candidate.

Network errors identify the operation, safe endpoint, attempt, elapsed time, status, GitHub request ID, bounded error response and error code without credentials or signed URL queries. Reads have at most three attempts with bounded delays and deadlines covering response bodies. Interrupted downloads restart into exclusive files; incomplete files are removed. Authentication, integrity and attestation failures stop immediately. Ambiguous writes are reconciled against the exact remote tag, draft or complete uploaded asset; conflicting or incomplete assets require review and are never silently replaced.

## Publish separately

Review the draft and download-verification results. Supply its ID and exact
candidate SHA to `publish` from `main`. Approve the separate protected action.
It authenticates the manifest before using it, rechecks eligibility, the tag,
complete asset set, downloaded bytes, and attestations, then publishes the same
assets without rebuilding. Publication races are rejected.

Windows signing and Apple notarization remain deferred. macOS uses ad-hoc
signing. Release notes disclose these alpha limitations. Source archives retain
the 2 GiB aggregate and 256 MiB member limits; native and sandbox limits remain
unchanged. See the [host source workflow](host-build.md) for advanced rebuilding.
