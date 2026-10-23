# Compiler releases

## Versions and compatibility

The compiler version is `0.1.0-alpha.1`. Alpha releases are experimental and may
change source support, commands, package layouts, and backend ABIs. Check the
[changelog](CHANGELOG.md) and notes for the exact release before upgrading.
Core, Intent, specification snapshots, and runtime profiles have separate
versions; a compiler version does not advance all those contracts together.

Native package definitions cover Linux, Windows, and macOS on x86-64 and ARM64.
Each published release must identify its available targets and tested OS
baselines. A target definition or minimum deployment version alone does not
establish support or certification. Optional engines, services, and cross-target
packs are separate from default native packages.

## Verify a download

Obtain assets from [GitHub Releases](https://github.com/kelftlang/kelft/releases).
Verify artifact provenance against this repository, the producing workflow, and
the exact source revision; compare downloaded bytes with the authenticated
SHA-256 inventory. An adjacent checksum file alone does not authenticate origin.
Source archives, seed sources, package inventories, and dependency notices must
correspond to those exact assets. See [installation](docs/install.md) and
[source rebuilding](docs/build.md).

## Qualification and signing

Release qualification applies to exact source and tool inputs on each native
host. It includes compiler generation equality, reproducible archives, language
behavior, extracted-package execution, and platform boundary/resource checks.
Local source checks and build reports do not establish that qualification.
Reports preserve their actual inputs and releaseEligible status.

The [release workflow guide](docs/release-workflow.md) describes native
qualification, draft preparation, artifact attestations and the separate manual
publication action. The workflow retains reviewed native hosts, rebuilds Kelft
compiler generations and verifies the exact extracted packages.

Trusted Windows executable signing and Apple notarization are deferred for the
initial alpha. macOS still requires its documented ad-hoc signing step. Release
notes must disclose signing status and any OS download warnings; ad-hoc signing
does not establish a trusted publisher identity. Unpublished assets have no
release or support claim.
