# Contributing to Kelft

Issues and pull requests are welcome. Direct pull requests to **`dev`**.
Maintainers review contributions for correctness, compatibility, scope, and
maintenance cost before deciding whether to merge them.

## Issues and proposals

For bugs, include the compiler version, OS and architecture, a minimal `.kelft`
example, the command you ran, expected behavior, and actual diagnostics. Remove
credentials and private application data. Report vulnerabilities through the
[security policy](SECURITY.md).

For features or language changes, open an issue to discuss the problem, proposed
behavior, compatibility impact, and examples before starting substantial work.
The [public specification](https://www.kelft.com) defines language contracts;
editorial changes must preserve their meaning.

## Pull requests

Keep changes focused and explain the problem and resulting behavior. Include
relevant successful and rejected examples for compiler changes, and tests for
affected contracts. Follow existing style and preserve ownership, traversal,
resource, and platform boundary requirements.

Run the [native bootstrap and tests](docs/build.md) after changing compiler
sources. Local edits and new modules do not require refreshing release hashes.
Include successful and rejected cases and describe the checks you ran. Source
checks alone do not establish platform qualification.

Contributions use the licenses described in [licensing](docs/licensing.md).
Preserve existing notices and third-party terms. Contributors retain ownership;
no copyright assignment or CLA is required. Sign off your commits with
`git commit -s` to certify [DCO 1.1](DCO).
