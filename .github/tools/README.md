# Vendored workflow tools

`actionlint_1.7.12_linux_amd64.tar.gz` is the upstream Linux amd64 release archive for
[`rhysd/actionlint` v1.7.12](https://github.com/rhysd/actionlint/releases/tag/v1.7.12).
It is vendored so the security workflow does not depend on an unbounded external image or
release-asset download before it can validate the repository's workflows.

- Upstream asset: `actionlint_1.7.12_linux_amd64.tar.gz`
- SHA-256: `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8`
- License: MIT; the upstream archive contains `LICENSE.txt`.

The security workflow verifies the archive hash before extracting only the `actionlint` executable.
The production Docker context excludes `.github`, and Python/deployment artifacts do not package
this archive.
