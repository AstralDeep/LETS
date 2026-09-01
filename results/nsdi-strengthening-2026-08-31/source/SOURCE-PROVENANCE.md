# Evidence source provenance

The measurements were produced while the evidence harnesses were new,
uncommitted files on `main` at
`a9f4ba810e1741f93ba204eb782b6c4e3d409a03`. Before opening the public PR, the
Python sources were mechanically Ruff-formatted and the complete test suite was
rerun. The retained observation payloads were not regenerated or rewritten by
that formatting step.

`PRE-PR-SOURCE-MANIFEST.json` records every pre-format byte count and SHA-256.
`pre-pr-source-snapshot.zip` contains those exact 29 files with deterministic
ZIP metadata. Its SHA-256 is
`62ef11d3a6a5d608c742ee23cccc664ad44d592a332ac35ae60458837230ec37`.

The remote-run manifests remain authoritative for executed-source identity:

- Matched-host benchmark:
  `81deccb273743f6536f22a2951bcaca99f075fce2c50e9c5264a79dc5aba0713`.
- Matched-host controller:
  `14822649d21ec627419c088e53e7411841280c1c7fbdbe89b37599ac32c8b9f8`.
- Three-host agent:
  `401793f4271e237485101beb069e52371301299762572b0058a7943d7a230f46`.
- Three-host run controller:
  `6960b32e51e59f27dabffeb2feb9f13ec9868440b496607ad02ea88bae4d0bad`.

The retained pre-PR three-host controller additionally contains local-only
rendering added after the remote run, so its whole-file hash is not substituted
for the run-controller hash above. The raw scenario JSON remains frozen.
