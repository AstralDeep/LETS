# Formal evidence

`LETS.tla` specifies the scalar kernel for local escrow, transfer delivery,
duplicate messages, receipt issuance, and executor replay protection.  Resource
vectors are the component-wise product of this scalar equation.  `LETS.cfg` is a
small three-warden TLC configuration.  TLC is optional and is not installed by
the project.  The reviewed TLC result records the exact tool checksum, spec
digest, command, state count, and complete-queue result in
`formal/evidence/tlc-check.json`.

The checked, dependency-free refinement model is `model_checker.py`.  It also
models recursive leases, per-peer transfer sequences, reordering, finalization,
receipt nonces, and per-lease executor watermarks.  Run it with the local venv:

```powershell
.venv\Scripts\python.exe -m formal.model_checker
```

Output goes to ignored `results/generated/formal/`.  Reviewed results are kept
under `formal/evidence/` with their model digest and exact bounds.

The runner downloads the exact TLA+ 1.8.0 tool release into ignored `tmp/`,
checks its SHA-256 digest and byte size against `tlc-tool.json`, keeps TLC state
under ignored generated evidence, and writes a structured result plus raw log:

```powershell
.venv\Scripts\python.exe -m formal.run_tlc
```

On POSIX systems the equivalent is `.venv/bin/python -m formal.run_tlc`.

The runner requires Java 11 or newer but does not install Java or any system
package. Reruns must use a fresh `--meta-directory` so evidence cannot silently
mix with an earlier state directory.

This is bounded exhaustive checking, not proof.  It establishes the listed
invariants only for the finite shares, depth, and object bounds in the result.
The mutation test deliberately injects duplicate transfer credit and requires a
minimal counterexample, demonstrating that the checker is capable of detecting
the central conservation fault rather than merely exercising actions.

`exhaustive_checker.py` is retained as the historical two-warden prototype
checker so earlier research artifacts remain reproducible.  New evidence and
tests use `model_checker.py`.
