# Security policy

LETS is an authorization boundary. Please do not disclose a suspected authority-minting,
signature, replay, tenant-isolation, or crash-consistency vulnerability in a public issue before
the maintainers can assess it.

Report vulnerabilities through GitHub's private vulnerability reporting flow for
`AstralDeep/LETS`. Include the affected version or commit, deployment shape, smallest reproducer,
security invariant violated, and whether signing keys or live credentials may have been exposed.
Do not include real secrets or sensitive tenant data.

## Supported line

Until the first stable release, security fixes are made on `main`; there is no supported older
release branch. Deploy an immutable commit digest and review the threat model and release evidence
for that commit.

## Scope assumptions

The base v1 threat model trusts wardens, their signing keys, configured policies, the declared
clock bound, protected executors, and host isolation. Byzantine wardens, concurrent use of cloned
warden state, and arbitrary exactly-once external effects are not claimed. See
`docs/threat-model.md` for the complete boundary.

The SQLite database never stores a private signing seed, but it does contain sensitive subject,
lineage, receipt, transfer, and audit metadata. LETS does not provide database encryption at rest.
Use restrictive filesystem/volume ACLs and encrypted backups; on Windows and in containers these
controls are an operator responsibility.
