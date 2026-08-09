# Runtime identity and signing providers

LETS keeps vendor SDKs outside the core package. A deployment can install an
adapter for OIDC, SPIFFE, an HSM, or a managed KMS under the Python entry-point
group `lets.runtime_providers`, then select that adapter by its entry-point name.
There is no module-path fallback and LETS imports only the selected entry point.

An adapter package registers a callable:

```toml
[project.entry-points."lets.runtime_providers"]
managed = "my_lets_runtime.provider:open_runtime"
```

The callable receives a frozen `lets.runtime.RuntimeProviderContext` and returns
`RuntimeBindings`. The context contains the expected warden, tenant, envelope,
configuration epoch, optional manifest digest, production flag, resolved config
path, and at most 32 bounded string options. Treat options as identifiers or
references to a provider's own secret store, not as secret values.

Bindings must provide:

- the exact declared warden and tenant identities;
- an Ed25519 signer exposing `warden_id`, `key_id`, 32-byte
  `public_key_bytes`, and `sign(bytes) -> bytes`;
- an `IdentityAuthenticator`, sync or async, whose results belong to the bound
  tenant;
- an optional linearizable `AuthorityAnchor` outside the database rollback
  domain (mandatory when `production_capable` is admitted for production);
- an optional idempotent durable `AuditSink` outside the live database
  (mandatory in production; LETS exports its durable outbox to this sink);
- an exact Boolean `production_capable` declaration; and
- an optional synchronous, idempotent cleanup callback returning `None`.

LETS signs and verifies a fresh admission challenge before opening storage. The
signer identity and public key must also match the database anchor and, for a
manifest deployment, a currently valid key in the signed manifest. Malformed or
cross-tenant authenticator results are rejected per request. Cleanup runs once
at shutdown and also runs when returned bindings fail admission. If a factory
raises before returning bindings, it remains responsible for cleaning up any
resources it acquired.

Select a provider persistently in the local configuration:

```json
{
  "runtime": {
    "provider": "managed",
    "options": {
      "signer_uri": "hsm://lets/warden-a",
      "authority_anchor_uri": "monotonic://lets/warden-a",
      "audit_sink_uri": "archive://lets/warden-a",
      "issuer": "https://identity.example",
      "audience": "lets-warden"
    }
  }
}
```

Or select it explicitly for `serve`, `key`, `info`, or `backup` with
`--runtime-provider NAME` and repeatable `--runtime-option NAME=VALUE`. Duplicate
options are errors; changing providers on the command line does not inherit the
configured provider's options.

`lets serve --production` additionally requires server TLS, HTTPS-only manifest
admission, an operator-signed manifest, no static bootstrap identities, and an
external provider that declares `production_capable=True` and supplies an
independent authority anchor and audit sink. It also requires explicit positive
`min_free_disk_bytes`, `max_database_bytes`, and `reserve_pages` settings so
authority writes retain bounded storage headroom. The `builtin`
file-seed/static-bearer provider remains the compatible development default and
is explicitly forbidden in production mode.

See [`examples/runtime_provider.py`](../examples/runtime_provider.py) for the
adapter shape. The example deliberately leaves organization-specific key and
token verification code undefined rather than providing an insecure substitute.
