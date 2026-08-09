"""Shape of an external LETS runtime-provider package.

Replace ``open_managed_signer`` and ``open_identity_authenticator`` with audited
organization-specific integrations. They are intentionally not implemented by
this vendor-neutral example.
"""

from __future__ import annotations

from lets.runtime import RuntimeBindings, RuntimeProviderContext


def open_runtime(context: RuntimeProviderContext) -> RuntimeBindings:
    signer = open_managed_signer(
        context.options["signer_uri"],
        expected_warden_id=context.warden_id,
    )
    authenticator = open_identity_authenticator(
        issuer=context.options["issuer"],
        audience=context.options["audience"],
    )
    authority_anchor = open_authority_anchor(context.options["authority_anchor_uri"])
    audit_sink = open_audit_sink(context.options["audit_sink_uri"])

    def cleanup() -> None:
        try:
            authenticator.close()
        finally:
            try:
                audit_sink.close()
            finally:
                try:
                    authority_anchor.close()
                finally:
                    signer.close()

    return RuntimeBindings(
        warden_id=context.warden_id,
        tenant_id=context.tenant_id,
        signer=signer,
        authenticator=authenticator,
        production_capable=True,
        authority_anchor=authority_anchor,
        audit_sink=audit_sink,
        cleanup=cleanup,
    )


# These declarations document the integration seam without pretending that a
# generic implementation could safely validate tokens or access managed keys.
def open_managed_signer(uri: str, *, expected_warden_id: str):
    raise NotImplementedError((uri, expected_warden_id))


def open_identity_authenticator(*, issuer: str, audience: str):
    raise NotImplementedError((issuer, audience))


def open_authority_anchor(uri: str):
    raise NotImplementedError(uri)


def open_audit_sink(uri: str):
    raise NotImplementedError(uri)
