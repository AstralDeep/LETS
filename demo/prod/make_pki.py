"""Generate the X.509 material for inbound mutual TLS.

Two independent certificate authorities are created on purpose:

  ca            the authority the warden is told to trust via --client-ca.
                Issues the warden's server certificate and the dashboard's
                client certificate.
  rogue-ca      trusted by nobody. Issues a syntactically perfect client
                certificate that the warden must refuse. Without this, "mTLS is
                configured" and "mTLS is enforced" are indistinguishable.

Written in Python rather than shelled out to openssl because this machine has
two different openssl builds on PATH depending on the shell (Cygwin 1.1.1f from
PowerShell, Git's 3.2.1 from bash), and the POSIX-path mangling between them
makes -subj arguments behave differently. This produces identical output either
way.

Idempotent: existing files are left alone, so re-running never invalidates a
certificate the warden is already configured against.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prod import params  # noqa: E402

# Deliberately long-lived; this is a local test rig and a mid-demo expiry would
# be a confusing failure rather than an instructive one.
VALIDITY_DAYS = 3650


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_key(path: Path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def make_ca(name: str, key_path: Path, cert_path: Path):
    if key_path.exists() and cert_path.exists():
        return _load_key(key_path), _load_cert(cert_path)

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_key(key_path, key)
    _write_cert(cert_path, cert)
    return key, cert


def make_leaf(
    common_name: str,
    key_path: Path,
    cert_path: Path,
    ca_key,
    ca_cert,
    *,
    server: bool,
    sans: list[x509.GeneralName] | None = None,
) -> None:
    if key_path.exists() and cert_path.exists():
        return

    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    usage = (
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
        if server
        else x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(usage, critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

    _write_key(key_path, key)
    _write_cert(cert_path, builder.sign(ca_key, hashes.SHA256()))


def main() -> int:
    pki = params.PKI_DIR
    ca_key, ca_cert = make_ca("LETS demo root CA", pki / "ca.key", params.CA_CERT)

    # httpx verifies the hostname, so the warden certificate has to carry both
    # the loopback IP the demo connects to and the name a browser would use.
    make_leaf(
        params.WARDEN_ID,
        params.WARDEN_KEY,
        params.WARDEN_CERT,
        ca_key,
        ca_cert,
        server=True,
        sans=[
            x509.IPAddress(ipaddress.ip_address(params.WARDEN_HOST)),
            x509.DNSName("localhost"),
        ],
    )
    make_leaf(
        "demo-dashboard",
        params.CLIENT_KEY,
        params.CLIENT_CERT,
        ca_key,
        ca_cert,
        server=False,
    )
    # Issued up front: --production demands peer TLS material if the generated
    # node config turns out to carry any peer endpoints.
    make_leaf(
        "warden-peer",
        pki / "peer-client.key",
        pki / "peer-client.crt",
        ca_key,
        ca_cert,
        server=False,
    )

    rogue_key, rogue_cert = make_ca(
        "LETS demo UNTRUSTED CA", pki / "rogue-ca.key", pki / "rogue-ca.crt"
    )
    make_leaf(
        "impostor",
        pki / "rogue-client.key",
        pki / "rogue-client.crt",
        rogue_key,
        rogue_cert,
        server=False,
    )

    for path in sorted(pki.glob("*")):
        print(f"  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
