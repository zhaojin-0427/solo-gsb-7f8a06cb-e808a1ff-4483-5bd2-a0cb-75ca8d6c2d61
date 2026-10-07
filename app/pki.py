"""基于 cryptography 的极简两级 PKI：固定 Server-CA 签发网关证书，根 A/B 签发客户端证书。"""
from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_SERIAL_ORDER = 0


@dataclass(frozen=True)
class CertKey:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


def _next_serial() -> int:
    # 进程内单调；跨进程靠时间戳与随机尾部拉开
    global _SERIAL_ORDER
    _SERIAL_ORDER += 1
    return int(
        datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000
    ) * 10000 + _SERIAL_ORDER


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def create_ca(cn: str) -> CertKey:
    key = new_key()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_next_serial())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return CertKey(cert, key)


def issue_leaf(
    ca: CertKey,
    cn: str,
    *,
    server: bool = False,
    client: bool = False,
    sans: list[str] | None = None,
) -> CertKey:
    key = new_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(_next_serial())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    eku_oids = []
    if server:
        eku_oids.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
        eku_oids.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
    if eku_oids:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku_oids), critical=False
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    cert = builder.sign(ca.key, hashes.SHA256())
    return CertKey(cert, key)


def cert_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 指纹，页面上统一显示前 16 位十六进制。"""
    return cert.fingerprint(hashes.SHA256()).hex()


def fp_short(fp: str) -> str:
    return fp[:16]


def load_cert_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)
