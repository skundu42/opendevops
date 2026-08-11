"""RemoteExecutor mTLS client construction."""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from tests.unit.test_executor_service import make_cfg

from opendevops.config import ExecutorTlsConfig
from opendevops.tools.executor import _build_remote_http_client


def _write_self_signed(tmp_path: Path) -> tuple[Path, Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "opendevops-test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "client.key"
    cert_path = tmp_path / "client.crt"
    ca_path = tmp_path / "ca.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(pem)
    ca_path.write_bytes(pem)
    return ca_path, cert_path, key_path


def test_build_remote_http_client_plain() -> None:
    cfg = make_cfg("/tmp/tls-plain")
    client = _build_remote_http_client(cfg)
    assert client is not None


def test_build_remote_http_client_with_mtls(tmp_path: Path) -> None:
    ca, cert, key = _write_self_signed(tmp_path)
    cfg = make_cfg(
        str(tmp_path),
        mode="remote",
        urls={
            "staging": {"ro": "https://s-ro", "rw": "https://s-rw"},
            "prod": {"ro": "https://p-ro", "rw": "https://p-rw"},
        },
        signing_key_env="AGENT_KEY",
        tls={
            "ca_file": str(ca),
            "cert_file": str(cert),
            "key_file": str(key),
        },
    )
    assert isinstance(cfg.executor.tls, ExecutorTlsConfig)
    client = _build_remote_http_client(cfg)
    assert client is not None
