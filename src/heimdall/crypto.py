"""Cryptographic primitives.

Every hash or key comparison in the project goes through
:func:`constant_time_equal`, so ``hmac.compare_digest`` lives in exactly one place.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import HeimdallError

KEY_ID_LEN = 8
_CHUNK = 1 << 16


# --------------------------------------------------------------------- hashing
def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_file(path: str | os.PathLike) -> bytes:
    """Hash a file in chunks so large files never need to fit in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare secrets/hashes without an early exit on the first differing byte."""
    return hmac.compare_digest(a, b)


# ------------------------------------------------------------------- key ids
def public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_from_raw(raw: bytes) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise HeimdallError("invalid Ed25519 public key") from exc


def key_hash(pub: Ed25519PublicKey) -> bytes:
    """SHA-256 of the raw public key: what the 'fuses' store for the root key."""
    return sha256_bytes(public_raw(pub))


def key_id_of_raw(raw: bytes) -> bytes:
    return sha256_bytes(raw)[:KEY_ID_LEN]


def key_id(pub: Ed25519PublicKey) -> bytes:
    return key_id_of_raw(public_raw(pub))


# ------------------------------------------------------------------ key files
def generate_keypair(
    name: str, out_dir: str | os.PathLike, passphrase: bytes | None = None
) -> tuple[Path, Path]:
    """Create ``<name>.key.pem`` (mode 0600) and ``<name>.pub.pem``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv_path = out / f"{name}.key.pem"
    pub_path = out / f"{name}.pub.pem"
    for path in (priv_path, pub_path):
        if path.exists():
            raise HeimdallError(f"refusing to overwrite {path}")

    priv = Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv_path, pub_path


def is_encrypted(path: str | os.PathLike) -> bool:
    return b"ENCRYPTED" in Path(path).read_bytes()


def load_private_key(
    path: str | os.PathLike, passphrase: bytes | None = None
) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except TypeError as exc:
        raise HeimdallError(f"{path} is encrypted: a passphrase is required") from exc
    except ValueError as exc:
        raise HeimdallError(
            f"cannot load {path} (wrong passphrase or not a PEM private key)"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise HeimdallError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str | os.PathLike) -> Ed25519PublicKey:
    data = Path(path).read_bytes()
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise HeimdallError(f"cannot load {path} as a PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise HeimdallError(f"{path} is not an Ed25519 public key")
    return key


# ------------------------------------------------------------ sign and verify
def sign(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)


def verify(pub: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Return True/False. The library raises on failure; we turn that into a bool."""
    try:
        pub.verify(signature, data)
    except InvalidSignature:
        return False
    return True
