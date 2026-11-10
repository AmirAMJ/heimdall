"""Signed boot-image format and its strict parser.

Layout::

    header (56 bytes) | payload (payload_len bytes) | signature (64 bytes, optional)

Header, little-endian, no padding (``<4sHHII32s8s``)::

    magic "HMDL" | format version | stage id | security counter |
    payload length | SHA-256 of payload | signing key id

The signature covers ``header + payload``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import crypto
from .errors import ImageFormatError, VerificationError

MAGIC = b"HMDL"
FORMAT_VERSION = 1
HEADER = struct.Struct("<4sHHII32s8s")
SIGNATURE_LEN = 64
MAX_PAYLOAD = 16 * 1024 * 1024
MAX_IMAGE_SIZE = HEADER.size + MAX_PAYLOAD + SIGNATURE_LEN
UNSIGNED_KEY_ID = bytes(crypto.KEY_ID_LEN)
MAX_COUNTER = 2**32 - 1


class Stage(IntEnum):
    BL1 = 1
    BL2 = 2
    KERNEL = 3


STAGE_BY_NAME = {"bl1": Stage.BL1, "bl2": Stage.BL2, "kernel": Stage.KERNEL}


@dataclass(frozen=True)
class Image:
    stage: Stage
    counter: int
    payload: bytes
    payload_hash: bytes
    key_id: bytes = UNSIGNED_KEY_ID
    signature: bytes = b""
    version: int = FORMAT_VERSION

    # -- serialisation ---------------------------------------------------
    def header(self) -> bytes:
        return HEADER.pack(
            MAGIC,
            self.version,
            int(self.stage),
            self.counter,
            len(self.payload),
            self.payload_hash,
            self.key_id,
        )

    def signed_bytes(self) -> bytes:
        """Exactly the bytes the signature covers."""
        return self.header() + self.payload

    def to_bytes(self) -> bytes:
        return self.signed_bytes() + self.signature

    @property
    def is_signed(self) -> bool:
        return len(self.signature) == SIGNATURE_LEN


def build_image(payload: bytes, stage: Stage, counter: int) -> Image:
    if not 0 <= counter <= MAX_COUNTER:
        raise ImageFormatError("security counter must fit in 32 bits")
    if len(payload) > MAX_PAYLOAD:
        raise ImageFormatError("payload too large")
    return Image(
        stage=Stage(stage),
        counter=counter,
        payload=payload,
        payload_hash=crypto.sha256_bytes(payload),
    )


def sign_image(image: Image, priv: Ed25519PrivateKey) -> Image:
    """Set the key id first (it is part of the signed header), then sign."""
    prepared = replace(image, key_id=crypto.key_id(priv.public_key()), signature=b"")
    return replace(prepared, signature=crypto.sign(priv, prepared.signed_bytes()))


def parse(data: bytes) -> Image:
    """Strictly parse an image. Raises only :class:`ImageFormatError`."""
    if len(data) < HEADER.size:
        raise ImageFormatError("truncated header")
    magic, version, stage, counter, length, payload_hash, key_id = HEADER.unpack_from(
        data
    )
    if magic != MAGIC:
        raise ImageFormatError("bad magic")
    if version != FORMAT_VERSION:
        raise ImageFormatError(f"unsupported format version {version}")
    try:
        stage_id = Stage(stage)
    except ValueError:
        raise ImageFormatError(f"unknown stage id {stage}") from None
    if length > MAX_PAYLOAD:
        raise ImageFormatError("payload too large")
    body_end = HEADER.size + length
    if len(data) < body_end:
        raise ImageFormatError("truncated payload")
    trailing = len(data) - body_end
    if trailing not in (0, SIGNATURE_LEN):
        raise ImageFormatError(f"unexpected trailing bytes ({trailing})")
    return Image(
        stage=stage_id,
        counter=counter,
        payload=bytes(data[HEADER.size : body_end]),
        payload_hash=payload_hash,
        key_id=key_id,
        signature=bytes(data[body_end:]),
        version=version,
    )


def verify_image(image: Image, pub: Ed25519PublicKey) -> None:
    """Raise :class:`VerificationError` unless the image is intact and signed by ``pub``."""
    if not image.is_signed:
        raise VerificationError("image is not signed")
    if not crypto.constant_time_equal(image.key_id, crypto.key_id(pub)):
        raise VerificationError("image was signed by a different key")
    if not crypto.constant_time_equal(
        image.payload_hash, crypto.sha256_bytes(image.payload)
    ):
        raise VerificationError("payload hash mismatch (image was modified)")
    if not crypto.verify(pub, image.signature, image.signed_bytes()):
        raise VerificationError("bad signature")
