"""Boot policy: dbx revocation (checked first) and anti-rollback."""

from __future__ import annotations

from .errors import PolicyError
from .keystore import Keystore


def check_revocation(keystore: Keystore, key_id: bytes, image_digest: bytes) -> None:
    """dbx always wins: a revoked key or image never boots, even with a valid signature."""
    if keystore.is_key_revoked(key_id):
        raise PolicyError(f"revoked: signing key {key_id.hex()} is in dbx")
    if keystore.is_image_revoked(image_digest):
        raise PolicyError(f"revoked: image {image_digest.hex()[:16]}... is in dbx")


def check_rollback(stage: str, image_counter: int, fuse_counter: int) -> None:
    if image_counter < fuse_counter:
        raise PolicyError(
            f"rollback: {stage} counter {image_counter} < fuse counter {fuse_counter}"
        )
