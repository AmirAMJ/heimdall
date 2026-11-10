"""Measured boot: a simulated TPM PCR, an event log with replay, and sealing.

``PCR_new = SHA256(PCR_old || measurement)``: a PCR can only be *extended*, so the
final value is reproducible only by the same measurements in the same order.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto
from .errors import PolicyError, VerificationError

PCR_LEN = 32
LOG_VERSION = 1
_SEAL_INFO = b"heimdall-seal-v1"


class Pcr:
    def __init__(self) -> None:
        self.value = bytes(PCR_LEN)

    def extend(self, measurement: bytes) -> bytes:
        if len(measurement) != PCR_LEN:
            raise ValueError("a measurement must be a 32-byte SHA-256 digest")
        self.value = crypto.sha256_bytes(self.value + measurement)
        return self.value


@dataclass(frozen=True)
class Event:
    stage: str
    sha256: str  # hex digest of the loaded image


def replay(events: list[Event]) -> bytes:
    pcr = Pcr()
    for event in events:
        pcr.extend(bytes.fromhex(event.sha256))
    return pcr.value


def save_event_log(path: str | os.PathLike, events: list[Event], pcr: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "version": LOG_VERSION,
        "events": [{"stage": e.stage, "sha256": e.sha256} for e in events],
        "pcr": pcr.hex(),
    }
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", "utf-8")
    os.replace(tmp, target)


def load_event_log(path: str | os.PathLike) -> tuple[list[Event], str]:
    try:
        raw = json.loads(Path(path).read_text("utf-8"))
        if raw["version"] != LOG_VERSION:
            raise VerificationError("unsupported event-log version")
        events = [Event(str(e["stage"]), bytes.fromhex(e["sha256"]).hex()) for e in raw["events"]]
        recorded = bytes.fromhex(raw["pcr"]).hex()
    except FileNotFoundError:
        raise VerificationError(f"event log not found: {path}") from None
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, UnicodeDecodeError):
        raise VerificationError("malformed event log") from None
    return events, recorded


def verify_event_log(path: str | os.PathLike, expect: str | None = None) -> bytes:
    """Replay the log. Raise on mismatch with the recorded (or expected) PCR."""
    events, recorded = load_event_log(path)
    replayed = replay(events)
    wanted = expect if expect is not None else recorded
    if not crypto.constant_time_equal(replayed, bytes.fromhex(wanted)):
        raise VerificationError(
            f"event log MISMATCH: expected {wanted}, replay gives {replayed.hex()}"
        )
    return replayed


# ------------------------------------------------------------------ sealing
def _seal_key(pcr: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_SEAL_INFO).derive(pcr)


def seal(secret: bytes, pcr: bytes) -> dict:
    """Encrypt ``secret`` under a key derived from the PCR."""
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(_seal_key(pcr, salt)).encrypt(nonce, secret, _SEAL_INFO)
    return {
        "version": 1,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def unseal(blob: dict, pcr: bytes) -> bytes:
    try:
        salt = bytes.fromhex(blob["salt"])
        nonce = bytes.fromhex(blob["nonce"])
        ciphertext = bytes.fromhex(blob["ciphertext"])
    except (KeyError, TypeError, ValueError):
        raise PolicyError("malformed sealed blob") from None
    try:
        return AESGCM(_seal_key(pcr, salt)).decrypt(nonce, ciphertext, _SEAL_INFO)
    except InvalidTag:
        raise PolicyError(
            "PCR mismatch: the boot state differs from the state the secret was sealed to"
        ) from None
