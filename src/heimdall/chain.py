"""The boot chain: ROM -> BL1 -> BL2 -> Kernel.

Each stage is read from disk **once**, verified, measured and then executed from
those same in-memory bytes (no time-of-check/time-of-use gap). Any failure halts the
chain: nothing after the failing stage ever runs.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto, policy, rom
from .errors import HeimdallError, ImageFormatError, VerificationError
from .image import MAX_IMAGE_SIZE, Stage, parse, verify_image
from .keystore import Keystore
from .measure import Event, Pcr, save_event_log

logger = logging.getLogger("heimdall.boot")

# (stage name, expected stage id, who verifies it)
STAGES = (
    ("bl1", Stage.BL1, "ROM"),
    ("bl2", Stage.BL2, "BL1"),
    ("kernel", Stage.KERNEL, "BL2"),
)

Executor = Callable[[str, bytes], None]
Reader = Callable[[str | os.PathLike], bytes]


class BootHalt(HeimdallError):
    """The chain stopped. The reason has already been logged."""


@dataclass
class BootResult:
    pcr: bytes
    events: list[Event]
    counters: dict[str, int]


def read_once(path: str | os.PathLike) -> bytes:
    """Read a whole image into memory with a hard size cap."""
    target = Path(path)
    if target.stat().st_size > MAX_IMAGE_SIZE:
        raise ImageFormatError("image file too large")
    with open(target, "rb") as handle:
        data = handle.read(MAX_IMAGE_SIZE + 1)
    if len(data) > MAX_IMAGE_SIZE:
        raise ImageFormatError("image file too large")
    return data


def default_executor(stage: str, payload: bytes) -> None:
    logger.info("[%s] %s", stage.upper(), payload.decode("utf-8", "replace").strip())


def _halt(verifier: str, what: str, exc: HeimdallError) -> None:
    logger.error("[%s] %s INVALID \u2014 HALT: %s", verifier, what, exc)
    raise BootHalt(str(exc)) from exc


def boot(
    *,
    bl1: str | os.PathLike,
    bl2: str | os.PathLike,
    kernel: str | os.PathLike,
    pk_pub: Ed25519PublicKey,
    fuses_path: str | os.PathLike,
    keystore_path: str | os.PathLike,
    events_path: str | os.PathLike | None = None,
    executor: Executor = default_executor,
    reader: Reader = read_once,
) -> BootResult:
    paths = {"bl1": bl1, "bl2": bl2, "kernel": kernel}

    # --- ROM: root of trust and key database ---------------------------------
    try:
        fuses = rom.load_fuses(fuses_path)
        rom.verify_root_key(fuses, pk_pub)
        logger.info("[ROM] root key matches fuse")
        keystore = Keystore.load(keystore_path)
        keystore.require_pk(pk_pub)
        keystore.validate()
        logger.info("[ROM] keystore valid (PK -> KEK -> db)")
    except HeimdallError as exc:
        _halt("ROM", "root of trust", exc)

    # --- each stage verifies the next ---------------------------------------
    pcr = Pcr()
    events: list[Event] = []
    new_counters: dict[str, int] = {}
    for name, stage_id, verifier in STAGES:
        try:
            data = reader(paths[name])  # the only read of this file
            image = parse(data)
            if image.stage != stage_id:
                raise VerificationError(
                    f"stage mismatch: image is {image.stage.name}, expected {stage_id.name}"
                )
            digest = crypto.sha256_bytes(data)
            policy.check_revocation(keystore, image.key_id, digest)  # dbx first
            pub = keystore.db_public_key(image.key_id)
            if pub is None:
                raise VerificationError(
                    f"signing key {image.key_id.hex()} is not enrolled in db"
                )
            verify_image(image, pub)
            policy.check_rollback(name, image.counter, fuses.counters[name])
        except (HeimdallError, OSError) as exc:
            err = exc if isinstance(exc, HeimdallError) else ImageFormatError(str(exc))
            _halt(verifier, name.upper(), err)

        logger.info(
            "[%s] %s verified (key %s, counter %d)",
            verifier,
            name.upper(),
            image.key_id.hex(),
            image.counter,
        )
        pcr.extend(digest)
        events.append(Event(name, digest.hex()))
        new_counters[name] = image.counter
        executor(name, image.payload)  # runs the verified bytes, not the file

    # --- the whole chain verified: commit counters and the event log --------
    rom.commit_counters(fuses_path, new_counters)
    if events_path is not None:
        save_event_log(events_path, events, pcr.value)
    return BootResult(pcr=pcr.value, events=events, counters=new_counters)
