"""The simulated boot ROM and its one-time-programmable 'fuses'.

``fuses.json`` holds the SHA-256 of the Platform Key and one anti-rollback counter
per boot stage. :func:`provision` creates it exactly once; afterwards the only
permitted change is :func:`commit_counters`, which can only raise counters.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import crypto
from .errors import PolicyError, VerificationError

FUSE_VERSION = 1
STAGE_NAMES = ("bl1", "bl2", "kernel")


@dataclass
class Fuses:
    pk_hash: str
    counters: dict[str, int]


def _write_atomic(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", "utf-8")
    os.replace(tmp, path)


def provision(path: str | os.PathLike, pk_pub: Ed25519PublicKey) -> Fuses:
    """Burn the root-key hash. Refuses if the fuses already exist."""
    target = Path(path)
    if target.exists():
        raise PolicyError("refused: fuses already programmed")
    target.parent.mkdir(parents=True, exist_ok=True)
    fuses = Fuses(
        pk_hash=crypto.key_hash(pk_pub).hex(), counters={n: 0 for n in STAGE_NAMES}
    )
    try:
        with open(target, "x", encoding="utf-8") as handle:
            json.dump(
                {
                    "version": FUSE_VERSION,
                    "pk_hash": fuses.pk_hash,
                    "counters": fuses.counters,
                },
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
    except FileExistsError:
        raise PolicyError("refused: fuses already programmed") from None
    return fuses


def load_fuses(path: str | os.PathLike) -> Fuses:
    try:
        raw = json.loads(Path(path).read_text("utf-8"))
    except FileNotFoundError:
        raise PolicyError(f"fuses not programmed ({path} missing)") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(f"corrupt fuses: {exc}") from None
    try:
        if raw["version"] != FUSE_VERSION:
            raise PolicyError("unsupported fuse version")
        pk_hash = raw["pk_hash"]
        bytes.fromhex(pk_hash)
        counters = {name: int(raw["counters"][name]) for name in STAGE_NAMES}
    except (KeyError, TypeError, ValueError):
        raise PolicyError("malformed fuses") from None
    if any(v < 0 for v in counters.values()):
        raise PolicyError("malformed fuses")
    return Fuses(pk_hash=pk_hash, counters=counters)


def verify_root_key(fuses: Fuses, pk_pub: Ed25519PublicKey) -> None:
    """Never trust a key just because it was handed to us: compare against the fuse."""
    if not crypto.constant_time_equal(
        bytes.fromhex(fuses.pk_hash), crypto.key_hash(pk_pub)
    ):
        raise VerificationError("root key hash MISMATCH (key does not match the fuse)")


def commit_counters(path: str | os.PathLike, new: dict[str, int]) -> Fuses:
    """Raise per-stage counters to ``new``. A counter never goes down."""
    fuses = load_fuses(path)
    for name, value in new.items():
        if name not in fuses.counters:
            raise PolicyError(f"unknown stage {name!r}")
        fuses.counters[name] = max(fuses.counters[name], value)
    _write_atomic(
        Path(path),
        {
            "version": FUSE_VERSION,
            "pk_hash": fuses.pk_hash,
            "counters": fuses.counters,
        },
    )
    return fuses
