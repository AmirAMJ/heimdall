"""The key database: PK -> KEK -> db, plus the dbx revocation list.

Modeled on UEFI Secure Boot:

* ``PK``  (Platform Key) is the root of trust. It authorizes KEK updates.
* ``KEK`` keys authorize db and dbx updates (and so may the PK).
* ``db``  keys are the only keys whose signatures make an image bootable.
* ``dbx`` lists revoked key ids and image hashes and always wins over db.

The store starts in *setup mode*, where updates need no signature. Enrolling the
PK switches it to *user mode* and seals every existing entry by signing it with
the PK; from then on every update must be signed by an authorized key.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import crypto
from .errors import KeystoreError

SETUP = "setup"
USER = "user"
KEYSTORE_VERSION = 1
KEY_KINDS = ("kek", "db")
REVOKE_KINDS = ("key", "image")
_HEX_LEN = {"key": crypto.KEY_ID_LEN, "image": 32}


def _hex(value: object, nbytes: int | None = None) -> str:
    if not isinstance(value, str):
        raise KeystoreError("expected a hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise KeystoreError(f"not valid hex: {value[:20]!r}") from None
    if nbytes is not None and len(raw) != nbytes:
        raise KeystoreError(f"expected {nbytes} bytes of hex, got {len(raw)}")
    return raw.hex()


def _key_message(kind: str, raw_pub: bytes) -> bytes:
    return b"HEIMDALL-KEYREC-v1|" + kind.encode() + b"|" + raw_pub


def _dbx_message(kind: str, value: bytes) -> bytes:
    return b"HEIMDALL-DBX-v1|" + kind.encode() + b"|" + value


@dataclass
class Entry:
    value: str  # hex: raw public key (kek/db) or key id / image hash (dbx)
    signer: str | None = None  # hex key id of the signing authority
    signature: str | None = None  # hex Ed25519 signature

    def to_json(self) -> dict:
        data = {"value": self.value}
        if self.signer:
            data["signer"] = self.signer
        if self.signature:
            data["signature"] = self.signature
        return data

    @classmethod
    def from_json(cls, data: dict, nbytes: int | None = None) -> "Entry":
        signer = data.get("signer")
        signature = data.get("signature")
        return cls(
            value=_hex(data["value"], nbytes),
            signer=_hex(signer, crypto.KEY_ID_LEN) if signer else None,
            signature=_hex(signature) if signature else None,
        )


@dataclass
class Keystore:
    mode: str = SETUP
    pk: str | None = None  # hex raw public key
    kek: list[Entry] = field(default_factory=list)
    db: list[Entry] = field(default_factory=list)
    dbx_keys: list[Entry] = field(default_factory=list)
    dbx_images: list[Entry] = field(default_factory=list)

    # ------------------------------------------------------------ persistence
    @classmethod
    def load(cls, path: str | os.PathLike) -> "Keystore":
        try:
            raw = json.loads(Path(path).read_text("utf-8"))
        except FileNotFoundError:
            raise KeystoreError(f"keystore not found: {path}") from None
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise KeystoreError(f"corrupt keystore: {exc}") from None
        try:
            if raw["version"] != KEYSTORE_VERSION:
                raise KeystoreError("unsupported keystore version")
            mode = raw["mode"]
            if mode not in (SETUP, USER):
                raise KeystoreError("invalid keystore mode")
            pk = raw.get("pk")
            return cls(
                mode=mode,
                pk=_hex(pk, 32) if pk else None,
                kek=[Entry.from_json(e, 32) for e in raw["kek"]],
                db=[Entry.from_json(e, 32) for e in raw["db"]],
                dbx_keys=[
                    Entry.from_json(e, crypto.KEY_ID_LEN) for e in raw["dbx"]["keys"]
                ],
                dbx_images=[Entry.from_json(e, 32) for e in raw["dbx"]["images"]],
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise KeystoreError(f"malformed keystore: {exc!r}") from None

    @classmethod
    def load_or_new(cls, path: str | os.PathLike) -> "Keystore":
        return cls.load(path) if Path(path).exists() else cls()

    def save(self, path: str | os.PathLike) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": KEYSTORE_VERSION,
            "mode": self.mode,
            "pk": self.pk,
            "kek": [e.to_json() for e in self.kek],
            "db": [e.to_json() for e in self.db],
            "dbx": {
                "keys": [e.to_json() for e in self.dbx_keys],
                "images": [e.to_json() for e in self.dbx_images],
            },
        }
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", "utf-8")
        os.replace(tmp, target)

    # ------------------------------------------------------------ authorities
    def _pk_pub(self) -> Ed25519PublicKey:
        if not self.pk:
            raise KeystoreError("no PK enrolled")
        return crypto.public_from_raw(bytes.fromhex(self.pk))

    def _check_entry(
        self,
        label: str,
        entry: Entry,
        message: bytes,
        authorities: list[Ed25519PublicKey],
    ) -> None:
        if not entry.signature or not entry.signer:
            raise KeystoreError(f"unsigned {label} entry {entry.value[:16]}")
        signer = bytes.fromhex(entry.signer)
        signature = bytes.fromhex(entry.signature)
        for auth in authorities:
            if crypto.constant_time_equal(crypto.key_id(auth), signer) and crypto.verify(
                auth, signature, message
            ):
                return
        raise KeystoreError(f"invalid signature on {label} entry {entry.value[:16]}")

    def _valid_keks(self) -> list[Ed25519PublicKey]:
        pk = self._pk_pub()
        keks = []
        for entry in self.kek:
            raw = bytes.fromhex(entry.value)
            self._check_entry("KEK", entry, _key_message("kek", raw), [pk])
            keks.append(crypto.public_from_raw(raw))
        return keks

    def _authorities(self, kind: str) -> list[Ed25519PublicKey]:
        """Who may sign an update of ``kind`` ('kek', 'db' or 'dbx')."""
        pk = self._pk_pub()
        return [pk] if kind == "kek" else [pk, *self._valid_keks()]

    # -------------------------------------------------------------- validation
    def validate(self) -> None:
        """Verify the whole PK -> KEK -> db chain and the dbx. Raises KeystoreError."""
        if self.mode != USER:
            raise KeystoreError(
                "keystore is in SETUP MODE: secure boot is not enforced until a PK is enrolled"
            )
        keks = self._valid_keks()
        authorities = [self._pk_pub(), *keks]
        for entry in self.db:
            raw = bytes.fromhex(entry.value)
            self._check_entry("db", entry, _key_message("db", raw), authorities)
        for kind, entries in (("key", self.dbx_keys), ("image", self.dbx_images)):
            for entry in entries:
                msg = _dbx_message(kind, bytes.fromhex(entry.value))
                self._check_entry(f"dbx {kind}", entry, msg, authorities)

    def require_pk(self, pk_pub: Ed25519PublicKey) -> None:
        if not self.pk or not crypto.constant_time_equal(
            crypto.public_raw(pk_pub), bytes.fromhex(self.pk)
        ):
            raise KeystoreError("keystore PK differs from the supplied root key")

    # ----------------------------------------------------------------- updates
    def _sign_entry(
        self,
        entry: Entry,
        message: bytes,
        signer: Ed25519PrivateKey | None,
        authorities: list[Ed25519PublicKey],
        what: str,
    ) -> None:
        if signer is None:
            raise KeystoreError(
                f"REJECTED: keystore is in USER MODE, the {what} update must be signed "
                "by an authorized key"
            )
        signer_raw = crypto.public_raw(signer.public_key())
        if not any(
            crypto.constant_time_equal(crypto.public_raw(a), signer_raw)
            for a in authorities
        ):
            raise KeystoreError(
                f"REJECTED: key {crypto.key_id_of_raw(signer_raw).hex()} "
                f"is not authorized to update {what}"
            )
        entry.signer = crypto.key_id_of_raw(signer_raw).hex()
        entry.signature = crypto.sign(signer, message).hex()

    def enroll(
        self,
        kind: str,
        pub: Ed25519PublicKey,
        signer: Ed25519PrivateKey | None = None,
    ) -> None:
        """Add a KEK or db key. In user mode ``signer`` must be an authority."""
        if kind not in KEY_KINDS:
            raise KeystoreError(f"unknown key kind {kind!r}")
        raw = crypto.public_raw(pub)
        target = self.kek if kind == "kek" else self.db
        if any(e.value == raw.hex() for e in target):
            raise KeystoreError(f"{kind} key already enrolled")
        entry = Entry(raw.hex())
        if self.mode == USER:
            self.validate()
            self._sign_entry(
                entry, _key_message(kind, raw), signer, self._authorities(kind), kind
            )
        target.append(entry)

    def enroll_pk(self, pub: Ed25519PublicKey, pk_priv: Ed25519PrivateKey) -> None:
        """Set the PK, seal all setup-time entries with it, switch to user mode."""
        if self.mode != SETUP or self.pk:
            raise KeystoreError("a PK is already enrolled")
        raw = crypto.public_raw(pub)
        if not crypto.constant_time_equal(crypto.public_raw(pk_priv.public_key()), raw):
            raise KeystoreError("the signing key does not match the PK being enrolled")
        self.pk = raw.hex()
        authorities = [pub]
        for entry in self.kek:
            self._sign_entry(
                entry,
                _key_message("kek", bytes.fromhex(entry.value)),
                pk_priv,
                authorities,
                "kek",
            )
        for entry in self.db:
            self._sign_entry(
                entry,
                _key_message("db", bytes.fromhex(entry.value)),
                pk_priv,
                authorities,
                "db",
            )
        for kind, entries in (("key", self.dbx_keys), ("image", self.dbx_images)):
            for entry in entries:
                self._sign_entry(
                    entry,
                    _dbx_message(kind, bytes.fromhex(entry.value)),
                    pk_priv,
                    authorities,
                    "dbx",
                )
        self.mode = USER

    def revoke(
        self, kind: str, value: str, signer: Ed25519PrivateKey | None = None
    ) -> None:
        """Add a revoked key id (``kind='key'``) or image hash (``kind='image'``)."""
        if kind not in REVOKE_KINDS:
            raise KeystoreError(f"unknown revocation kind {kind!r}")
        value = _hex(value, _HEX_LEN[kind])
        target = self.dbx_keys if kind == "key" else self.dbx_images
        if any(e.value == value for e in target):
            raise KeystoreError("already revoked")
        entry = Entry(value)
        if self.mode == USER:
            self.validate()
            self._sign_entry(
                entry,
                _dbx_message(kind, bytes.fromhex(value)),
                signer,
                self._authorities("dbx"),
                "dbx",
            )
        target.append(entry)

    # ------------------------------------------------------------------ queries
    def db_public_key(self, key_id: bytes) -> Ed25519PublicKey | None:
        for entry in self.db:
            raw = bytes.fromhex(entry.value)
            if crypto.constant_time_equal(crypto.key_id_of_raw(raw), key_id):
                return crypto.public_from_raw(raw)
        return None

    def is_key_revoked(self, key_id: bytes) -> bool:
        return any(
            crypto.constant_time_equal(bytes.fromhex(e.value), key_id)
            for e in self.dbx_keys
        )

    def is_image_revoked(self, digest: bytes) -> bool:
        return any(
            crypto.constant_time_equal(bytes.fromhex(e.value), digest)
            for e in self.dbx_images
        )

    # ------------------------------------------------------------------ display
    def describe(self) -> str:
        user = self.mode == USER
        lines = [f"mode: {'USER MODE' if user else 'SETUP MODE'}"]
        pk_ok = False
        authorities: list[Ed25519PublicKey] = []
        if self.pk:
            pk = self._pk_pub()
            lines.append(f"PK   {crypto.key_id(pk).hex()}")
            authorities = [pk]
            pk_ok = True
        else:
            lines.append("PK   (not enrolled)")

        def status(label: str, entry: Entry, msg: bytes, auths: list) -> str:
            if not entry.signature:
                return "unsigned"
            try:
                self._check_entry(label, entry, msg, auths)
            except KeystoreError:
                return "INVALID"
            return "ok"

        kek_ok = bool(self.kek) and pk_ok
        valid_keks: list[Ed25519PublicKey] = []
        for entry in self.kek:
            raw = bytes.fromhex(entry.value)
            st = status("KEK", entry, _key_message("kek", raw), authorities)
            kek_ok = kek_ok and st == "ok"
            if st == "ok":
                valid_keks.append(crypto.public_from_raw(raw))
            lines.append(f"KEK  {crypto.key_id_of_raw(raw).hex()}  [{st}]")
        db_ok = bool(self.db) and pk_ok
        for entry in self.db:
            raw = bytes.fromhex(entry.value)
            st = status("db", entry, _key_message("db", raw), authorities + valid_keks)
            db_ok = db_ok and st == "ok"
            lines.append(f"db   {crypto.key_id_of_raw(raw).hex()}  [{st}]")
        lines.append(
            f"dbx  {len(self.dbx_keys)} revoked key(s), {len(self.dbx_images)} revoked image(s)"
        )
        mark = lambda ok: "\u2713" if ok else "\u2717"  # noqa: E731
        lines.append(
            f"chain: PK {mark(pk_ok)} \u2192 KEK {mark(kek_ok)} \u2192 db {mark(db_ok)}"
        )
        return "\n".join(lines)
