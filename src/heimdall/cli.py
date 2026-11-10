"""Command-line interface.

No security logic lives here: this module parses arguments and calls the others.
Exit codes: 0 success, 1 verification/policy failure, 2 usage error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__, chain, crypto, efi, image, measure, rom
from .errors import HeimdallError, KeystoreError
from .keystore import SETUP, Keystore

PASSPHRASE_ENV = "HEIMDALL_PASSPHRASE"
DEFAULT_STATE = "state"
DEFAULT_KEYS = "keys"


# --------------------------------------------------------------------- helpers
def configure_logging(log_file: str | None = None) -> None:
    logger = logging.getLogger("heimdall")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)
    if log_file:
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)


def _state(args: argparse.Namespace, name: str) -> Path:
    return Path(args.state_dir) / name


def _passphrase_for_use(path: str) -> bytes | None:
    if not crypto.is_encrypted(path):
        return None
    env = os.environ.get(PASSPHRASE_ENV)
    if env:
        return env.encode()
    return getpass.getpass(f"Passphrase for {path}: ").encode()


def _new_passphrase() -> bytes:
    env = os.environ.get(PASSPHRASE_ENV)
    if env:
        return env.encode()
    first = getpass.getpass("New passphrase: ")
    if not first:
        raise HeimdallError("empty passphrase")
    if getpass.getpass("Repeat passphrase: ") != first:
        raise HeimdallError("passphrases do not match")
    return first.encode()


def _load_private(path: str):
    return crypto.load_private_key(path, _passphrase_for_use(path))


def _optional_signer(path: str | None):
    return _load_private(path) if path else None


# -------------------------------------------------------------------- commands
def cmd_version(args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    print(crypto.sha256_file(args.file).hex())
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    passphrase = _new_passphrase() if args.encrypt else None
    priv, pub = crypto.generate_keypair(args.name, args.out_dir, passphrase)
    print(f"private key: {priv}")
    print(f"public key:  {pub}")
    return 0


def cmd_build_image(args: argparse.Namespace) -> int:
    payload = Path(args.payload).read_bytes()
    built = image.build_image(payload, image.STAGE_BY_NAME[args.stage], args.counter)
    Path(args.out).write_bytes(built.to_bytes())
    print(f"built unsigned {args.stage} image: {args.out} ({len(built.to_bytes())} bytes)")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    parsed = image.parse(Path(args.image).read_bytes())
    signed = image.sign_image(parsed, _load_private(args.key))
    out = args.out or args.image
    Path(out).write_bytes(signed.to_bytes())
    print(f"signed {out} (key id {signed.key_id.hex()})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        parsed = image.parse(Path(args.image).read_bytes())
        image.verify_image(parsed, crypto.load_public_key(args.pub))
    except HeimdallError as exc:
        print(f"INVALID: {type(exc).__name__}: {exc}")
        return 1
    print(f"VALID (stage {parsed.stage.name}, counter {parsed.counter}, key {parsed.key_id.hex()})")
    return 0


def cmd_provision(args: argparse.Namespace) -> int:
    fuses = rom.provision(_state(args, "fuses.json"), crypto.load_public_key(args.pk_pub))
    print(f"fuses programmed: pk_hash={fuses.pk_hash}")
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    path = _state(args, "keystore.json")
    keystore = Keystore.load_or_new(path)
    pub = crypto.load_public_key(args.pub)
    signer = _optional_signer(args.signed_by)
    if args.kind == "pk":
        if signer is None:
            raise KeystoreError("enrolling the PK needs --signed-by <pk private key>")
        keystore.enroll_pk(pub, signer)
    else:
        keystore.enroll(args.kind, pub, signer)
    keystore.save(path)
    print(f"enrolled {args.kind} {crypto.key_id(pub).hex()}; keystore is now {keystore.mode.upper()} MODE")
    return 0


def cmd_keystore(args: argparse.Namespace) -> int:
    print(Keystore.load_or_new(_state(args, "keystore.json")).describe())
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    keystore = Keystore.load_or_new(_state(args, "keystore.json"))
    print("SETUP MODE" if keystore.mode == SETUP else "USER MODE")
    try:
        fuses = rom.load_fuses(_state(args, "fuses.json"))
        print(f"fuses: programmed (pk_hash {fuses.pk_hash[:16]}..., counters {fuses.counters})")
    except HeimdallError:
        print("fuses: not programmed")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    path = _state(args, "keystore.json")
    keystore = Keystore.load(path)
    signer = _optional_signer(args.signed_by)
    if args.image_hash:
        keystore.revoke("image", args.image_hash, signer)
    else:
        keystore.revoke("key", args.key_id, signer)
    keystore.save(path)
    print("revoked")
    return 0


def cmd_boot(args: argparse.Namespace) -> int:
    events_path = _state(args, "events.json") if args.measure else None
    try:
        result = chain.boot(
            bl1=args.bl1,
            bl2=args.bl2,
            kernel=args.kernel,
            pk_pub=crypto.load_public_key(args.pk_pub),
            fuses_path=_state(args, "fuses.json"),
            keystore_path=_state(args, "keystore.json"),
            events_path=events_path,
        )
    except chain.BootHalt:
        return 1  # already logged
    if args.measure:
        print(f"final PCR: {result.pcr.hex()}")
    return 0


def cmd_replay_log(args: argparse.Namespace) -> int:
    path = args.events or _state(args, "events.json")
    try:
        pcr = measure.verify_event_log(path, args.expect)
    except HeimdallError as exc:
        print(f"MISMATCH: {exc}")
        return 1
    print(f"replayed PCR: {pcr.hex()}")
    return 0


def _current_pcr(args: argparse.Namespace) -> bytes:
    return measure.verify_event_log(args.events or _state(args, "events.json"))


def cmd_seal(args: argparse.Namespace) -> int:
    secret = Path(args.secret_file).read_bytes() if args.secret_file else args.secret.encode()
    blob = measure.seal(secret, _current_pcr(args))
    out = Path(args.out or _state(args, "sealed.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(blob, indent=2) + "\n", "utf-8")
    print(f"sealed to the current boot state: {out}")
    return 0


def cmd_unseal(args: argparse.Namespace) -> int:
    blob_path = Path(args.blob or _state(args, "sealed.json"))
    try:
        blob = json.loads(blob_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HeimdallError(f"cannot read sealed blob: {exc}") from exc
    secret = measure.unseal(blob, _current_pcr(args))
    sys.stdout.write(secret.decode("utf-8", "replace") + "\n")
    return 0


def cmd_efi_sign(args: argparse.Namespace) -> int:
    efi.sign_efi(args.infile, args.out, args.key, args.cert)
    print(f"signed EFI binary: {args.out}")
    return 0


def cmd_efi_verify(args: argparse.Namespace) -> int:
    print(efi.verify_efi(args.infile, args.cert))
    return 0


# ---------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="heimdall",
        description="Heimdall: a Python reference implementation of the secure-boot chain of trust.",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("HEIMDALL_STATE", DEFAULT_STATE),
        help="where fuses.json, keystore.json, events.json and sealed.json live",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    def add(name: str, func, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.set_defaults(func=func)
        return p

    add("version", cmd_version, "print the version")

    p = add("hash", cmd_hash, "print the SHA-256 of a file")
    p.add_argument("file")

    p = add("keygen", cmd_keygen, "generate an Ed25519 key pair")
    p.add_argument("--name", required=True)
    p.add_argument("--out-dir", default=DEFAULT_KEYS)
    p.add_argument("--encrypt", action="store_true", help="protect the private key with a passphrase")

    p = add("build-image", cmd_build_image, "wrap a payload in an unsigned image")
    p.add_argument("--payload", required=True)
    p.add_argument("--stage", required=True, choices=sorted(image.STAGE_BY_NAME))
    p.add_argument("--counter", type=int, default=1)
    p.add_argument("--out", required=True)

    p = add("sign", cmd_sign, "sign an image with a private key")
    p.add_argument("--key", required=True)
    p.add_argument("--out", help="write here instead of signing in place")
    p.add_argument("image")

    p = add("verify", cmd_verify, "verify an image against a public key")
    p.add_argument("--pub", required=True)
    p.add_argument("image")

    p = add("provision", cmd_provision, "burn the root-key hash into the fuses (once)")
    p.add_argument("--pk-pub", required=True)

    p = add("enroll", cmd_enroll, "enroll a PK, KEK or db key")
    p.add_argument("kind", choices=["pk", "kek", "db"])
    p.add_argument("--pub", required=True)
    p.add_argument("--signed-by", help="private key of an authorized signer")

    p = add("keystore", cmd_keystore, "show the key database")
    p.add_argument("action", choices=["show"])

    add("status", cmd_status, "show setup/user mode and fuse state")

    p = add("revoke", cmd_revoke, "add an entry to the dbx revocation list")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--image-hash", help="SHA-256 (hex) of a whole image file")
    group.add_argument("--key-id", help="8-byte key id (hex)")
    p.add_argument("--signed-by", help="private key of an authorized signer")

    p = add("boot", cmd_boot, "run the verified boot chain")
    for stage in ("bl1", "bl2", "kernel"):
        p.add_argument(f"--{stage}", required=True)
    p.add_argument("--pk-pub", required=True)
    p.add_argument("--measure", action="store_true", help="record PCR and event log")
    p.add_argument("--log-file")

    p = add("replay-log", cmd_replay_log, "replay the event log and check the PCR")
    p.add_argument("events", nargs="?")
    p.add_argument("--expect", help="expected final PCR (hex)")

    p = add("seal", cmd_seal, "seal a secret to the current boot state")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--secret")
    group.add_argument("--secret-file")
    p.add_argument("--events")
    p.add_argument("--out")

    p = add("unseal", cmd_unseal, "unseal a secret (only works in the same boot state)")
    p.add_argument("--events")
    p.add_argument("--blob")

    p = add("efi-sign", cmd_efi_sign, "sign an EFI binary with sbsign")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--cert", required=True)

    p = add("efi-verify", cmd_efi_verify, "verify an EFI binary with sbverify")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--cert", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(getattr(args, "log_file", None))
    try:
        return args.func(args)
    except chain.BootHalt:
        return 1
    except (HeimdallError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
