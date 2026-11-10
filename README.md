# Heimdall

[![CI](https://github.com/AmirAMJ/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/AmirAMJ/heimdall/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

**The watchman of your boot chain.** Heimdall is a small, readable Python reference implementation of the
secure-boot chain of trust: signed images, a PK → KEK → db/dbx key hierarchy, anti-rollback counters and
measured boot with a simulated TPM. It is built to be *learned from*: every concept has a module, a test and an attack.

> **Scope:** this is an educational simulator. A real boot ROM is not written in Python. Heimdall shows the
> logic of secure boot and ships a bridge (`efi-sign`) to real UEFI tooling. Do not use it to protect real hardware.

## Quickstart

```bash
git clone https://github.com/AmirAMJ/heimdall && cd heimdall
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
bash scripts/demo.sh        # the whole story in ~30 lines of output
pytest                      # 99 tests, including the attack suite
```

## What it does

```
fuses.json (hash of PK) ──► ROM ──► BL1 ──► BL2 ──► Kernel
                             │        each stage verifies the next:
                             │        parse → dbx → db key → signature → rollback → measure → run
                             └─ keystore.json: PK → KEK → db, plus dbx revocations
```

| Feature | Where |
|---|---|
| Ed25519 signed images with a strict, fuzzed parser | `image.py`, `tests/test_fuzz_parser.py` |
| Root of trust in one-time-programmable "fuses" | `rom.py` |
| PK → KEK → db hierarchy, setup/user mode, dbx revocation | `keystore.py`, `policy.py` |
| Per-stage anti-rollback counters | `policy.py`, `rom.py` |
| Read-once loading (no TOCTOU), fail-closed halts | `chain.py` |
| Measured boot: PCR extend, event log, replay, sealing | `measure.py` |
| Bridge to real `sbsign` / `sbverify` | `efi.py` |

## CLI

```
heimdall keygen --name db [--encrypt]            generate an Ed25519 key pair (private key chmod 600)
heimdall build-image --payload P --stage bl1|bl2|kernel --counter N --out F
heimdall sign --key keys/db.key.pem F            sign an image;  heimdall verify --pub keys/db.pub.pem F
heimdall provision --pk-pub keys/pk.pub.pem      burn the root-key hash into the fuses (once)
heimdall enroll kek|db|pk --pub P [--signed-by KEY]
heimdall keystore show | status                  inspect the key database and fuse state
heimdall revoke --image-hash H | --key-id ID --signed-by KEY
heimdall boot --bl1 A --bl2 B --kernel C --pk-pub PK [--measure]
heimdall replay-log | seal --secret S | unseal   measured boot and sealing
heimdall efi-sign / efi-verify                   real UEFI signing through sbsigntool
```

Global option: `--state-dir DIR` (default `state/`). Encrypted keys read their passphrase from a prompt, or from
`HEIMDALL_PASSPHRASE` for scripts (note that environment variables are visible to other processes of the same user).

## Attack → defense

Run `pytest -m attacks -v`: every PASSED line means the attack was **refused**.

| Attack | Defense |
|---|---|
| Flip a bit in a stage | payload hash + signature check |
| Forge a header field (counter, length, key id) | header is covered by the signature; strict parser |
| Image signed by an unknown or attacker key | key must be in `db`, chained to the PK |
| Unsigned image or unsigned keystore entry | refused; keystore is validated on every boot |
| Downgrade to an older signed image | per-stage anti-rollback counters in fuses |
| Revoked key or image | `dbx` is checked first and always wins |
| Swap the BL2 image into the BL1 slot | stage id is part of the signed header |
| Hand the ROM a different root key | hash must match the fuse |
| Replace the keystore with one made in setup mode | setup mode never boots |
| Swap a file between verify and run (TOCTOU) | each file is read once; the verified bytes are what runs |

## Known limitations

- The keystore and fuse files must live in storage the attacker cannot write (as on real hardware, where they sit in
  protected flash). Heimdall signs keystore entries but cannot stop an attacker who can delete or roll back the whole file.
- Measured boot compares against a recorded PCR; real systems use TPM quotes signed by a hardware key.
- Ed25519 only. UEFI itself uses RSA/X.509; `efi-sign` covers that side through `sbsigntool`.

## Project layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md). Licensed under the MIT License.
