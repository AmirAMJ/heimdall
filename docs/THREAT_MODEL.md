# Threat model

## Assets

| Asset | Why it matters |
|---|---|
| Private keys (PK, KEK, db) | whoever holds them decides what boots |
| Root-key hash in the fuses | anchors all trust; cannot be changed after provisioning |
| Anti-rollback counters | stop old, vulnerable images from booting again |
| Boot images (BL1, BL2, kernel) | the code that actually runs |
| Keystore and dbx | decide which keys and images are trusted or revoked |
| Event log and PCR | evidence of what actually booted |

## Trust assumptions

- The ROM code and the fuse file are immutable to the attacker (except that counters can only go up, via the ROM).
- Private keys stay offline and encrypted; compromising one is handled by revocation, not prevented here.
- The keystore lives in protected storage (see README, *Known limitations*).

## Attacker capabilities

The attacker can read and modify any boot image on disk, supply their own files and keys on the command line,
replay old signed images, and swap files while the system is running. The attacker cannot modify the ROM or lower a counter.

## Threats and defenses

| ID | Attack | Defense | Test |
|---|---|---|---|
| T1 | Bit-flip in a boot stage | payload hash and signature | `test_bit_flip_in_kernel_payload` |
| T2 | Image signed by an unknown or attacker key | key must chain PK → KEK → db | `test_image_signed_by_attacker_key` |
| T3 | Forged key id with an attacker signature | signature verified against the *enrolled* key | `test_attacker_forges_db_key_id_but_signs_with_own_key` |
| T4 | Downgrade to an old signed image | per-stage counters in fuses | `test_downgrade_to_older_signed_kernel` |
| T5 | Use of a compromised key or known-bad image | dbx checked first, wins over db | `test_revoked_*` |
| T6 | Malformed header (length lies, trailing bytes, bad magic) | strict parser, fuzzed | `test_header_length_lie_is_rejected`, `tests/test_fuzz_parser.py` |
| T7 | Stage confusion (BL2 image in BL1 slot) | stage id inside the signed header | `test_stage_confusion_bl2_image_in_bl1_slot` |
| T8 | Wrong root key handed to the ROM | hash compared with the fuse | `test_attacker_supplies_their_own_root_key` |
| T9 | Tampered or attacker-made keystore | every entry signature verified each boot; setup mode never boots | `test_attacker_adds_unsigned_db_key_to_keystore`, `test_attacker_swaps_in_their_own_keystore_in_setup_mode` |
| T10 | TOCTOU file swap | single read, verified bytes are executed | `test_toctou_file_swapped_after_read_does_not_change_what_runs` |
| T11 | Timing side channel on hash comparison | `hmac.compare_digest` in one place | code review rule |
| T12 | Shell injection through file names in `efi-sign` | argument lists, `shell=False` | `tests/test_efi.py` |

## Out of scope

Physical attacks, fault injection, side channels on the signing machine, hardware root-of-trust tamper resistance,
and attacks on the real UEFI firmware.
