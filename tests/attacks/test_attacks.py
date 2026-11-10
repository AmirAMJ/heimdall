"""Attack suite. Every test PASSING means the attack was REFUSED by the boot chain."""

from dataclasses import replace

import pytest

from heimdall import chain, crypto, image, rom
from heimdall.errors import HeimdallError
from heimdall.image import Stage
from heimdall.keystore import Entry, Keystore

pytestmark = pytest.mark.attacks


def _halts(env, **kw):
    ran = []
    with pytest.raises(chain.BootHalt):
        env.boot(executor=lambda s, p: ran.append(s), **kw)
    return ran


def test_bit_flip_in_kernel_payload(env):
    data = bytearray(env.images["kernel"].read_bytes())
    data[60] ^= 0x01
    env.images["kernel"].write_bytes(bytes(data))
    assert "kernel" not in _halts(env)


def test_bit_flip_in_header_counter(env):
    data = bytearray(env.images["kernel"].read_bytes())
    data[8] ^= 0x01  # counter field
    env.images["kernel"].write_bytes(bytes(data))
    assert "kernel" not in _halts(env)


def test_image_signed_by_attacker_key(env):
    env.images["kernel"] = env.make_image("kernel", signer="evil")
    assert "kernel" not in _halts(env)


def test_attacker_forges_db_key_id_but_signs_with_own_key(env):
    forged = image.build_image(b"pwned", Stage.KERNEL, 1)
    forged = replace(forged, key_id=crypto.key_id(env.pub("db")), signature=b"")
    sig = crypto.sign(env.priv("evil"), forged.signed_bytes())
    env.images["kernel"].write_bytes(replace(forged, signature=sig).to_bytes())
    assert "kernel" not in _halts(env)


def test_unsigned_image(env):
    env.images["kernel"] = env.make_image("kernel", signer=None)
    assert "kernel" not in _halts(env)


def test_downgrade_to_older_signed_kernel(env):
    env.images["kernel"] = env.make_image("kernel", counter=2, payload=b"kernel v2")
    env.boot()  # boots fine, counter 2 committed
    old = env.make_image("kernel", counter=1, payload=b"kernel v1 (vulnerable)")
    assert "kernel" not in _halts(env, kernel=old)
    assert rom.load_fuses(env.fuses).counters["kernel"] == 2


def test_header_length_lie_is_rejected(env):
    data = bytearray(env.images["kernel"].read_bytes())
    data[12:16] = (len(data) + 50).to_bytes(4, "little")  # claim a longer payload
    env.images["kernel"].write_bytes(bytes(data))
    assert "kernel" not in _halts(env)


def test_trailing_bytes_appended(env):
    env.images["kernel"].write_bytes(env.images["kernel"].read_bytes() + b"EXTRA")
    assert "kernel" not in _halts(env)


def test_revoked_signing_key_beats_valid_signature(env):
    ks = Keystore.load(env.keystore)
    ks.revoke("key", crypto.key_id(env.pub("db")).hex(), env.priv("kek"))
    ks.save(env.keystore)
    assert _halts(env) == []  # BL1 itself is signed by the revoked key


def test_revoked_image_hash_beats_valid_signature(env):
    ks = Keystore.load(env.keystore)
    ks.revoke("image", crypto.sha256_file(env.images["kernel"]).hex(), env.priv("pk"))
    ks.save(env.keystore)
    assert _halts(env) == ["bl1", "bl2"]  # only the revoked kernel is refused


def test_stage_confusion_bl2_image_in_bl1_slot(env):
    assert _halts(env, bl1=env.images["bl2"]) == []


def test_attacker_supplies_their_own_root_key(env):
    assert _halts(env, pk_pub=env.pub("evil")) == []


def test_attacker_adds_unsigned_db_key_to_keystore(env):
    ks = Keystore.load(env.keystore)
    ks.db.append(Entry(crypto.public_raw(env.pub("evil")).hex()))
    ks.save(env.keystore)
    env.images["kernel"] = env.make_image("kernel", signer="evil")
    assert _halts(env) == []  # the whole keystore is rejected, nothing runs


def test_attacker_swaps_in_their_own_keystore_in_setup_mode(env):
    evil = Keystore()
    evil.enroll("db", env.pub("evil"))  # setup mode: no signature needed
    evil.save(env.keystore)
    env.images["kernel"] = env.make_image("kernel", signer="evil")
    assert _halts(env) == []  # setup mode never boots


def test_toctou_file_swapped_after_read_does_not_change_what_runs(env):
    """The loader reads each file once; swapping it afterwards must have no effect."""
    evil = env.make_image("kernel", payload=b"EVIL", signer="evil")
    original = env.images["kernel"].read_bytes()

    def swapping_reader(path):
        data = chain.read_once(path)
        if str(path) == str(env.images["kernel"]):
            env.images["kernel"].write_bytes(evil.read_bytes())  # attacker swaps now
        return data

    ran = []
    env.boot(reader=swapping_reader, executor=lambda s, p: ran.append((s, p)))
    assert ran[-1] == ("kernel", b"kernel running")
    assert env.images["kernel"].read_bytes() != original  # the swap did happen
