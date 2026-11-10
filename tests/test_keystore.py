import pytest

from heimdall import crypto
from heimdall.errors import KeystoreError
from heimdall.keystore import SETUP, USER, Keystore


@pytest.fixture
def keys(tmp_path):
    out = {}
    for n in ("pk", "kek", "db", "db2", "rogue"):
        p, q = crypto.generate_keypair(n, tmp_path)
        out[n] = (crypto.load_private_key(p), crypto.load_public_key(q))
    return out


@pytest.fixture
def sealed(keys):
    ks = Keystore()
    ks.enroll("kek", keys["kek"][1])
    ks.enroll("db", keys["db"][1])
    ks.enroll_pk(keys["pk"][1], keys["pk"][0])
    return ks


def test_setup_mode_allows_unsigned_updates_then_seals(keys):
    ks = Keystore()
    assert ks.mode == SETUP
    ks.enroll("kek", keys["kek"][1])  # unsigned, allowed
    assert ks.kek[0].signature is None
    with pytest.raises(KeystoreError, match="SETUP MODE"):
        ks.validate()
    ks.enroll("db", keys["db"][1])
    ks.enroll_pk(keys["pk"][1], keys["pk"][0])
    assert ks.mode == USER
    assert all(e.signature for e in ks.kek + ks.db)
    ks.validate()


def test_user_mode_rejects_unsigned_update(sealed, keys):
    with pytest.raises(KeystoreError, match="USER MODE"):
        sealed.enroll("db", keys["db2"][1])


def test_user_mode_rejects_unauthorized_signer(sealed, keys):
    with pytest.raises(KeystoreError, match="not authorized"):
        sealed.enroll("db", keys["db2"][1], keys["rogue"][0])


def test_kek_can_enroll_db_but_not_kek(sealed, keys):
    sealed.enroll("db", keys["db2"][1], keys["kek"][0])
    sealed.validate()
    with pytest.raises(KeystoreError, match="not authorized"):
        sealed.enroll("kek", keys["rogue"][1], keys["kek"][0])
    sealed.enroll("kek", keys["rogue"][1], keys["pk"][0])  # only the PK may


def test_pk_can_sign_db_directly(sealed, keys):
    sealed.enroll("db", keys["db2"][1], keys["pk"][0])
    sealed.validate()


def test_enroll_pk_requires_matching_private_key_and_setup_mode(keys, sealed):
    with pytest.raises(KeystoreError, match="does not match"):
        Keystore().enroll_pk(keys["pk"][1], keys["rogue"][0])
    with pytest.raises(KeystoreError, match="already enrolled"):
        sealed.enroll_pk(keys["pk"][1], keys["pk"][0])


def test_duplicate_enroll_rejected(sealed, keys):
    with pytest.raises(KeystoreError, match="already enrolled"):
        sealed.enroll("db", keys["db"][1], keys["pk"][0])


def test_save_load_roundtrip(sealed, tmp_path):
    path = tmp_path / "state" / "ks.json"
    sealed.save(path)
    loaded = Keystore.load(path)
    assert loaded == sealed
    loaded.validate()


def test_tampered_keystore_detected(sealed, keys, tmp_path):
    sealed.db[0].value = crypto.public_raw(keys["rogue"][1]).hex()  # swap the db key
    with pytest.raises(KeystoreError, match="invalid signature"):
        sealed.validate()


def test_unsigned_entry_added_to_user_keystore_detected(sealed, keys):
    from heimdall.keystore import Entry

    sealed.db.append(Entry(crypto.public_raw(keys["rogue"][1]).hex()))
    with pytest.raises(KeystoreError, match="unsigned"):
        sealed.validate()


def test_dbx_signed_and_queried(sealed, keys):
    kid = crypto.key_id(keys["db"][1])
    sealed.revoke("key", kid.hex(), keys["kek"][0])
    sealed.revoke("image", "ab" * 32, keys["pk"][0])
    sealed.validate()
    assert sealed.is_key_revoked(kid)
    assert sealed.is_image_revoked(bytes.fromhex("ab" * 32))
    assert not sealed.is_image_revoked(bytes(32))
    with pytest.raises(KeystoreError, match="USER MODE"):
        sealed.revoke("image", "cd" * 32)
    with pytest.raises(KeystoreError):
        sealed.revoke("image", "zz")
    with pytest.raises(KeystoreError):
        sealed.revoke("key", "ab" * 32)  # wrong length for a key id


def test_db_public_key_lookup(sealed, keys):
    kid = crypto.key_id(keys["db"][1])
    assert crypto.public_raw(sealed.db_public_key(kid)) == crypto.public_raw(keys["db"][1])
    assert sealed.db_public_key(bytes(8)) is None


def test_require_pk(sealed, keys):
    sealed.require_pk(keys["pk"][1])
    with pytest.raises(KeystoreError):
        sealed.require_pk(keys["rogue"][1])


def test_load_errors(tmp_path):
    with pytest.raises(KeystoreError, match="not found"):
        Keystore.load(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(KeystoreError, match="corrupt"):
        Keystore.load(bad)
    bad.write_text('{"version": 1}')
    with pytest.raises(KeystoreError, match="malformed"):
        Keystore.load(bad)


def test_describe_shows_chain(sealed):
    text = sealed.describe()
    assert "USER MODE" in text
    assert "PK \u2713 \u2192 KEK \u2713 \u2192 db \u2713" in text


def test_describe_setup_mode():
    assert "SETUP MODE" in Keystore().describe()
