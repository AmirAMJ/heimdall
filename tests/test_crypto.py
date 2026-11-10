import hashlib
import os
import stat
import sys

import pytest

from heimdall import crypto
from heimdall.errors import HeimdallError


def test_sha256_file_matches_hashlib(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello\n" * 50_000)  # bigger than one chunk
    assert crypto.sha256_file(f) == hashlib.sha256(f.read_bytes()).digest()


def test_tamper_changes_hash():
    assert crypto.sha256_bytes(b"hello") != crypto.sha256_bytes(b"hellp")


def test_constant_time_equal():
    assert crypto.constant_time_equal(b"abc", b"abc")
    assert not crypto.constant_time_equal(b"abc", b"abd")
    assert not crypto.constant_time_equal(b"abc", b"abcd")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_private_key_is_0600(tmp_path):
    priv, _ = crypto.generate_keypair("k", tmp_path)
    assert stat.S_IMODE(os.stat(priv).st_mode) == 0o600


def test_keygen_refuses_overwrite(tmp_path):
    crypto.generate_keypair("k", tmp_path)
    with pytest.raises(HeimdallError):
        crypto.generate_keypair("k", tmp_path)


def test_signature_good_tampered_and_wrong_key(tmp_path):
    p1, _ = crypto.generate_keypair("a", tmp_path)
    _, pub2 = crypto.generate_keypair("b", tmp_path)
    priv = crypto.load_private_key(p1)
    pub = priv.public_key()
    sig = crypto.sign(priv, b"message")
    assert crypto.verify(pub, sig, b"message")
    assert not crypto.verify(pub, sig, b"messagf")
    assert not crypto.verify(crypto.load_public_key(pub2), sig, b"message")


def test_encrypted_key_roundtrip_and_wrong_passphrase(tmp_path):
    priv_path, _ = crypto.generate_keypair("e", tmp_path, passphrase=b"correct horse")
    assert priv_path.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert crypto.is_encrypted(priv_path)
    assert crypto.load_private_key(priv_path, b"correct horse")
    with pytest.raises(HeimdallError):
        crypto.load_private_key(priv_path, b"wrong")
    with pytest.raises(HeimdallError):
        crypto.load_private_key(priv_path)


def test_key_id_length_and_stability(tmp_path):
    _, pub_path = crypto.generate_keypair("k", tmp_path)
    pub = crypto.load_public_key(pub_path)
    assert len(crypto.key_id(pub)) == crypto.KEY_ID_LEN
    assert crypto.key_id(pub) == crypto.key_id_of_raw(crypto.public_raw(pub))


def test_load_public_key_rejects_garbage(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a key")
    with pytest.raises(HeimdallError):
        crypto.load_public_key(bad)
