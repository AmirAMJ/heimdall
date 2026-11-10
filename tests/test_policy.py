import pytest

from heimdall import crypto, policy
from heimdall.errors import PolicyError
from heimdall.keystore import Keystore


@pytest.fixture
def ks(tmp_path):
    p, q = crypto.generate_keypair("pk", tmp_path)
    ks = Keystore()
    ks.enroll_pk(crypto.load_public_key(q), crypto.load_private_key(p))
    ks.revoke("key", "11" * 8, crypto.load_private_key(p))
    ks.revoke("image", "22" * 32, crypto.load_private_key(p))
    return ks


def test_revoked_key_and_image(ks):
    with pytest.raises(PolicyError, match="signing key"):
        policy.check_revocation(ks, bytes.fromhex("11" * 8), bytes(32))
    with pytest.raises(PolicyError, match="image"):
        policy.check_revocation(ks, bytes(8), bytes.fromhex("22" * 32))
    policy.check_revocation(ks, bytes(8), bytes(32))


def test_rollback():
    policy.check_rollback("kernel", 2, 2)
    policy.check_rollback("kernel", 3, 2)
    with pytest.raises(PolicyError, match=r"counter 1 < fuse counter 2"):
        policy.check_rollback("kernel", 1, 2)
