import json

import pytest

from heimdall import crypto, rom
from heimdall.errors import PolicyError, VerificationError


@pytest.fixture
def pks(tmp_path):
    a = crypto.load_public_key(crypto.generate_keypair("a", tmp_path)[1])
    b = crypto.load_public_key(crypto.generate_keypair("b", tmp_path)[1])
    return a, b


def test_provision_once(tmp_path, pks):
    path = tmp_path / "state" / "fuses.json"
    fuses = rom.provision(path, pks[0])
    assert fuses.pk_hash == crypto.key_hash(pks[0]).hex()
    assert fuses.counters == {"bl1": 0, "bl2": 0, "kernel": 0}
    with pytest.raises(PolicyError, match="already programmed"):
        rom.provision(path, pks[1])
    assert rom.load_fuses(path).pk_hash == fuses.pk_hash  # unchanged


def test_verify_root_key(tmp_path, pks):
    fuses = rom.provision(tmp_path / "f.json", pks[0])
    rom.verify_root_key(fuses, pks[0])
    with pytest.raises(VerificationError, match="MISMATCH"):
        rom.verify_root_key(fuses, pks[1])


def test_counters_only_go_up(tmp_path, pks):
    path = tmp_path / "f.json"
    rom.provision(path, pks[0])
    rom.commit_counters(path, {"kernel": 5})
    assert rom.load_fuses(path).counters["kernel"] == 5
    rom.commit_counters(path, {"kernel": 2})  # attempt to lower: ignored
    assert rom.load_fuses(path).counters["kernel"] == 5
    with pytest.raises(PolicyError):
        rom.commit_counters(path, {"nope": 1})


def test_load_errors(tmp_path):
    with pytest.raises(PolicyError, match="not programmed"):
        rom.load_fuses(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("garbage")
    with pytest.raises(PolicyError, match="corrupt"):
        rom.load_fuses(bad)
    bad.write_text(json.dumps({"version": 1, "pk_hash": "zz", "counters": {}}))
    with pytest.raises(PolicyError, match="malformed"):
        rom.load_fuses(bad)
