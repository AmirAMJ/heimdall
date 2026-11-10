import hashlib

import pytest

from heimdall import measure
from heimdall.errors import PolicyError, VerificationError
from heimdall.measure import Event, Pcr


def test_pcr_extend_known_vector():
    m = hashlib.sha256(b"bl1").digest()
    expected = hashlib.sha256(bytes(32) + m).digest()
    pcr = Pcr()
    assert pcr.extend(m) == expected == pcr.value


def test_extend_order_matters():
    a, b = hashlib.sha256(b"a").digest(), hashlib.sha256(b"b").digest()
    p1, p2 = Pcr(), Pcr()
    p1.extend(a), p1.extend(b)
    p2.extend(b), p2.extend(a)
    assert p1.value != p2.value


def test_extend_rejects_wrong_length():
    with pytest.raises(ValueError):
        Pcr().extend(b"short")


def _events():
    return [Event(n, hashlib.sha256(n.encode()).hexdigest()) for n in ("bl1", "bl2", "kernel")]


def test_event_log_roundtrip_and_mismatch(tmp_path):
    events = _events()
    path = tmp_path / "events.json"
    measure.save_event_log(path, events, measure.replay(events))
    assert measure.verify_event_log(path) == measure.replay(events)
    path.write_text(path.read_text().replace(events[1].sha256, events[0].sha256))
    with pytest.raises(VerificationError, match="MISMATCH"):
        measure.verify_event_log(path)


def test_expect_argument(tmp_path):
    events = _events()
    path = tmp_path / "e.json"
    measure.save_event_log(path, events, measure.replay(events))
    measure.verify_event_log(path, expect=measure.replay(events).hex())
    with pytest.raises(VerificationError):
        measure.verify_event_log(path, expect="00" * 32)


def test_malformed_event_log(tmp_path):
    bad = tmp_path / "e.json"
    bad.write_text("{}")
    with pytest.raises(VerificationError, match="malformed"):
        measure.load_event_log(bad)
    with pytest.raises(VerificationError, match="not found"):
        measure.load_event_log(tmp_path / "missing.json")


def test_seal_unseal_same_and_different_pcr():
    pcr1 = hashlib.sha256(b"state-1").digest()
    pcr2 = hashlib.sha256(b"state-2").digest()
    blob = measure.seal(b"launch-codes", pcr1)
    assert measure.unseal(blob, pcr1) == b"launch-codes"
    with pytest.raises(PolicyError, match="PCR mismatch"):
        measure.unseal(blob, pcr2)
    with pytest.raises(PolicyError, match="malformed"):
        measure.unseal({}, pcr1)
