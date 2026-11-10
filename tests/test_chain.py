import logging

import pytest

from heimdall import chain, measure, rom
from heimdall.image import Stage


def test_happy_path_order_and_executed_payloads(env):
    ran = []
    result = env.boot(executor=lambda stage, payload: ran.append((stage, payload)))
    assert ran == [
        ("bl1", b"bl1 running"),
        ("bl2", b"bl2 running"),
        ("kernel", b"kernel running"),
    ]
    assert [e.stage for e in result.events] == ["bl1", "bl2", "kernel"]


def test_log_lines(env, caplog):
    with caplog.at_level(logging.INFO, logger="heimdall.boot"):
        env.boot(executor=chain.default_executor)
    text = "\n".join(r.getMessage() for r in caplog.records)
    for line in (
        "[ROM] root key matches fuse",
        "[ROM] BL1 verified",
        "[BL1] BL2 verified",
        "[BL2] KERNEL verified",
        "[KERNEL] kernel running",
    ):
        assert line in text


def test_counters_committed_and_event_log_replays(env):
    env.images["kernel"] = env.make_image("kernel", counter=4)
    result = env.boot()
    assert rom.load_fuses(env.fuses).counters == {"bl1": 1, "bl2": 1, "kernel": 4}
    assert measure.verify_event_log(env.events) == result.pcr


def test_failure_halts_before_next_stage(env):
    data = bytearray(env.images["bl2"].read_bytes())
    data[60] ^= 0xFF
    env.images["bl2"].write_bytes(bytes(data))
    ran = []
    with pytest.raises(chain.BootHalt):
        env.boot(executor=lambda s, p: ran.append(s))
    assert ran == ["bl1"]  # BL2 and the kernel never ran


def test_failed_boot_does_not_touch_counters_or_log(env):
    env.images["kernel"] = env.make_image("kernel", counter=9, signer="evil")
    with pytest.raises(chain.BootHalt):
        env.boot()
    assert rom.load_fuses(env.fuses).counters == {"bl1": 0, "bl2": 0, "kernel": 0}
    assert not env.events.exists()


def test_missing_image_halts_cleanly(env, tmp_path):
    with pytest.raises(chain.BootHalt):
        env.boot(kernel=tmp_path / "nope.img")


def test_setup_mode_keystore_refuses_to_boot(env):
    from heimdall.keystore import Keystore

    Keystore().save(env.keystore)
    with pytest.raises(chain.BootHalt):
        env.boot()


def test_oversize_file_rejected(env, tmp_path):
    big = tmp_path / "big.img"
    big.write_bytes(b"\x00" * (chain.MAX_IMAGE_SIZE + 1))
    with pytest.raises(chain.BootHalt):
        env.boot(kernel=big)


def test_stage_enum_values():
    assert [int(s) for s in Stage] == [1, 2, 3]
