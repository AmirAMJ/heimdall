import hashlib

import pytest

from heimdall import __version__
from heimdall.cli import main


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def _run(*argv):
        code = main(["--state-dir", str(tmp_path / "state"), *map(str, argv)])
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def _setup_chain(run, tmp_path):
    for k in ("pk", "kek", "db", "evil"):
        assert run("keygen", "--name", k)[0] == 0
    for s in ("bl1", "bl2", "kernel"):
        (tmp_path / f"{s}.bin").write_text(f"{s} running\n")
        assert run("build-image", "--payload", f"{s}.bin", "--stage", s, "--counter", 1, "--out", f"{s}.img")[0] == 0
        assert run("sign", "--key", "keys/db.key.pem", f"{s}.img")[0] == 0
    assert run("provision", "--pk-pub", "keys/pk.pub.pem")[0] == 0
    assert run("enroll", "kek", "--pub", "keys/kek.pub.pem")[0] == 0
    assert run("enroll", "db", "--pub", "keys/db.pub.pem")[0] == 0
    assert run("enroll", "pk", "--pub", "keys/pk.pub.pem", "--signed-by", "keys/pk.key.pem")[0] == 0


BOOT = ("boot", "--bl1", "bl1.img", "--bl2", "bl2.img", "--kernel", "kernel.img", "--pk-pub", "keys/pk.pub.pem")


def test_version(run):
    assert run("version") == (0, __version__ + "\n", "")


def test_hash_matches_hashlib(run, tmp_path):
    (tmp_path / "a.bin").write_bytes(b"hello\n")
    code, out, _ = run("hash", "a.bin")
    assert code == 0 and out.strip() == hashlib.sha256(b"hello\n").hexdigest()


def test_full_cli_story(run, tmp_path):
    _setup_chain(run, tmp_path)
    assert "VALID" in run("verify", "--pub", "keys/db.pub.pem", "kernel.img")[1]
    assert "USER MODE" in run("status")[1]
    assert "PK \u2713 \u2192 KEK \u2713 \u2192 db \u2713" in run("keystore", "show")[1]

    code, out, _ = run(*BOOT, "--measure")
    assert code == 0
    assert "[ROM] root key matches fuse" in out and "[KERNEL] kernel running" in out
    assert "final PCR:" in out
    assert run("replay-log")[0] == 0
    assert run("seal", "--secret", "launch-codes")[0] == 0
    assert run("unseal")[1].strip() == "launch-codes"

    # tamper with the kernel: boot halts, exit 1, the kernel never runs
    bad = bytearray((tmp_path / "kernel.img").read_bytes())
    bad[60] ^= 0xFF
    (tmp_path / "kernel.img").write_bytes(bytes(bad))
    code, out, _ = run(*BOOT)
    assert code == 1 and "HALT" in out and "[KERNEL] kernel running" not in out


def test_verify_tampered_and_malformed_have_no_traceback(run, tmp_path):
    _setup_chain(run, tmp_path)
    data = bytearray((tmp_path / "kernel.img").read_bytes())
    data[60] ^= 0xFF
    (tmp_path / "bad.img").write_bytes(bytes(data))
    code, out, err = run("verify", "--pub", "keys/db.pub.pem", "bad.img")
    assert code == 1 and out.startswith("INVALID") and "Traceback" not in err
    (tmp_path / "empty.img").write_bytes(b"")
    code, out, err = run("verify", "--pub", "keys/db.pub.pem", "empty.img")
    assert code == 1 and "ImageFormatError: truncated header" in out and "Traceback" not in err


def test_second_provision_refused(run, tmp_path):
    run("keygen", "--name", "pk")
    assert run("provision", "--pk-pub", "keys/pk.pub.pem")[0] == 0
    code, _, err = run("provision", "--pk-pub", "keys/pk.pub.pem")
    assert code == 1 and "already programmed" in err


def test_status_before_setup(run):
    code, out, _ = run("status")
    assert code == 0 and "SETUP MODE" in out and "not programmed" in out


def test_user_mode_unsigned_enroll_refused(run, tmp_path):
    _setup_chain(run, tmp_path)
    run("keygen", "--name", "db2")
    code, _, err = run("enroll", "db", "--pub", "keys/db2.pub.pem")
    assert code == 1 and "USER MODE" in err
    assert run("enroll", "db", "--pub", "keys/db2.pub.pem", "--signed-by", "keys/kek.key.pem")[0] == 0


def test_revoke_via_cli(run, tmp_path):
    _setup_chain(run, tmp_path)
    digest = run("hash", "kernel.img")[1].strip()
    assert run("revoke", "--image-hash", digest, "--signed-by", "keys/kek.key.pem")[0] == 0
    code, out, _ = run(*BOOT)
    assert code == 1 and "revoked" in out


def test_encrypted_key_via_env(run, tmp_path, monkeypatch):
    monkeypatch.setenv("HEIMDALL_PASSPHRASE", "hunter2")
    assert run("keygen", "--name", "enc", "--encrypt")[0] == 0
    assert "ENCRYPTED" in (tmp_path / "keys" / "enc.key.pem").read_text()
    (tmp_path / "p.bin").write_text("x")
    run("build-image", "--payload", "p.bin", "--stage", "bl1", "--out", "p.img")
    assert run("sign", "--key", "keys/enc.key.pem", "p.img")[0] == 0
    monkeypatch.setenv("HEIMDALL_PASSPHRASE", "wrong")
    code, _, err = run("sign", "--key", "keys/enc.key.pem", "p.img")
    assert code == 1 and "Traceback" not in err


def test_efi_sign_hostile_name_is_safe(run, tmp_path):
    code, _, err = run("efi-sign", "--in", f"a; touch {tmp_path}/pwned.efi", "--out", "o", "--key", "k", "--cert", "c")
    assert code == 1 and "not found" in err
    assert not (tmp_path / "pwned.efi").exists()
