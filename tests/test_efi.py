import subprocess

import pytest

from heimdall import efi
from heimdall.errors import HeimdallError, VerificationError


@pytest.fixture
def files(tmp_path):
    for n in ("in.efi", "k.key", "c.crt"):
        (tmp_path / n).write_bytes(b"x")
    return tmp_path


def _fake_run(calls, rc=0):
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, rc, stdout="Signature verification OK\n", stderr="boom")

    return run


def test_sign_uses_arg_list_and_no_shell(files, monkeypatch):
    calls = []
    monkeypatch.setattr(efi.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(efi.subprocess, "run", _fake_run(calls))
    efi.sign_efi(files / "in.efi", files / "out.efi", files / "k.key", files / "c.crt")
    args, kwargs = calls[0]
    assert isinstance(args, list) and args[0] == "/usr/bin/sbsign"
    assert kwargs["shell"] is False


def test_dash_prefixed_names_cannot_become_options():
    assert efi._arg("-rf") == "./-rf"
    assert efi._arg("normal.efi") == "normal.efi"


def test_hostile_filename_is_just_a_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(efi.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(efi.subprocess, "run", _fake_run([]))
    hostile = "a; touch " + str(tmp_path / "pwned.efi")
    with pytest.raises(HeimdallError, match="not found"):
        efi.sign_efi(hostile, tmp_path / "o", tmp_path / "k", tmp_path / "c")
    assert not (tmp_path / "pwned.efi").exists()


def test_missing_tool(files, monkeypatch):
    monkeypatch.setattr(efi.shutil, "which", lambda n: None)
    with pytest.raises(HeimdallError, match="sbsigntool"):
        efi.sign_efi(files / "in.efi", files / "o", files / "k.key", files / "c.crt")


def test_tool_failure_is_reported(files, monkeypatch):
    monkeypatch.setattr(efi.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(efi.subprocess, "run", _fake_run([], rc=1))
    with pytest.raises(HeimdallError, match="failed"):
        efi.sign_efi(files / "in.efi", files / "o", files / "k.key", files / "c.crt")
    with pytest.raises(VerificationError):
        efi.verify_efi(files / "in.efi", files / "c.crt")


def test_verify_ok(files, monkeypatch):
    monkeypatch.setattr(efi.shutil, "which", lambda n: f"/usr/bin/{n}")
    monkeypatch.setattr(efi.subprocess, "run", _fake_run([]))
    assert "OK" in efi.verify_efi(files / "in.efi", files / "c.crt")
