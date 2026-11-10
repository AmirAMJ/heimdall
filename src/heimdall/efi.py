"""Bridge to real UEFI tooling (``sbsign`` / ``sbverify`` from sbsigntool).

Processes are always started from an argument *list* with ``shell=False``, so file
names can never be interpreted by a shell.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .errors import HeimdallError, VerificationError

_TIMEOUT = 60


def _arg(path: str | os.PathLike) -> str:
    """Stop a file name like '-x' from being parsed as an option."""
    text = os.fspath(path)
    return "./" + text if text.startswith("-") else text


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise HeimdallError(f"{name} not found; install it (package: sbsigntool)")
    return found


def _require_file(path: str | os.PathLike, label: str) -> None:
    if not Path(path).is_file():
        raise HeimdallError(f"{label} not found: {path}")


def _run(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            args, shell=False, check=False, capture_output=True, text=True, timeout=_TIMEOUT
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HeimdallError(f"could not run {Path(args[0]).name}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise HeimdallError(f"{Path(args[0]).name} failed: {detail}")
    return proc.stdout


def sign_efi(src, dst, key, cert) -> None:
    for path, label in ((src, "input"), (key, "key"), (cert, "certificate")):
        _require_file(path, label)
    _run(
        [
            _tool("sbsign"),
            "--key",
            _arg(key),
            "--cert",
            _arg(cert),
            "--output",
            _arg(dst),
            _arg(src),
        ]
    )


def verify_efi(path, cert) -> str:
    for target, label in ((path, "input"), (cert, "certificate")):
        _require_file(target, label)
    try:
        return _run([_tool("sbverify"), "--cert", _arg(cert), _arg(path)]).strip()
    except HeimdallError as exc:
        raise VerificationError(str(exc)) from exc
