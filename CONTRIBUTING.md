# Contributing to Heimdall

Thanks for helping! Heimdall is meant to be read and learned from, so clarity beats cleverness.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Workflow

1. Open an issue or comment on an existing one so we can agree on the idea first.
2. Create a branch, make a small focused change, and add or update tests.
3. Run `pytest` and `bash scripts/demo.sh` locally; CI runs both.
4. Open a pull request that explains *what* and *why*. One topic per PR keeps reviews fast.

## Rules of the house

- Every defense needs an attack test in `tests/attacks/` that fails if the defense is removed.
- Compare hashes and keys only through `crypto.constant_time_equal`.
- Never use `shell=True`; never catch a verification error and carry on.
- Keep module dependencies pointing downward (see `docs/ARCHITECTURE.md`).
- Never commit private keys (`keys/*.key.pem` is git-ignored; keep it that way).

## Reporting bugs

Include your Python version, the command you ran and the full output. For security issues see `SECURITY.md`.
