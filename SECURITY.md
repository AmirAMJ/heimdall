# Security policy

Heimdall is an educational reference implementation, not production firmware. Reports are still welcome.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
[security advisory form](../../security/advisories/new) for this repository, and include the version, steps to
reproduce, and the impact you see. We aim to acknowledge reports within 7 days.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: signature, hash, keystore, rollback, revocation and parser logic. Out of scope: the documented
limitations in the README, and attacks that require write access to the ROM or fuse storage.
