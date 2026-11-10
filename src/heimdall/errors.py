"""Exception hierarchy. Every one of these is fatal for the boot chain."""


class HeimdallError(Exception):
    """Base class for every expected failure."""


class ImageFormatError(HeimdallError):
    """An image file is malformed (bad magic, truncated, wrong lengths...)."""


class VerificationError(HeimdallError):
    """A signature, hash or root-of-trust check failed."""


class PolicyError(HeimdallError):
    """A policy rule refused the operation (revoked, rollback, fuses...)."""


class KeystoreError(HeimdallError):
    """The key database is malformed, unsigned, or an update is unauthorized."""
