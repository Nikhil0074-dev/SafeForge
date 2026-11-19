class SafeForgeError(Exception):
    """Base class for all SafeForge failures. Every failure is fail-closed."""


class BombError(SafeForgeError):
    """File looks like a decompression / XML / pixel / object-count bomb."""


class BlockedError(SafeForgeError):
    """File type is blocked by policy (executables, unsupported archives...)."""


class CDRError(SafeForgeError):
    """File could not be parsed or rebuilt safely."""


class VerificationError(SafeForgeError):
    """Sanitized output still contains something the verifier rejects."""
