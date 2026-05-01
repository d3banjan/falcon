"""Trusted input markers for provenance-gated loader experiments."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import NewType

TrustedPath = NewType("TrustedPath", Path)
TrustedBytes = NewType("TrustedBytes", bytes)
TrustedArtifact = NewType("TrustedArtifact", Path)


def trusted_path(path: Path, *, reason: str) -> TrustedPath:
    """Mark a path as reviewed by policy outside the type checker."""
    if not reason:
        raise ValueError("trusted_path requires a non-empty reason")
    return TrustedPath(path)


def verify_path_sha256(path: Path, expected_sha256: str) -> TrustedPath:
    """Mark a path trusted after matching its SHA-256 digest."""
    digest = sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise ValueError("path digest does not match expected SHA-256")
    return TrustedPath(path)


def trusted_bytes(data: bytes, *, reason: str) -> TrustedBytes:
    """Mark bytes as reviewed by policy outside the type checker."""
    if not reason:
        raise ValueError("trusted_bytes requires a non-empty reason")
    return TrustedBytes(data)


def verify_bytes_sha256(data: bytes, expected_sha256: str) -> TrustedBytes:
    """Mark bytes trusted after matching their SHA-256 digest."""
    digest = sha256(data).hexdigest()
    if digest != expected_sha256:
        raise ValueError("bytes digest does not match expected SHA-256")
    return TrustedBytes(data)


def trusted_artifact(path: Path, *, reason: str) -> TrustedArtifact:
    """Mark an already-materialized artifact as reviewed."""
    if not reason:
        raise ValueError("trusted_artifact requires a non-empty reason")
    return TrustedArtifact(path)
