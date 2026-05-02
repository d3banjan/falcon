"""Provenance-gated dangerous loader wrappers."""

from __future__ import annotations

import pickle
from typing import Any

from falcon_secure._unsafe import Unsafe
from falcon_secure.trust import TrustedBytes, TrustedPath


def pickle_loads(data: TrustedBytes, *args: Any, **kwargs: Any) -> Unsafe[Any]:
    """Load pickle bytes after provenance review, preserving Unsafe quarantine."""
    return Unsafe(pickle.loads(data, *args, **kwargs))


def joblib_load(path: TrustedPath, *args: Any, **kwargs: Any) -> Unsafe[Any]:
    """Load a joblib artifact after provenance review, preserving Unsafe quarantine."""
    import joblib

    return Unsafe(joblib.load(path, *args, **kwargs))


def torch_load(path: TrustedPath, *args: Any, **kwargs: Any) -> Unsafe[Any]:
    """Load a torch artifact after provenance review, preserving Unsafe quarantine."""
    import torch

    return Unsafe(torch.load(path, *args, **kwargs))
