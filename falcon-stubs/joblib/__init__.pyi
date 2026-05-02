"""Strict joblib stubs — pickle-backed loaders return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedPath


def load(filename: TrustedPath, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
