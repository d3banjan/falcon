"""Strict joblib stubs — pickle-backed loaders return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe


def load(filename: Any, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
