"""Strict cloudpickle stubs — deserialization APIs return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedBinaryIO, TrustedBytes


def load(file: TrustedBinaryIO, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
def loads(data: TrustedBytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
