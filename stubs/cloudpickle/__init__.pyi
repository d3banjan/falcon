"""Strict cloudpickle stubs — deserialization APIs return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe


def load(file: Any, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
def loads(data: bytes | bytearray | memoryview, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
