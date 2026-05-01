"""Strict jsonpickle stubs — decode-style deserialization APIs return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe


def decode(string: str | bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
def loads(string: str | bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
