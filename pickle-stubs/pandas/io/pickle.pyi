"""Strict pandas.io.pickle stubs — pickle-backed loader returns Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe


def read_pickle(filepath_or_buffer: Any, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
