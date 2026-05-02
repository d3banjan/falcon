"""Strict pandas.io.pickle stubs — pickle-backed loader returns Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedPath


def read_pickle(filepath_or_buffer: TrustedPath, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
