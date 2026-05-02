"""Strict pandas stubs — pickle-backed loaders return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedPath


def read_pickle(filepath_or_buffer: TrustedPath, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...

def __getattr__(name: str) -> Any: ...
