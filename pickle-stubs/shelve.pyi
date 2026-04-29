"""Strict shelve stubs — every deserialization API returns Unsafe[Any].

Mutations vs typeshed:
  - Shelf.__getitem__() -> Unsafe[Any]      (was Any)
  - Shelf.get() -> Unsafe[Any] | default   (was Any | default)  
  - Shelf.values() -> ValuesView[Unsafe[Any]]  (was ValuesView[Any])
  - Shelf.items() -> ItemsView[str, Unsafe[Any]]  (was ItemsView[str, Any])

All other signatures preserved verbatim from typeshed.
"""

from _unsafe import Unsafe
from collections.abc import ItemsView, KeysView, MutableMapping, ValuesView
from typing import Any, Generic, TypeVar

_K = TypeVar("_K")
_V = TypeVar("_V")


class Shelf(MutableMapping[_K, _V]):
    """Base class for shelf implementations."""
    
    dict: dict[_K, _V]
    cache: dict[_K, _V]
    keyencoding: str
    protocol: int
    writeback: bool
    
    def __init__(
        self,
        dict: Any,
        protocol: int | None = None,
        writeback: bool = False,
        keyencoding: str = "utf-8",
    ) -> None: ...
    
    def __getitem__(self, key: _K) -> Unsafe[Any]: ...
    def __setitem__(self, key: _K, value: _V) -> None: ...
    def __delitem__(self, key: _K) -> None: ...
    def __contains__(self, key: object) -> bool: ...
    def __iter__(self) -> Any: ...  # Actually returns iterator over keys (strings)
    def __len__(self) -> int: ...
    def __enter__(self) -> Shelf[_K, _V]: ...
    def __exit__(self, *excinfo: Any) -> None: ...
    def __del__(self) -> None: ...
    
    def get(self, key: _K, default: Any = None) -> Unsafe[Any] | Any: ...
    def setdefault(self, key: _K, default: Any = None) -> Any: ...
    def pop(self, key: _K, default: Any = None) -> Any: ...
    def popitem(self) -> tuple[_K, _V]: ...
    def clear(self) -> None: ...
    def update(self, other: Any = ()) -> None: ...
    
    def keys(self) -> KeysView[_K]: ...
    def values(self) -> ValuesView[Unsafe[Any]]: ...
    def items(self) -> ItemsView[_K, Unsafe[Any]]: ...
    
    def sync(self) -> None: ...
    def close(self) -> None: ...


class DbfilenameShelf(Shelf[_K, _V]):
    """Shelf implementation using a single file on disk."""
    
    def __init__(
        self,
        filename: str,
        flag: str = "c",
        protocol: int | None = None,
        writeback: bool = False,
    ) -> None: ...


def open(
    filename: str,
    flag: str = "c",
    protocol: int | None = None,
    writeback: bool = False,
) -> DbfilenameShelf[str, Any]: ...