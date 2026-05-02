"""Strict numpy stubs for consumers that use pandas/ML stack deserialization surfaces."""

from typing import Any, Literal, overload

from _unsafe import Unsafe


@overload
def load(
    file: Any,
    mmap_mode: str | None = ...,
    allow_pickle: Literal[False] = ...,
    fix_imports: bool = ...,
    encoding: str = ...,
    max_header_size: int = ...,
) -> Any: ...


@overload
def load(
    file: Any,
    mmap_mode: str | None = ...,
    allow_pickle: bool = ...,
    fix_imports: bool = ...,
    encoding: str = ...,
    max_header_size: int = ...,
) -> Unsafe[Any]: ...

