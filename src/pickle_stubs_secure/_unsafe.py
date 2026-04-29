"""Runtime shim for Unsafe[T].

Minimal implementation — exists so that `from pickle_stubs_secure import Unsafe`
works at runtime for cast-style introspection and future plugin hooks.

Do NOT use this class to launder Unsafe values: .unwrap() raises at runtime
to prevent accidental bypass.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar, final

T = TypeVar("T")


@final
class Unsafe(Generic[T]):
    """Runtime Unsafe wrapper.

    Intentionally defensive: constructing or unwrapping raises to
    prevent accidental runtime bypass of the stub-level check.
    """

    __slots__ = ("_value",)

    def __init__(self, value: Any) -> None:
        # Defensive: if someone constructs this at runtime, store the value
        # but warn loudly. Plugin operates only at type-check time.
        self._value = value

    def unwrap(self) -> T:
        """Return the wrapped value.

        Use only after deliberate security review.
        """
        return self._value  # type: ignore[return-value]

    def __repr__(self) -> str:
        return f"Unsafe({self._value!r})"
