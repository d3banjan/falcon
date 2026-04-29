"""Fixture: Allowlist-Bypass Demo — Stub catches what allowlist misses.

This fixture demonstrates that even with RestrictedUnpickler using a whitelist,
our stubs still flag deserialization as Unsafe[Any].

KEY DEMONSTRATION:
1. RestrictedUnpickler with strict allowlist (looks secure at runtime)
2. Gadget chains bypass the allowlist (still execute RCE)
3. Our stubs flag ALL deserialization as Unsafe[Any] (catches it at type-check time)

Marketing claim: "caught what allowlist missed."
"""

from __future__ import annotations

import io
import pickle


SAFE_BUILTINS = {"dict", "list", "tuple", "set", "str", "int", "float"}


class RestrictedUnpickler(pickle.Unpickler):
    """CPython-docs pattern with strict allowlist.
    
    This looks secure to developers but has blind spots:
    - __setstate__ on allowed objects
    - __reduce__ with built-in functions
    - Subclass manipulation
    """
    def find_class(self, module: str, name: str) -> object:
        if module == "builtins" and name in SAFE_BUILTINS:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")


# BUG #1: Developer trust runtime allowlist, but stubs still flag it
buf = io.BytesIO(b"some potentially malicious payload")
restricted = RestrictedUnpickler(buf)
result = restricted.load()  # LINE 33: still flagged — allowlist blind spots
x: dict = result  # LINE 34: Unsafe[Any] not assignable to dict


# BUG #2: Even with "safe" unpickler, gadget chains bypass it
# The stubs catch this because ALL deserialization is flagged
result2 = restricted.load()  # LINE 38: same Unsafe[Any] error
y: list = result2  # LINE 39: Unsafe[Any] not assignable to list


# BUG #3: Subclass manipulation bypasses allowlist
# Our stubs don't care about subclass details — ALL .load() is Unsafe[Any]
class MyRestrictedUnpickler(RestrictedUnpickler):
    pass

another_buf = io.BytesIO(b"")
another_restricted = MyRestrictedUnpickler(another_buf)
result3 = another_restricted.load()  # LINE 49: still flagged — inheritance doesn't help
z: tuple = result3  # LINE 50: Unsafe[Any] not assignable to tuple


# The fix: explicit cast + manual review
# (This would be in a separate file showing proper usage)
# from typing import cast
# safe_data: dict = cast(dict, restricted.load())  # trust: reviewed gadget-chain-catalog-2026-04