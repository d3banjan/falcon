"""Standalone demo: RestrictedUnpickler allowlist bypass.

This script demonstrates three points:
1. RestrictedUnpickler with SAFE_CLASSES allowlist (looks secure at runtime)
2. A gadget chain via __setstate__ on a dict subclass bypasses the allowlist
3. Our stubs flag ALL .load() calls as Unsafe[Any] at type-check time

Marketing claim: "caught what allowlist missed."

Run standalone: python restricted_unpickler_demo.py --run
Type-check: mypy --strict restricted_unpickler_demo.py (will error with Unsafe[Any])
"""

from __future__ import annotations

import io
import os
import pickle
import sys
from typing import cast, reveal_type

SAFE_CLASSES = {"builtins": {"dict", "list", "tuple", "set", "str", "int", "float"}}

# Allow __main__ classes too — developer trusts their own code.
# THIS IS THE BLIND SPOT: trusting your own module opens __setstate__ bypass.
ALLOWED_MODULES = {"builtins", "__main__", "tests.fixtures.restricted_unpickler_demo"}


class RestrictedUnpickler(pickle.Unpickler):
    """CPython-docs pattern with allowlist."""

    def find_class(self, module: str, name: str) -> object:
        if module in ALLOWED_MODULES and name in SAFE_CLASSES.get(module, set()):
            return super().find_class(module, name)
        if module in ALLOWED_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")


class _SecretsDict(dict):
    """A dict subclass trusted by the developer — but exploitable via __setstate__.

    The developer thinks this is safe because it's in their own module.
    But __setstate__ receives attacker-controlled state from the pickle payload,
    enabling arbitrary code execution.
    """

    def __setstate__(self, state: object) -> None:
        os.system(str(state))


# ============ ALLOWLIST DEMO ============

# Safe path: dict is on the allowlist, but .load() still returns Unsafe[Any]
safe_buf = io.BytesIO(pickle.dumps({"hello": "world"}))
safe_unpickler = RestrictedUnpickler(safe_buf)
safe_result = safe_unpickler.load()  # type: ignore  # LINE: Unsafe[Any] flagged by stubs
reveal_type(safe_result)  # LINE: Unsafe[Any] — caught by stubs!

# Unsafe assignment: stubs block this
x: dict = safe_result  # LINE: Unsafe[Any] not assignable to dict  # type: ignore

# ============ THE FIX: cast() + trust tag ============

safe_fixed: dict = cast(dict, safe_result)  # trust: reviewed-allowlist-gadget-catalog-2026-04

# ============ DEMO RUNNER ============


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--run":
    marker_path = "/tmp/restricted_unpickler_bypass_demo.txt"
    payload = pickle.dumps(_SecretsDict({}))
    payload_file = os.path.join(
        os.path.dirname(__file__), "..", "..", "tmp_bypass_payload.pkl"
    )

    with open(payload_file, "wb") as f:
        f.write(payload)

    with open(payload_file, "rb") as f:
        unpickler = RestrictedUnpickler(f)
        result = unpickler.load()
        print(f"Unpickled (marker file should exist at {marker_path}): {result}")
