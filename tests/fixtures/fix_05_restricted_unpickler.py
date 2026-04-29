"""Fixture: RestrictedUnpickler pattern from CPython docs — still flagged."""
import io
import pickle


SAFE_BUILTINS = {"dict", "list", "tuple", "set", "frozenset", "str", "int", "float", "bool"}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        if module == "builtins" and name in SAFE_BUILTINS:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")


buf = io.BytesIO(b"")
u = RestrictedUnpickler(buf)
result = u.load()  # line 18: still flagged — restriction is runtime, not type-level
x: dict = result  # line 19: Unsafe[Any] not assignable to dict
