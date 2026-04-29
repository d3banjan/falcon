"""Test fixture: cast on shelf.get() — should be detected by audit."""
import shelve
from typing import Any, cast

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
value = cast(dict, shelf.get("key"))  # trust: testing-payload-validation