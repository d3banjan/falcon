"""Test fixture: cast on shelf[key] — should be detected by audit."""
import shelve
from typing import Any, cast

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
value = cast(dict, shelf["key"])  # trust: testing-payload-validation