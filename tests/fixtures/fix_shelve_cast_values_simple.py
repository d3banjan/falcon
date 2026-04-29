"""Test fixture: cast on shelf.values() — should be detected by audit."""
import shelve
from typing import Any, cast

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
values = cast(list, shelf.values())  # trust: testing-payload-validation