"""Fixture: shelf.values() — should produce Unsafe[Any] error."""
import shelve
from typing import Any

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
values = shelf.values()  # should be flagged
for value in values:
    x: dict = value  # Unsafe[Any] not assignable to dict — should be flagged