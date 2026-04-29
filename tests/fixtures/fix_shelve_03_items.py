"""Fixture: shelf.items() — should produce Unsafe[Any] error in values."""
import shelve
from typing import Any

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
for key, value in shelf.items():
    x: dict = value  # Unsafe[Any] not assignable to dict — should be flagged