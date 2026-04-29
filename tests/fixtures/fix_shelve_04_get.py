"""Fixture: shelf.get(key) — should produce Unsafe[Any] error."""
import shelve
from typing import Any

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
value = shelf.get("key")  # should be flagged
x: dict = value  # Unsafe[Any] not assignable to dict — should be flagged