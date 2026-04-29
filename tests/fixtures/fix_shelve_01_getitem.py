"""Fixture: shelf[key] read — should produce Unsafe[Any] error."""
import shelve
from typing import Any

shelf: shelve.Shelf[str, Any] = shelve.open("test.db")
value = shelf["key"]  # should be flagged
x: dict = value  # Unsafe[Any] not assignable to dict — should be flagged