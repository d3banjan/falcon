"""Fixture: direct `from _pickle import loads` — must also be flagged."""
from _pickle import loads

data = b""
result = loads(data)  # line 5: should be flagged
x: dict = result  # line 6: Unsafe[Any] not assignable to dict
