"""Fixture: pickle.loads — should produce Unsafe[Any] error on assignment."""
import pickle

data = b""
result = pickle.loads(data)  # line 5: should be flagged
x: dict = result  # line 6: Unsafe[Any] not assignable to dict — should be flagged
