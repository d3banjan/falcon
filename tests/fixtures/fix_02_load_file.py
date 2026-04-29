"""Fixture: pickle.load(file) — should produce Unsafe[Any] error."""
import io
import pickle

buf = io.BytesIO(b"")
result = pickle.load(buf)  # line 6: should be flagged
x: dict = result  # line 7: Unsafe[Any] not assignable to dict
