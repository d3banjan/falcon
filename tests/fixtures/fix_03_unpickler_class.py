"""Fixture: Unpickler().load() — should produce Unsafe[Any] error."""
import io
import pickle

buf = io.BytesIO(b"")
u = pickle.Unpickler(buf)
result = u.load()  # line 7: should be flagged
x: dict = result  # line 8: Unsafe[Any] not assignable to dict
