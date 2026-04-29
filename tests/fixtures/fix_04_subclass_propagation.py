"""Fixture: Unpickler subclass — .load() should still return Unsafe[Any]."""
import io
import pickle


class MyUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        return super().find_class(module, name)


buf = io.BytesIO(b"")
u = MyUnpickler(buf)
result = u.load()  # line 13: should be flagged
x: dict = result  # line 14: Unsafe[Any] not assignable to dict
