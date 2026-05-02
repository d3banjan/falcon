from typing import Any

from _unsafe import Unsafe


class RemotePythonExecutor:
    def loads(self, payload: bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
    def deserialize(self, payload: bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...

