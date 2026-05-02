from typing import Any

from _unsafe import Unsafe


class JsonPickleSerializer:
    def dumps(self, value: Any) -> str | bytes: ...
    def deserialize(self, value: str, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
