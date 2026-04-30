from typing import Any

from _unsafe import Unsafe


class LivekitFrameSerializer:
    def deserialize(self, data: bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
    async def deserialize_async(self, data: bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...

