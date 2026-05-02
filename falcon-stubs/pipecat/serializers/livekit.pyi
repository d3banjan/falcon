from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedBytes


class LivekitFrameSerializer:
    async def deserialize(self, data: TrustedBytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
