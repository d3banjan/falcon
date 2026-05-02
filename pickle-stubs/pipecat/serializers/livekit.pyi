from typing import Any

from _unsafe import Unsafe
from pickle_stubs_secure.trust import TrustedBytes


class LivekitFrameSerializer:
    async def deserialize(self, data: TrustedBytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
