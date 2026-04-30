from typing import Any, Self

from _unsafe import Unsafe


class FAISS:
    @classmethod
    def deserialize_from_bytes(cls, serialized: bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
    @classmethod
    def load_local(cls, folder_path: str, *args: Any, **kwargs: Any) -> Unsafe[Self]: ...

