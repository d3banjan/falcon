from typing import Any, Self

from _unsafe import Unsafe
from pickle_stubs_secure.trust import TrustedBytes, TrustedPath


class FAISS:
    @classmethod
    def deserialize_from_bytes(
        cls,
        serialized: TrustedBytes,
        embeddings: Any,
        *,
        allow_dangerous_deserialization: bool = ...,
        **kwargs: Any,
    ) -> Unsafe[Any]: ...
    @classmethod
    def load_local(
        cls,
        folder_path: TrustedPath,
        embeddings: Any,
        index_name: str = ...,
        *,
        allow_dangerous_deserialization: bool = ...,
        **kwargs: Any,
    ) -> Unsafe[Self]: ...
