from typing import Any

from _unsafe import Unsafe
from pickle_stubs_secure.trust import TrustedPath


def load(f: TrustedPath, *args: Any, weights_only: bool = ..., **kwargs: Any) -> Unsafe[Any]: ...
