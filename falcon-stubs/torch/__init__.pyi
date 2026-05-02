from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedPath


def load(f: TrustedPath, *args: Any, weights_only: bool = ..., **kwargs: Any) -> Unsafe[Any]: ...
