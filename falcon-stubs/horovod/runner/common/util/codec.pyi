from typing import Any

from _unsafe import Unsafe


def loads_base64(encoded: str | bytes, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
def dumps_base64(obj: Any, to_ascii: bool = ...) -> str | bytes: ...
