"""Strict Embedchain OpenAPI loader stubs — unsafe YAML wrappers return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe


class OpenAPILoader:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def load_data(self, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
