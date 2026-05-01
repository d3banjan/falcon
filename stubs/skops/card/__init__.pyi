"""Strict skops.card stubs — model-card loaders return Unsafe[Any]."""

from typing import Any

from _unsafe import Unsafe


class Card:
    def __init__(self, model: Any, *args: Any, **kwargs: Any) -> None: ...
    def get_model(self, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
