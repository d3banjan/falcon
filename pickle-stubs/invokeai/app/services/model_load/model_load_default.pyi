from typing import Any

from _unsafe import Unsafe


class ModelLoadService:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def load_model_from_path(self, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...
