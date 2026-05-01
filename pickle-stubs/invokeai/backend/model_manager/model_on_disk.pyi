from typing import Any

from _unsafe import Unsafe


class ModelOnDisk:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def load_state_dict(self, *args: Any, **kwargs: Any) -> Unsafe[Any]: ...

